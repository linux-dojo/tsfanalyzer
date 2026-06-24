package parser

import (
	"archive/tar"
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// CounterSample is one measurement of one counter at one point in time.
type CounterSample struct {
	Name  string    `json:"name"`
	Ts    time.Time `json:"ts"`
	Value float64   `json:"value"`
}

// Global-counter sections with a shorter elapsed time are incremental deltas
// printed between full samples; they would throw the series off, so only
// sections at/above this elapsed time are collected.
const gcMinElapsedSeconds = 120.0

var monitorFileRe = regexp.MustCompile(`(?:^|/)(dp|mp)-monitor\.log(?:\.\d+)?$`)

// CollectAllCounters makes a single pass over the archive and extracts
// counter time series from every dp-monitor.log* and mp-monitor.log* file.
func CollectAllCounters(r io.ReadSeeker) ([]CounterSample, error) {
	tr, err := openTar(r)
	if err != nil {
		return nil, err
	}
	var out []CounterSample
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			break // tolerate trailing corruption
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		m := monitorFileRe.FindStringSubmatch(normalizePath(hdr.Name))
		if m == nil {
			continue
		}
		out = append(out, collectMonitor(tr, m[1])...)
	}
	return out, nil
}

/* ---------- regexes ---------- */

var (
	gcSecRe     = regexp.MustCompile(`^:Global counters:`)
	gcElapsedRe = regexp.MustCompile(`^:Elapsed time since last sampling:\s+([\d.]+)\s+seconds`)
	gcKvRe      = regexp.MustCompile(`^:([a-z][a-z0-9_]*)\s+(\d+)\s+(-?\d+)\s*$`)
	gcEndRe     = regexp.MustCompile(`^:Total counters shown:`)

	cpu15mSecRe = regexp.MustCompile(`^:CPU load \(%\) during last 15 minutes:`)
	coreHdrRe   = regexp.MustCompile(`^:core((?:\s+\d+)+)\s*$`)
	avgMaxHdrRe = regexp.MustCompile(`^:(?:\s*avg\s+max)+\s*$`)
	valRowRe    = regexp.MustCompile(`^:((?:\s+\d+)+)\s*$`)

	cacheSecRe = regexp.MustCompile(`^:Cache-Type\b`)
	cacheRowRe = regexp.MustCompile(`^:([A-Za-z][A-Za-z0-9_]*)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s*$`)

	// "--- cpu" block
	cpuAvgMaxRe = regexp.MustCompile(`^(\d+)\s+(\d+)\s*$`)
	loadAvgRe   = regexp.MustCompile(`^([\d.]+)\s+([\d.]+)\s+([\d.]+)`)

	// per pan-task (per core) global counters
	perTaskSecRe = regexp.MustCompile(`^:\s*Per pan-task counter statistics`)
	perTaskHdrRe = regexp.MustCompile(`^:Counter Name((?:\s+\d+)+)\s+Total\s*$`)
	perTaskRowRe = regexp.MustCompile(`^:([a-z][a-z0-9_]*)((?:\s+\d+)+)\s*$`)

	// "--- ifconfig" block
	ifaceHdrRe  = regexp.MustCompile(`^\d+:\s+([A-Za-z0-9._@-]+):`)
	rxtxHdrRe   = regexp.MustCompile(`^(RX|TX):\s+([a-z][a-z /]*)$`)
	numsOnlyRe  = regexp.MustCompile(`^[\d\s]+$`)

	// "--- memory" block
	memRowRe  = regexp.MustCompile(`^Mem\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)`)
	swapRowRe = regexp.MustCompile(`^Swap\s+(\d+)\s+(\d+)\s+(\d+)`)

	// "--- logrcvr_statistics" block: "Label name:   123/sec"
	lrLineRe = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9 ()/_-]*?):\s+([\d.]+)(?:/sec)?\s*$`)

	// "--- netstat_detail" block: "<pid>/<program>"
	nsProgRe = regexp.MustCompile(`^(\d+)/([\w.-]+)`)

	// "--- netstat_stats" block (netstat -s style)
	nsSectionRe  = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9]*):$`)
	nsColonRe    = regexp.MustCompile(`^(.+?):\s+(-?\d+)\s*$`)
	nsNumFirstRe = regexp.MustCompile(`^(-?\d+)\s+(.+?)\s*$`)

	// "--- filesystem" block
	fsRowRe = regexp.MustCompile(`^(\S+)\s+(\d+)\s+(\d+)\s*$`)

	// pool tables: Mem-Pool-Type / Software Pools / Pow Atomic / shared pool
	mempoolHdrRe    = regexp.MustCompile(`^:Mem-Pool-Type\b`)
	mempoolRowRe    = regexp.MustCompile(`^:([A-Za-z][A-Za-z0-9_]*)\s+(.+)$`)
	softpoolHdrRe   = regexp.MustCompile(`^:Software Pools\b`)
	softpoolRowRe   = regexp.MustCompile(`^:\[\s*\d+\]\s+(.+?)\s+\(\s*\d+\):\s+(\d+)/(\d+)`)
	powpoolHdrRe    = regexp.MustCompile(`Pow Atomic Memory Pools`)
	powpoolRowRe    = regexp.MustCompile(`^:?\s*\[\s*\d+\]\s+(.+?)\s+:\s+(\d+)/(\d+)`)
	sharedpoolHdrRe = regexp.MustCompile(`^:User\s+Quota\b`)
	sharedpoolRowRe = regexp.MustCompile(`^:([A-Za-z][A-Za-z0-9_]*)\s+(.+)$`)
)

/* ---------- monitor log state machine ---------- */

type counterCollector struct {
	plane  string
	ts     time.Time
	haveTs bool
	block  string
	mode   string // "", gc, gcskip, cpu15m, cache, pertask

	coreIDs []int
	rowIdx  int

	loadAvgNext bool
	cpuDone     bool

	taskCols []int // per pan-task column core ids

	curIface string   // ifconfig: current interface
	rxtxDir  string   // ifconfig: pending RX/TX value row
	rxtxCols []string // ifconfig: column names from the header

	lrDone bool // logrcvr: stop after "Total (MB)"

	nsAcc map[string]float64 // netstat_detail: per proto+program queue sums
	nsTs  time.Time

	nsSection string // netstat_stats: current section (ip/tcp/...)

	out []CounterSample
}

func collectMonitor(r io.Reader, plane string) []CounterSample {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	c := &counterCollector{plane: plane}
	for sc.Scan() {
		c.line(strings.TrimRight(sc.Text(), "\r"))
	}
	c.flushNetstat()
	return c.out
}

func (c *counterCollector) flushNetstat() {
	for name, v := range c.nsAcc {
		c.emitAt(c.nsTs, name, v)
	}
	c.nsAcc = nil
}

func (c *counterCollector) emitAt(ts time.Time, name string, v float64) {
	if !c.haveTs {
		return
	}
	c.out = append(c.out, CounterSample{Name: name, Ts: ts, Value: v})
}

func (c *counterCollector) emit(name string, v float64) {
	c.emitAt(c.ts, name, v)
}

func sanitizeCounter(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	lastUnd := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastUnd = false
		default:
			if !lastUnd && b.Len() > 0 {
				b.WriteByte('_')
				lastUnd = true
			}
		}
	}
	return strings.Trim(b.String(), "_")
}

func (c *counterCollector) line(raw string) {
	trimmed := strings.TrimSpace(raw)

	// new top-level block ("<ts> -0700 --- <name>")
	if m := blockHdrRe.FindStringSubmatch(trimmed); m != nil {
		c.flushNetstat()
		c.mode = ""
		if t, err := time.Parse("2006-01-02 15:04:05", strings.ReplaceAll(m[1], "/", "-")); err == nil {
			c.ts, c.haveTs = t, true
		}
		c.block = m[2]
		c.loadAvgNext, c.cpuDone = false, false
		c.coreIDs = nil
		c.curIface, c.rxtxDir = "", ""
		c.lrDone = false
		c.nsSection = ""
		if c.block == "netstat_detail" {
			c.nsAcc = make(map[string]float64)
			c.nsTs = c.ts
		}
		return
	}

	// dedicated blocks outside panio
	switch c.block {
	case "cpu":
		c.cpuBlockLine(trimmed)
		return
	case "ifconfig":
		c.ifconfigLine(trimmed)
		return
	case "memory":
		c.memoryLine(trimmed)
		return
	case "logrcvr_statistics":
		c.logrcvrLine(trimmed)
		return
	case "netstat_detail":
		c.netstatLine(trimmed)
		return
	case "netstat_stats":
		c.netstatStatsLine(trimmed)
		return
	case "processes":
		c.processesLine(trimmed)
		return
	case "filesystem":
		c.filesystemLine(trimmed)
		return
	}

	// section transitions (inside panio and friends)
	switch {
	case gcSecRe.MatchString(trimmed):
		c.mode = "gc-elapsed" // decide keep/skip on the elapsed line
		return
	case gcEndRe.MatchString(trimmed):
		c.mode = ""
		return
	case cpu15mSecRe.MatchString(trimmed):
		c.mode = "cpu15m"
		c.coreIDs = nil
		c.rowIdx = 0
		return
	case cacheSecRe.MatchString(trimmed):
		c.mode = "cache"
		return
	case perTaskSecRe.MatchString(trimmed):
		c.mode = "pertask"
		c.taskCols = nil
		return
	case mempoolHdrRe.MatchString(trimmed):
		c.mode = "mempool"
		return
	case softpoolHdrRe.MatchString(trimmed):
		c.mode = "softpool"
		return
	case powpoolHdrRe.MatchString(trimmed):
		c.mode = "powpool"
		return
	case sharedpoolHdrRe.MatchString(trimmed):
		c.mode = "sharedpool"
		return
	}

	switch c.mode {
	case "gc-elapsed":
		if m := gcElapsedRe.FindStringSubmatch(trimmed); m != nil {
			if atofu(m[1]) >= gcMinElapsedSeconds {
				c.mode = "gc"
			} else {
				c.mode = "gcskip" // short-interval delta: ignore values
			}
		}
	case "gc":
		if m := gcKvRe.FindStringSubmatch(trimmed); m != nil {
			c.emit(c.plane+"__gc__"+m[1], atofu(m[2]))
		}
	case "gcskip":
		// swallow until ":Total counters shown:" (handled above)
	case "cpu15m":
		if m := coreHdrRe.FindStringSubmatch(trimmed); m != nil {
			c.coreIDs = c.coreIDs[:0]
			for _, f := range strings.Fields(m[1]) {
				n, _ := strconv.Atoi(f)
				c.coreIDs = append(c.coreIDs, n)
			}
			c.rowIdx = 0
			return
		}
		if avgMaxHdrRe.MatchString(trimmed) {
			return
		}
		if m := valRowRe.FindStringSubmatch(trimmed); m != nil && len(c.coreIDs) > 0 {
			vals := strings.Fields(m[1])
			if len(vals) != 2*len(c.coreIDs) {
				return
			}
			// one row per minute, first row = most recent minute
			rowTs := c.ts.Add(-time.Duration(c.rowIdx) * time.Minute)
			for i, id := range c.coreIDs {
				c.emitAt(rowTs, fmt.Sprintf("%s__cpu__%02d_avg", c.plane, id), atofu(vals[2*i]))
				c.emitAt(rowTs, fmt.Sprintf("%s__cpu__%02d_max", c.plane, id), atofu(vals[2*i+1]))
			}
			c.rowIdx++
		}
	case "pertask":
		if m := perTaskHdrRe.FindStringSubmatch(trimmed); m != nil {
			c.taskCols = c.taskCols[:0]
			for _, f := range strings.Fields(m[1]) {
				n, _ := strconv.Atoi(f)
				c.taskCols = append(c.taskCols, n)
			}
			return
		}
		if m := perTaskRowRe.FindStringSubmatch(trimmed); m != nil && len(c.taskCols) > 0 {
			vals := strings.Fields(m[2])
			// per-core values + trailing Total; Total is dropped
			if len(vals) != len(c.taskCols)+1 {
				return
			}
			for i, col := range c.taskCols {
				c.emit(fmt.Sprintf("%s__gc%02d__%s", c.plane, col, m[1]), atofu(vals[i]))
			}
		}
	case "cache":
		if m := cacheRowRe.FindStringSubmatch(trimmed); m != nil {
			base := c.plane + "__ct__" + sanitizeCounter(m[1])
			c.emit(base+"_max_entries", atofu(m[2]))
			c.emit(base+"_cur_entries", atofu(m[3]))
			c.emit(base+"_max_alloc", atofu(m[4]))
			c.emit(base+"_cur_sz_b", atofu(m[5]))
			c.emit(base+"_insert_failure", atofu(m[6]))
			// Mem-Pool-Type (m[7]) intentionally not tracked
		}
	case "mempool":
		c.mempoolRow(trimmed)
	case "softpool":
		c.softpoolRow(trimmed)
	case "powpool":
		c.powpoolRow(trimmed)
	case "sharedpool":
		c.sharedpoolRow(trimmed)
	}
}

// cpuBlockLine handles the standalone "--- cpu" block:
//
//	Last 180 seconds
//	Avg (%)    Max (%)
//	17         24
//	Load Avg:
//	1.44 1.67 1.58 1/1449 498878
func (c *counterCollector) cpuBlockLine(trimmed string) {
	if strings.HasPrefix(trimmed, "Load Avg") {
		c.loadAvgNext = true
		return
	}
	if c.loadAvgNext {
		if m := loadAvgRe.FindStringSubmatch(trimmed); m != nil {
			c.emit(c.plane+"__cpu_load_avg__i_1", atofu(m[1]))
			c.emit(c.plane+"__cpu_load_avg__i_5", atofu(m[2]))
			c.emit(c.plane+"__cpu_load_avg__i_15", atofu(m[3]))
		}
		c.loadAvgNext = false
		return
	}
	if !c.cpuDone {
		if m := cpuAvgMaxRe.FindStringSubmatch(trimmed); m != nil {
			c.emit(c.plane+"__cpu__last_3m_avg_pct", atofu(m[1]))
			c.emit(c.plane+"__cpu__last_3m_max_pct", atofu(m[2]))
			c.cpuDone = true
		}
	}
}

// ifconfigLine handles "--- ifconfig": per-interface RX/TX counter rows.
//
//	1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 ...
//	    RX:  bytes packets errors dropped  missed   mcast
//	    2572190192 9666206      0       0       0       0
//	    TX:  bytes packets errors dropped carrier collsns
//	    ...
func (c *counterCollector) ifconfigLine(trimmed string) {
	if m := ifaceHdrRe.FindStringSubmatch(trimmed); m != nil {
		name := m[1]
		if at := strings.IndexByte(name, '@'); at >= 0 {
			name = name[:at] // "eth0@if5" → "eth0"
		}
		c.curIface = sanitizeCounter(name)
		c.rxtxDir = ""
		return
	}
	if m := rxtxHdrRe.FindStringSubmatch(trimmed); m != nil && c.curIface != "" {
		c.rxtxDir = strings.ToLower(m[1])
		c.rxtxCols = strings.Fields(m[2])
		return
	}
	if c.rxtxDir != "" && numsOnlyRe.MatchString(trimmed) {
		vals := strings.Fields(trimmed)
		if len(vals) == len(c.rxtxCols) {
			for i, col := range c.rxtxCols {
				c.emit(c.plane+"__ifconfig__"+c.curIface+"_"+c.rxtxDir+"_"+sanitizeCounter(col), atofu(vals[i]))
			}
		}
		c.rxtxDir = ""
	}
}

// memoryLine handles "--- memory" (chosen over the top block: it is sampled
// ~7x more often and includes MemAvailable; values stay in kB).
//
//	Mem        429592        424240        8111956       1881560
//	Swap       3096060       3095804       4095996
func (c *counterCollector) memoryLine(trimmed string) {
	if m := memRowRe.FindStringSubmatch(trimmed); m != nil {
		c.emit(c.plane+"__memory__mem_free", atofu(m[1]))
		c.emit(c.plane+"__memory__mem_min", atofu(m[2]))
		c.emit(c.plane+"__memory__mem_total", atofu(m[3]))
		c.emit(c.plane+"__memory__mem_available", atofu(m[4]))
	} else if m := swapRowRe.FindStringSubmatch(trimmed); m != nil {
		c.emit(c.plane+"__memory__swap_free", atofu(m[1]))
		c.emit(c.plane+"__memory__swap_min", atofu(m[2]))
		c.emit(c.plane+"__memory__swap_total", atofu(m[3]))
	}
}

// logrcvrLine handles "--- logrcvr_statistics": "Label:  N[/sec]" lines up to
// and including "Total (MB)". "Traffic logs written" is intentionally skipped.
func (c *counterCollector) logrcvrLine(trimmed string) {
	if c.lrDone {
		return
	}
	m := lrLineRe.FindStringSubmatch(trimmed)
	if m == nil {
		return
	}
	label := sanitizeCounter(m[1])
	if label == "traffic_logs_written" {
		return
	}
	c.emit(c.plane+"__logreceiver_statistics__"+label, atofu(m[2]))
	if label == "total_mb" {
		c.lrDone = true
	}
}

// netstatLine handles "--- netstat_detail": Recv-Q/Send-Q per program.
// Rows without a program name are skipped; multiple sockets of the same
// proto+program are summed and flushed at the end of the block.
func (c *counterCollector) netstatLine(trimmed string) {
	if c.nsAcc == nil {
		return
	}
	fields := strings.Fields(trimmed)
	if len(fields) < 6 || !strings.HasPrefix(fields[0], "tcp") && !strings.HasPrefix(fields[0], "udp") {
		return
	}
	m := nsProgRe.FindStringSubmatch(fields[len(fields)-1])
	if m == nil {
		return // no program name
	}
	proto := sanitizeCounter(fields[0])
	prog := sanitizeCounter(m[2])
	base := c.plane + "__netstat_detail__" + proto + "_" + prog
	c.nsAcc[base+"_recv_q"] += atofu(fields[1])
	c.nsAcc[base+"_send_q"] += atofu(fields[2])
}

func atofu(s string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return f
}

// mempoolCols is the positional field list of the global :Mem-Pool-Type table.
var mempoolCols = []string{
	"max_sz_b", "threshold", "min_sz_b", "cur_sz_b",
	"max_alloc", "cur_alloc", "total_alloc",
	"fail_thresh", "fail_nomem", "local_reuse",
}

// sharedPoolCols is the positional field list of the :User ... shared pool
// table; the trailing Data(Pool)-SZ column is intentionally excluded.
var sharedPoolCols = []string{
	"quota", "threshold", "min_alloc", "cur_alloc", "max_alloc",
	"total_alloc", "fail_thresh", "fail_nomem", "local_reuse",
}

// leadNum parses the leading number of a field, ignoring a trailing
// parenthetical such as the "(0)" in a Local-Reuse "0(0)" value.
func leadNum(s string) float64 {
	if i := strings.IndexByte(s, '('); i >= 0 {
		s = s[:i]
	}
	return atofu(s)
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// netstatStatsLine handles "--- netstat_stats" (netstat -s style output).
// Section headers like "Ip:" / "TcpExt:" set the current section; stat lines
// come in two shapes: "Label: <n>" and "<n> free-text label".
func (c *counterCollector) netstatStatsLine(trimmed string) {
	if trimmed == "" {
		return
	}
	if m := nsSectionRe.FindStringSubmatch(trimmed); m != nil {
		c.nsSection = sanitizeCounter(m[1])
		return
	}
	if c.nsSection == "" {
		return
	}
	if m := nsColonRe.FindStringSubmatch(trimmed); m != nil {
		c.emit(c.plane+"__nsstats__"+c.nsSection+"_"+sanitizeCounter(m[1]), atofu(m[2]))
		return
	}
	if m := nsNumFirstRe.FindStringSubmatch(trimmed); m != nil {
		c.emit(c.plane+"__nsstats__"+c.nsSection+"_"+sanitizeCounter(m[2]), atofu(m[1]))
	}
}

// processesLine handles "--- processes": one row per process. Columns are
// Name PID CPU% FDs-Open Virt-Mem Res+Swap State Res+Swap-Lazy; State is
// non-numeric and skipped. Counters are keyed by process name and PID.
func (c *counterCollector) processesLine(trimmed string) {
	f := strings.Fields(trimmed)
	if len(f) < 6 || !isAllDigits(f[1]) {
		return // header row, "Total num processes", or malformed
	}
	base := c.plane + "__processes__" + sanitizeCounter(f[0]) + "_" + f[1]
	c.emit(base+"_cpu", atofu(f[2]))
	c.emit(base+"_fds_open", atofu(f[3]))
	c.emit(base+"_virt_mem", atofu(f[4]))
	c.emit(base+"_res_swap", atofu(f[5]))
	if len(f) >= 8 {
		c.emit(base+"_res_swap_lazy", atofu(f[len(f)-1]))
	}
}

// filesystemLine handles "--- filesystem": "Mount  Used(%)  Used(kB)" rows.
func (c *counterCollector) filesystemLine(trimmed string) {
	m := fsRowRe.FindStringSubmatch(trimmed)
	if m == nil {
		return
	}
	base := c.plane + "__filesystem__" + fsMountName(m[1])
	c.emit(base+"_pct", atofu(m[2]))
	c.emit(base+"_used_kb", atofu(m[3]))
}

// fsMountName turns a mount path into a counter-safe name ("/" -> "root").
func fsMountName(p string) string {
	if p == "/" {
		return "root"
	}
	return sanitizeCounter(p)
}

// mempoolRow emits one row of the global :Mem-Pool-Type table. Rows may be
// short (trailing columns omitted); only the columns present are emitted.
func (c *counterCollector) mempoolRow(trimmed string) {
	m := mempoolRowRe.FindStringSubmatch(trimmed)
	if m == nil {
		return
	}
	base := c.plane + "__pool__mempool__" + sanitizeCounter(m[1])
	for i, f := range strings.Fields(m[2]) {
		if i >= len(mempoolCols) {
			break
		}
		c.emit(base+"_"+mempoolCols[i], leadNum(f))
	}
}

// sharedpoolRow emits one row of the :User ... shared pool table.
func (c *counterCollector) sharedpoolRow(trimmed string) {
	m := sharedpoolRowRe.FindStringSubmatch(trimmed)
	if m == nil {
		return
	}
	base := c.plane + "__pool__sharedpool__" + sanitizeCounter(m[1])
	fields := strings.Fields(m[2])
	for i := 0; i < len(fields) && i < len(sharedPoolCols); i++ {
		c.emit(base+"_"+sharedPoolCols[i], leadNum(fields[i]))
	}
}

// softpoolRow emits the free value and free/total ratio for one
// :Software Pools row.
func (c *counterCollector) softpoolRow(trimmed string) {
	m := softpoolRowRe.FindStringSubmatch(trimmed)
	if m == nil {
		return
	}
	base := c.plane + "__pool__softpool__" + sanitizeCounter(m[1])
	free, total := atofu(m[2]), atofu(m[3])
	c.emit(base, free)
	if total != 0 {
		c.emit(base+"_pct", free/total)
	}
}

// powpoolRow emits the free value and free/total ratio for one Pow Atomic
// Memory Pools row.
func (c *counterCollector) powpoolRow(trimmed string) {
	m := powpoolRowRe.FindStringSubmatch(trimmed)
	if m == nil {
		return
	}
	base := c.plane + "__pool__powpool__" + sanitizeCounter(m[1])
	free, total := atofu(m[2]), atofu(m[3])
	c.emit(base, free)
	if total != 0 {
		c.emit(base+"_pct", free/total)
	}
}
