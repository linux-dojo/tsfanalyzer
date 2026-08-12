package parser

import (
	"archive/tar"
	"bufio"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// CounterSample is one measurement of one counter at one point in time.
// Used while streaming a log and by tests; stored data uses Series below.
type CounterSample struct {
	Name  string    `json:"name"`
	Ts    time.Time `json:"ts"`
	Value float64   `json:"value"`
}

// Point is one sample of an already-identified counter.
//
// The name is deliberately absent: it is the map key in Series. Carrying it
// per sample meant a large archive held millions of copies of ~30k distinct
// strings, which was enough on its own to exhaust the API container.
type Point struct {
	Ts    time.Time `json:"ts"`
	Value float64   `json:"value"`
}

// Series is every counter in an archive, keyed by name. Each name exists
// exactly once (as the map key) and each slice is sorted oldest-first.
type Series map[string][]Point

// Global-counter sections with a shorter elapsed time are incremental deltas
// printed between full samples; they would throw the series off, so only
// sections at/above this elapsed time are collected.
const gcMinElapsedSeconds = 120.0

var monitorFileRe = regexp.MustCompile(`(?:^|/)(dp|mp)-monitor\.log(?:\.\d+)?$`)

// CollectAllCounters makes a single pass over the archive and extracts
// counter time series from every dp-monitor.log* and mp-monitor.log* file.
// Samples accumulate straight into a name-keyed map, so a counter name is
// allocated once no matter how many samples it has.
func CollectAllCounters(r io.ReadSeeker) (Series, error) {
	tr, err := openTar(r)
	if err != nil {
		return nil, err
	}
	out := Series{}
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
		collectMonitor(tr, m[1], out)
	}
	// rotated logs can be visited out of order, so normalize per series
	for name := range out {
		pts := out[name]
		sort.Slice(pts, func(i, j int) bool { return pts[i].Ts.Before(pts[j].Ts) })
		out[name] = pts
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

	// "--- memory_detail" block: /proc/meminfo style "Key:  <n> kB" lines.
	// SUnreclaim (unreclaimable slab) is the key signal for kernel-side
	// growth that no user-space process accounts for.
	memDetailRe = regexp.MustCompile(`^([A-Za-z_()][A-Za-z0-9_()]*):\s+(-?\d+)(?:\s+kB)?\s*$`)

	// "--- slabinfo" block: the /proc/slabinfo table. Columns after the
	// name are: active_objs num_objs objsize objperslab pagesperslab,
	// then tunables/slabdata sections. Total active size is derived as
	// active_objs * objsize, which is what makes a growing cache like
	// kmalloc-96 visible in bytes rather than object counts alone.
	slabRowRe = regexp.MustCompile(`^(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*:`)

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

	// "--- top" block
	topUptimeRe = regexp.MustCompile(`up\s+(.+?),\s+\d+\s+users?`)
	topUsersRe  = regexp.MustCompile(`,\s+(\d+)\s+users?`)
	topLoadRe   = regexp.MustCompile(`load average:\s*([\d.]+),\s*([\d.]+),\s*([\d.]+)`)
	upDaysRe    = regexp.MustCompile(`(\d+)\s+day`)
	upHMRe      = regexp.MustCompile(`(\d+):(\d+)`)
	upMinRe     = regexp.MustCompile(`(\d+)\s+min`)
	numWordRe   = regexp.MustCompile(`([\d.]+)\s+([A-Za-z/]+)`)

	// processing-time tables (:func / :group summaries, and per-col detail)
	procusFuncHdrRe  = regexp.MustCompile(`^:func\s+max-us`)
	procusGroupHdrRe = regexp.MustCompile(`^:group\s+max-us`)
	procusRowRe      = regexp.MustCompile(`^:([a-z][a-z0-9_]*)\s+(.+)$`)
	procusdHdrRe     = regexp.MustCompile(`^:(\S+)\s+\((func|group)\)\s*$`)
	procusdRowRe     = regexp.MustCompile(`^:\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)`)

	// resource utilization (%) during last 15 minutes
	ruSecRe   = regexp.MustCompile(`^:Resource utilization \(%\) during last 15 minutes:`)
	ruLabelRe = regexp.MustCompile(`^:(.+?)\s+\((average|maximum)\):`)
	ruRowRe   = regexp.MustCompile(`^:\s+(\d+(?:\s+\d+)*)\s*$`)

	// session info block
	siStartRe   = regexp.MustCompile(`^:Number of sessions supported`)
	siDiscardRe = regexp.MustCompile(`TCP:\s*(\d+)\s*secs.*UDP:\s*(\d+).*SCTP:\s*(\d+).*other IP protocols:\s*(\d+)`)
	firstNumRe  = regexp.MustCompile(`-?\d+(?:\.\d+)?`)

	// "--- pow" thread statistics
	vmpowStartRe     = regexp.MustCompile(`^:pow parameters:`)
	vmpowThreadNumRe = regexp.MustCompile(`^:thread (\d+)`)
	vmpowThreadRe    = regexp.MustCompile(`^:thread (\d+) (rcv_tot|deq|null|submit|desubmit|sel to|sel ok|pow_wait) (\d+)`)
	vmpowIoWqeRe     = regexp.MustCompile(`^:io: wqe alloc (\d+) wqe null (\d+)`)
	vmpowInflightRe  = regexp.MustCompile(`^:Total inflight wqe (\d+)`)
	vmpowUsedWqeRe   = regexp.MustCompile(`^:used wqe (\d+) total wqe (\d+)\s+(\d+)% used`)
	vmpowRcvThreshRe = regexp.MustCompile(`^:rcv_thresh\s*:\s*(\d+)`)
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

	detKind string // procusd: "func"/"group"
	detName string // procusd: current detailed table name
	ruLabel string // ru: current "<name>_avg|_max"

	powThread int // vmpow: current thread context (for io lines)

	out Series
}

func collectMonitor(r io.Reader, plane string, out Series) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	c := &counterCollector{plane: plane, out: out}
	for sc.Scan() {
		c.line(strings.TrimRight(sc.Text(), "\r"))
	}
	c.flushNetstat()
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
	// appending under the map key means the freshly concatenated name string
	// is retained once (as the key) and the rest becomes garbage
	c.out[name] = append(c.out[name], Point{Ts: ts, Value: v})
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
		c.detKind, c.detName, c.ruLabel = "", "", ""
		c.powThread = 0
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
	case "memory_detail":
		c.memoryDetailLine(trimmed)
		return
	case "slabinfo":
		c.slabinfoLine(trimmed)
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
	case "top":
		c.topLine(trimmed)
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
	case procusFuncHdrRe.MatchString(trimmed):
		c.mode = "procus_func"
		return
	case procusGroupHdrRe.MatchString(trimmed):
		c.mode = "procus_group"
		return
	case procusdHdrRe.MatchString(trimmed):
		m := procusdHdrRe.FindStringSubmatch(trimmed)
		c.mode, c.detName, c.detKind = "procusd", sanitizeCounter(m[1]), m[2]
		return
	case ruSecRe.MatchString(trimmed):
		c.mode, c.ruLabel = "ru", ""
		return
	case siStartRe.MatchString(trimmed):
		c.mode = "si"
		c.siLine(trimmed)
		return
	case vmpowStartRe.MatchString(trimmed):
		c.mode, c.powThread = "vmpow", 0
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
	case "procus_func":
		c.procusRow(trimmed, "func")
	case "procus_group":
		c.procusRow(trimmed, "group")
	case "procusd":
		c.procusdRow(trimmed)
	case "ru":
		c.ruLine(trimmed)
	case "si":
		c.siLine(trimmed)
	case "vmpow":
		c.vmpowLine(trimmed)
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

// memoryDetailLine handles "--- memory_detail", the /proc/meminfo dump.
// Every "Key: <n> kB" line becomes <plane>__memorydetail__<key>, values
// kept in kB as printed. From PAN-OS 10.2 this block is the authoritative
// place to read available memory, and its SUnreclaim/Slab counters are how
// kernel-side growth is distinguished from a user-space process leak.
func (c *counterCollector) memoryDetailLine(trimmed string) {
	m := memDetailRe.FindStringSubmatch(trimmed)
	if m == nil {
		return
	}
	c.emit(c.plane+"__memorydetail__"+sanitizeCounter(m[1]), atofu(m[2]))
}

// slabinfoLine handles "--- slabinfo" rows, emitting per-cache object
// counts plus a derived total active size in bytes so growth in a specific
// cache (e.g. kmalloc-96) can be graphed against available memory.
func (c *counterCollector) slabinfoLine(trimmed string) {
	if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "slabinfo") {
		return
	}
	m := slabRowRe.FindStringSubmatch(trimmed)
	if m == nil {
		return
	}
	base := c.plane + "__slabinfo__" + sanitizeCounter(m[1])
	activeObjs, numObjs, objSize := atofu(m[2]), atofu(m[3]), atofu(m[4])
	c.emit(base+"_activeobjs", activeObjs)
	c.emit(base+"_numobjs", numObjs)
	c.emit(base+"_objsize", objSize)
	c.emit(base+"_totalactsize", activeObjs*objSize)
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
	"max_sz_kb", "threshold", "min_sz_kb", "cur_sz_b",
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
		c.emit(c.plane+"__nsstats__"+c.nsSection+"__"+sanitizeCounter(m[1]), atofu(m[2]))
		return
	}
	if m := nsNumFirstRe.FindStringSubmatch(trimmed); m != nil {
		c.emit(c.plane+"__nsstats__"+c.nsSection+"__"+sanitizeCounter(m[2]), atofu(m[1]))
	}
}

// processesLine handles "--- processes": one row per process. Columns are
// Name PID CPU% FDs-Open Virt-Mem Res+Swap State Res+Swap-Lazy; State is
// non-numeric and skipped. Counters are keyed by process name and PID.
func (c *counterCollector) processesLine(trimmed string) {
	f := strings.Fields(trimmed)
	if strings.HasPrefix(trimmed, "Total num processes") {
		if n := firstNumRe.FindString(trimmed); n != "" {
			c.emit(c.plane+"__total__processes", atofu(n))
		}
		return
	}
	if strings.HasPrefix(trimmed, "Totals") && len(f) >= 6 {
		c.emit(c.plane+"__total__cpu_pct", atofu(f[1]))
		c.emit(c.plane+"__total__fds", atofu(f[2]))
		c.emit(c.plane+"__total__virt_mem", atofu(f[3]))
		c.emit(c.plane+"__total__res_mem", atofu(f[4]))
		c.emit(c.plane+"__total__res_mem_sub_lazy", atofu(f[5]))
		return
	}
	if len(f) < 6 || !isAllDigits(f[1]) {
		return // header row, "Total num processes", or malformed
	}
	base := c.plane + "__processes__" + sanitizeCounter(f[0]) + "_" + f[1]
	c.emit(base+"_cpu", atofu(f[2]))
	c.emit(base+"_fds_open", atofu(f[3]))
	c.emit(base+"_virt_mem", atofu(f[4]))
	c.emit(base+"_res_swap", atofu(f[5]))
	if len(f) >= 8 {
		c.emit(base+"_res_swap_sub_lazy", atofu(f[len(f)-1]))
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

/* ---------- processing-time tables ---------- */

var procusCols = []string{
	"max_us", "avg_us", "count", "total_us",
	"ac_max_us", "ac_avg_us", "ac_count", "ac_total_us",
}

var procusdCols = []string{"avg_ticks", "avg_us", "count", "total_us"}

// procusRow emits one row of a :func or :group processing-time summary.
func (c *counterCollector) procusRow(trimmed, kind string) {
	m := procusRowRe.FindStringSubmatch(trimmed)
	if m == nil {
		return
	}
	base := c.plane + "__procus__" + kind + "__" + sanitizeCounter(m[1])
	for i, f := range strings.Fields(m[2]) {
		if i >= len(procusCols) {
			break
		}
		c.emit(base+"_"+procusCols[i], atofu(f))
	}
}

// procusdRow emits one per-column row of a "<name> (func|group)" detail table.
func (c *counterCollector) procusdRow(trimmed string) {
	if c.detName == "" {
		return
	}
	m := procusdRowRe.FindStringSubmatch(trimmed)
	if m == nil {
		return
	}
	base := c.plane + "__procusd__" + c.detKind + "__" + c.detName + "_c" + m[1]
	for i, v := range []string{m[2], m[3], m[4], m[5]} {
		c.emit(base+"_"+procusdCols[i], atofu(v))
	}
}

/* ---------- resource utilization (%) during last 15 minutes ---------- */

var ruNames = map[string]string{
	"session":            "session",
	"packet buffer":      "pktbuf",
	"packet descriptor":  "pktdesc",
	"sw tags descriptor": "swtags",
}

// ruLine tracks the current "<thing> (average|maximum)" label and, on the
// value row that follows, emits the 15 per-minute samples newest-first
// (column 1 = current minute).
func (c *counterCollector) ruLine(trimmed string) {
	if m := ruLabelRe.FindStringSubmatch(trimmed); m != nil {
		name, ok := ruNames[strings.TrimSpace(m[1])]
		if !ok {
			name = sanitizeCounter(m[1])
		}
		suf := "_avg"
		if m[2] == "maximum" {
			suf = "_max"
		}
		c.ruLabel = name + suf
		return
	}
	if c.ruLabel == "" {
		return
	}
	if m := ruRowRe.FindStringSubmatch(trimmed); m != nil {
		for i, f := range strings.Fields(m[1]) {
			c.emitAt(c.ts.Add(-time.Duration(i)*time.Minute), c.plane+"__ru__"+c.ruLabel, atofu(f))
		}
		c.ruLabel = "" // exactly one value row per label
	}
}

/* ---------- session info ---------- */

// siMap maps a session-info label (text before its colon) to a counter suffix.
var siMap = map[string]string{
	"Number of sessions supported":               "sessions_supported",
	"Number of allocated sessions":               "sessions_allocated",
	"Number of active TCP sessions":              "sessions_tcp",
	"Number of active UDP sessions":              "sessions_udp",
	"Number of active ICMP sessions":             "sessions_icmp",
	"Number of active GTPc sessions":             "sessions_gtpc",
	"Number of active HTTP2-5gc sessions":        "sessions_http2_5gc",
	"Number of active GTPu sessions":             "sessions_gtpu",
	"Number of pending GTPu sessions":            "sessions_pending_gtpu",
	"Number of active BCAST sessions":            "sessions_bcast",
	"Number of active MCAST sessions":            "sessions_mcast",
	"Number of active predict sessions":          "sessions_predict",
	"Number of active SCTP sessions":             "sessions_sctp",
	"Number of active SCTP associations":         "associations_sctp",
	"Number of active PFCP sessions":             "sessions_pfcp",
	"Number of active IMSI sessions":             "sessions_imsi",
	"Session table utilization":                  "session_table_utelization_pct",
	"Number of sessions created since bootup":    "sesscrsboot",
	"Packet rate":                                "pktrate",
	"Throughput":                                 "throughput_kbps",
	"New connection establish rate":              "newconn",
	"TCP default timeout":                        "timeout_tcp_default",
	"TCP session timeout before SYN-ACK received":   "timeout_tcp_before_syn_ack",
	"TCP session timeout before 3-way handshaking":  "timeout_tcp_before_3way",
	"TCP half-closed session timeout":            "timeout_tcp_half_closed",
	"TCP session timeout in TIME_WAIT":           "timeout_tcp_time_wait",
	"TCP session delayed ack timeout":            "timeout_tcp_delayed_ack",
	"TCP session timeout for unverified RST":     "timeout_tcp_unverified_rst",
	"UDP default timeout":                        "timeout_udp_default",
	"ICMP default timeout":                       "timeout_icmp_default",
	"SCTP default timeout":                       "timeout_sctp_default",
	"SCTP timeout before INIT-ACK received":      "timeout_sctp_before_init_ack",
	"SCTP timeout before COOKIE received":        "timeout_sctp_before_cookie",
	"SCTP timeout before SHUTDOWN received":      "timeout_sctp_before_shutdown",
	"5GC delete timeout":                         "timeout_5gc_delete",
	"other IP default timeout":                   "timeout_other_ip_default",
	"Captive Portal session timeout":             "timeout_captive_portal",
	"Session accelerated aging":                  "accel_aging",
	"Accelerated aging threshold":                "accel_aging_threshold_pct",
	"Scaling factor":                             "accel_aging_scaling_factor",
	"TCP - reject non-SYN first packet":          "setup_reject_non_syn_first",
	"Hardware session offloading":                "hw_offload",
	"Software Cut Through":                        "setup_sw_cut_through",
	"Run-to-completion mode":                      "setup_run_to_completion",
	"Tunnel acceleration":                        "setup_tunnel_accel",
	"IPv6 firewalling":                           "setup_ipv6_firewalling",
	"Strict TCP/IP checksum":                     "setup_strict_tcpip_checksum",
	"Strict TCP RST sequence":                    "setup_strict_tcp_rst_seq",
	"Reject TCP small initial window":            "setup_reject_tcp_small_initial_window",
	"Reject TCP SYN with different seq/options":  "setup_reject_tcp_syn_diff_seq",
	"Teardown session if forward zone changes":   "setup_teardown_on_fwd_zone_change",
	"Do not refresh discard sessions":            "setup_no_refresh_discard",
	"ICMP Unreachable Packet Rate":               "setup_icmp_unreachable_rate",
	"Timeout to determine application trickling":  "trickling_timeout",
	"Resource utilization threshold to start scan": "trickling_ru_threshold_pct",
	"Scan scaling factor over regular aging":     "trickling_scan_scaling_factor",
	"Pcap token bucket rate":                     "pcap_token_bucket_rate",
	"Max pending queued mcast packets per session": "max_pending_mcast_pkts",
}

// siLine parses one session-info line. Booleans map True->1, False->-1;
// otherwise the first number in the value is used (units stripped).
func (c *counterCollector) siLine(trimmed string) {
	s := strings.TrimSpace(strings.TrimPrefix(trimmed, ":"))
	if m := siDiscardRe.FindStringSubmatch(s); m != nil {
		c.emit(c.plane+"__si__timeout_discard_tcp", atofu(m[1]))
		c.emit(c.plane+"__si__timeout_discard_udp", atofu(m[2]))
		c.emit(c.plane+"__si__timeout_discard_sctp", atofu(m[3]))
		c.emit(c.plane+"__si__timeout_discard_other_ip", atofu(m[4]))
		return
	}
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return
	}
	suf, ok := siMap[strings.TrimSpace(s[:i])]
	if !ok {
		return
	}
	val := s[i+1:]
	base := c.plane + "__si__" + suf
	switch {
	case strings.Contains(val, "True"):
		c.emit(base, 1)
	case strings.Contains(val, "False"):
		c.emit(base, -1)
	default:
		if num := firstNumRe.FindString(val); num != "" {
			c.emit(base, atofu(num))
		}
	}
}

/* ---------- top ---------- */

// parseUptime converts the "up ..." field to total minutes. Handles
// "HH:MM", "N days, HH:MM", "N day, HH:MM" and "N min".
func parseUptime(s string) int {
	mins := 0
	if m := upDaysRe.FindStringSubmatch(s); m != nil {
		d, _ := strconv.Atoi(m[1])
		mins += d * 1440
	}
	if m := upHMRe.FindStringSubmatch(s); m != nil {
		h, _ := strconv.Atoi(m[1])
		mm, _ := strconv.Atoi(m[2])
		mins += h*60 + mm
	} else if m := upMinRe.FindStringSubmatch(s); m != nil {
		mm, _ := strconv.Atoi(m[1])
		mins += mm
	}
	return mins
}

// topLine parses one line of the "--- top" block.
func (c *counterCollector) topLine(trimmed string) {
	if pf := strings.Fields(trimmed); len(pf) >= 12 && isAllDigits(pf[0]) {
		c.topProcessRow(pf)
		return
	}
	if strings.HasPrefix(trimmed, "top -") {
		if m := topUptimeRe.FindStringSubmatch(trimmed); m != nil {
			c.emit(c.plane+"__top__uptime_minutes", float64(parseUptime(m[1])))
		}
		if m := topUsersRe.FindStringSubmatch(trimmed); m != nil {
			c.emit(c.plane+"__top__user_sess", atofu(m[1]))
		}
		if m := topLoadRe.FindStringSubmatch(trimmed); m != nil {
			c.emit(c.plane+"__top__load_avg_1", atofu(m[1]))
			c.emit(c.plane+"__top__load_avg_5", atofu(m[2]))
			c.emit(c.plane+"__top__load_avg_15", atofu(m[3]))
		}
		return
	}
	pairs := map[string]float64{}
	for _, mm := range numWordRe.FindAllStringSubmatch(trimmed, -1) {
		pairs[mm[2]] = atofu(mm[1])
	}
	emit := func(set map[string]string, prefix, suffix string) {
		for k, n := range set {
			if v, ok := pairs[k]; ok {
				c.emit(c.plane+"__top__"+prefix+n+suffix, v)
			}
		}
	}
	switch {
	case strings.HasPrefix(trimmed, "Tasks:"):
		emit(map[string]string{"total": "tasks_total", "running": "tasks_running",
			"sleeping": "tasks_sleeping", "stopped": "tasks_stopped", "zombie": "tasks_zombie"}, "", "")
	case strings.HasPrefix(trimmed, "%Cpu"):
		emit(map[string]string{"us": "user", "sy": "system", "ni": "nice", "id": "idle",
			"wa": "iowait", "hi": "hinterrupt", "si": "sinterrupt", "st": "st"}, "cpu__", "_pct")
	case strings.HasPrefix(trimmed, "MiB Mem"):
		emit(map[string]string{"total": "mem_total", "free": "mem_free",
			"used": "mem_used", "buff/cache": "mem_buffcache"}, "", "")
	case strings.HasPrefix(trimmed, "MiB Swap"):
		emit(map[string]string{"total": "swap_total", "free": "swap_free",
			"used": "swap_used", "avail": "avail_mem"}, "", "")
	}
}

/* ---------- top per-process table ---------- */

// parseTopSize converts a top SIZE field to bytes. A k/m/g/t suffix scales
// accordingly; a bare number is KiB (top's default unit).
func parseTopSize(s string) float64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	mult := 1024.0 // bare = KiB
	switch s[len(s)-1] {
	case 'k', 'K':
		mult, s = 1024, s[:len(s)-1]
	case 'm', 'M':
		mult, s = 1024*1024, s[:len(s)-1]
	case 'g', 'G':
		mult, s = 1024*1024*1024, s[:len(s)-1]
	case 't', 'T':
		mult, s = 1024*1024*1024*1024, s[:len(s)-1]
	}
	return atofu(s) * mult
}

// parseTopTime converts a top TIME+ field (MM:SS.ss or HH:MM:SS) to seconds.
func parseTopTime(s string) float64 {
	var total float64
	for _, p := range strings.Split(strings.TrimSpace(s), ":") {
		total = total*60 + atofu(p)
	}
	return total
}

// topProcessRow emits one row of the top per-process table. Columns:
// PID USER PR NI VIRT RES SHR S %CPU %MEM TIME+ COMMAND (USER/PR/S skipped).
func (c *counterCollector) topProcessRow(f []string) {
	base := c.plane + "__topprocess__" + sanitizeCounter(f[11]) + "_" + f[0] + "__"
	c.emit(base+"cpu", atofu(f[8]))
	c.emit(base+"mem_pct", atofu(f[9]))
	c.emit(base+"nice", atofu(f[3]))
	c.emit(base+"virt_mem", parseTopSize(f[4]))
	c.emit(base+"res_mem", parseTopSize(f[5]))
	c.emit(base+"shr_mem", parseTopSize(f[6]))
	c.emit(base+"time", parseTopTime(f[10]))
}

/* ---------- pow thread statistics ---------- */

var vmpowFields = map[string]string{
	"rcv_tot": "rcv_tot", "deq": "deq", "null": "null", "submit": "submit",
	"desubmit": "desubmit", "sel to": "sel_to", "sel ok": "sel_ok", "pow_wait": "pow_wait",
}

// vmpowLine parses the pow thread-statistics block. Per-thread metrics carry
// their thread number inline; the "io:" lines inherit the most recent thread.
func (c *counterCollector) vmpowLine(trimmed string) {
	if m := vmpowThreadNumRe.FindStringSubmatch(trimmed); m != nil {
		c.powThread, _ = strconv.Atoi(m[1])
	}
	if m := vmpowThreadRe.FindStringSubmatch(trimmed); m != nil {
		if field := vmpowFields[m[2]]; field != "" {
			c.emit(fmt.Sprintf("%s__vmpow__thread%02d__%s", c.plane, c.powThread, field), atofu(m[3]))
		}
		return
	}
	if m := vmpowIoWqeRe.FindStringSubmatch(trimmed); m != nil {
		c.emit(fmt.Sprintf("%s__vmpow__thread%02d__io_wqe_alloc", c.plane, c.powThread), atofu(m[1]))
		c.emit(fmt.Sprintf("%s__vmpow__thread%02d__io_wqe_null", c.plane, c.powThread), atofu(m[2]))
		return
	}
	if m := vmpowInflightRe.FindStringSubmatch(trimmed); m != nil {
		c.emit(c.plane+"__vmpow__total_inflight_wqe", atofu(m[1]))
		return
	}
	if m := vmpowUsedWqeRe.FindStringSubmatch(trimmed); m != nil {
		c.emit(c.plane+"__vmpow__used_wqe", atofu(m[1]))
		c.emit(c.plane+"__vmpow__used_wqe_total", atofu(m[2]))
		c.emit(c.plane+"__vmpow__used_wqe_pct", atofu(m[3]))
		return
	}
	if m := vmpowRcvThreshRe.FindStringSubmatch(trimmed); m != nil {
		c.emit(c.plane+"__vmpow__rcv_thresh", atofu(m[1]))
	}
}
