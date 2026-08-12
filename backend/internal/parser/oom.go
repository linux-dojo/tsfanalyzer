// Package parser: oom.go locates OOM-killer events in a tech-support
// archive and works out what actually consumed the memory.
//
// The reasoning it encodes, which is why it doesn't simply blame whatever
// the OOM log names:
//
//   - The kernel invokes the OOM killer when it cannot satisfy an
//     allocation. The process named as *invoking* it is merely the one
//     that happened to ask for memory next; it is not the cause.
//   - The process the kernel then SIGKILLs is chosen by OOM score, so it
//     is usually neither the requester nor the leaker — commonly it is
//     just the largest RSS at that instant.
//   - So the OOM log identifies no culprit at all. The culprit is found by
//     trending available memory (MemAvailable, not MemFree) and finding
//     which process's Res+Swap growth accounts for the decline.
//   - Highest absolute memory is not the criterion; several PAN-OS
//     processes are legitimately large. Only growth that tracks the
//     available-memory decline is suspicious.
//   - If no user-space process accounts for the drop, the leak is likely
//     in the kernel: unreclaimable slab (SUnreclaim) and then the
//     individual slab caches (e.g. kmalloc-96) are checked instead.
package parser

import (
	"archive/tar"
	"bufio"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// OOMEvent is one OOM-killer invocation found in the logs.
type OOMEvent struct {
	Ts        time.Time `json:"ts"`
	InvokedBy string    `json:"invoked_by"`  // asked for memory; NOT the cause
	Killed    string    `json:"killed"`      // chosen by OOM score; usually not the cause either
	KilledPid string    `json:"killed_pid"`
	Score     string    `json:"score,omitempty"`
	Source    string    `json:"source"` // archive path the line came from
	Raw       string    `json:"raw"`
}

// MemSuspect is one process (or slab cache) whose growth is a candidate
// explanation for the decline in available memory.
//
// Process entries are keyed by process *name*, not name+PID: a restart
// gives the process a new PID and therefore a new counter series, so
// tracking per-PID would hide exactly the before/after comparison that
// identifies a leak. Counters lists every PID's series so the whole
// timeline can be plotted across restarts.
type MemSuspect struct {
	Name      string   `json:"name"`     // process or slab-cache name
	Counter   string   `json:"counter"`  // representative series
	Counters  []string `json:"counters"` // every series for this process, all PIDs
	PIDs      []string `json:"pids,omitempty"`
	StartKB   float64  `json:"start_kb"`
	EndKB     float64  `json:"end_kb"`
	PeakKB    float64  `json:"peak_kb"`
	GrowthKB  float64  `json:"growth_kb"`  // the figure it is ranked on
	PctOfDrop float64  `json:"pct_of_drop"` // share of the available-memory decline it explains
	Restarted bool     `json:"restarted"`

	// Restart evidence: what the process settled at after its last restart,
	// and how much the restart handed back. A large reclaim that then stays
	// flat well below the old peak is the signature of a leak — this is
	// stronger evidence than absolute size, which is why it is ranked on.
	PostRestartKB float64 `json:"post_restart_kb,omitempty"`
	ReclaimedKB   float64 `json:"reclaimed_kb,omitempty"`
}

// MemTrend is the available-memory trend the whole analysis is anchored to.
type MemTrend struct {
	Counter  string    `json:"counter"` // which series was used, and why matters: MemAvailable, not MemFree
	StartKB  float64   `json:"start_kb"`
	EndKB    float64   `json:"end_kb"`
	MinKB    float64   `json:"min_kb"`
	DropKB   float64   `json:"drop_kb"` // start - end; negative means it recovered
	From     time.Time `json:"from"`
	To       time.Time `json:"to"`
	Points   int       `json:"points"`
	SpanDays float64   `json:"span_days"`
}

// Finding is one human-readable conclusion, ordered by severity for display.
type Finding struct {
	Severity string `json:"severity"` // critical | high | medium | info
	Title    string `json:"title"`
	Detail   string `json:"detail"`
}

// MemoryAnalysis is the whole verdict rendered by the Memory / OOM tab.
type MemoryAnalysis struct {
	OOMEvents      []OOMEvent   `json:"oom_events"`
	FirstOOM       *OOMEvent    `json:"first_oom,omitempty"`
	Trend          *MemTrend    `json:"trend,omitempty"`
	Suspects       []MemSuspect `json:"suspects"`
	KernelSuspects []MemSuspect `json:"kernel_suspects"`
	KernelLikely   bool         `json:"kernel_likely"`
	Explained      float64      `json:"explained_pct"` // share of the drop user-space growth accounts for
	Duplicates     []string     `json:"duplicates"`    // process names seen with several PIDs
	Findings       []Finding    `json:"findings"`
}

/* ---------- locating OOM events in the archive ---------- */

var (
	oomInvokeRe = regexp.MustCompile(`(?i)([\w./-]+)\s+invoked\s+oom-killer`)
	// "Out of memory: Killed process 1234 (logd)" / "Kill process 1234 (logd) score 907"
	oomKillRe  = regexp.MustCompile(`(?i)(?:out of memory:\s*)?kill(?:ed)?\s+process\s+(\d+)\s+\(([^)]+)\)`)
	oomScoreRe = regexp.MustCompile(`(?i)score\s+(\d+)`)
	// files worth scanning for kernel messages
	oomFileRe = regexp.MustCompile(`(?i)(dmesg|messages|kern|syslog|show_log_system|_log_|\.log)`)
)

const maxOOMScanBytes = 64 << 20 // skip implausibly large single files

// FindOOMEvents scans the archive's log files for OOM-killer activity.
// Both halves of an OOM report (the "invoked oom-killer" line and the
// "Killed process" line) are correlated into one event when they appear
// close together, since they are emitted by the same incident.
func FindOOMEvents(r io.ReadSeeker) ([]OOMEvent, error) {
	tr, err := openTar(r)
	if err != nil {
		return nil, err
	}
	var out []OOMEvent
	refYear := time.Now().UTC().Year()

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			break // tolerate trailing corruption
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Size <= 0 || hdr.Size > maxOOMScanBytes {
			continue
		}
		path := normalizePath(hdr.Name)
		if !oomFileRe.MatchString(path) {
			continue
		}

		sc := bufio.NewScanner(tr)
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		var pending *OOMEvent // an "invoked oom-killer" awaiting its kill line

		for sc.Scan() {
			line := strings.TrimRight(sc.Text(), "\r")
			low := strings.ToLower(line)
			if !strings.Contains(low, "oom") && !strings.Contains(low, "out of memory") &&
				!strings.Contains(low, "kill process") && !strings.Contains(low, "killed process") {
				continue
			}
			ts, _ := extractTimestamp(line, refYear)

			if m := oomInvokeRe.FindStringSubmatch(line); m != nil {
				if pending != nil {
					out = append(out, *pending)
				}
				pending = &OOMEvent{Ts: ts, InvokedBy: m[1], Source: path, Raw: strings.TrimSpace(line)}
				continue
			}
			if m := oomKillRe.FindStringSubmatch(line); m != nil {
				ev := pending
				if ev == nil {
					ev = &OOMEvent{Ts: ts, Source: path, Raw: strings.TrimSpace(line)}
				}
				ev.KilledPid, ev.Killed = m[1], m[2]
				if s := oomScoreRe.FindStringSubmatch(line); s != nil {
					ev.Score = s[1]
				}
				if ev.Ts.IsZero() {
					ev.Ts = ts
				}
				out = append(out, *ev)
				pending = nil
			}
		}
		if pending != nil {
			out = append(out, *pending)
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Ts.Before(out[j].Ts) })
	return out, nil
}

/* ---------- memory trend and leak attribution ---------- */

// Units differ per source, so everything is normalized to kB before it is
// compared: the top block prints MiB, /proc/meminfo and the process table
// print kB, and the slabinfo total-active-size counter is derived in bytes.
const (
	kbPerMiB    = 1024.0
	bytesPerKB  = 1024.0
	restartDrop = 0.5 // a mid-window fall to under half of peak reads as a restart
)

// availCandidates lists the available-memory series in order of preference,
// with the multiplier that converts each into kB. MemAvailable is used
// rather than MemFree because free memory excludes reclaimable page cache
// and so understates what is actually usable.
var availCandidates = []struct {
	suffix string
	toKB   float64
}{
	{"__memorydetail__memavailable", 1},       // PAN-OS 10.2+, most precise
	{"__memory__mem_available", 1},            // --- memory block, sampled often
	{"__top__avail_mem", kbPerMiB},            // --- top, MiB
}

func bySeries(samples []CounterSample) map[string][]CounterSample {
	m := make(map[string][]CounterSample, 256)
	for _, s := range samples {
		m[s.Name] = append(m[s.Name], s)
	}
	for k := range m {
		v := m[k]
		sort.Slice(v, func(i, j int) bool { return v[i].Ts.Before(v[j].Ts) })
		m[k] = v
	}
	return m
}

// pickAvailTrend chooses the best available-memory series for the plane and
// summarizes its trend.
func pickAvailTrend(byName map[string][]CounterSample, plane string) *MemTrend {
	for _, c := range availCandidates {
		name := plane + c.suffix
		pts := byName[name]
		if len(pts) < 2 {
			continue
		}
		startKB := pts[0].Value * c.toKB
		endKB := pts[len(pts)-1].Value * c.toKB
		minKB := startKB
		for _, p := range pts {
			if v := p.Value * c.toKB; v < minKB {
				minKB = v
			}
		}
		span := pts[len(pts)-1].Ts.Sub(pts[0].Ts).Hours() / 24
		return &MemTrend{
			Counter: name, StartKB: startKB, EndKB: endKB, MinKB: minKB,
			DropKB: startKB - endKB, From: pts[0].Ts, To: pts[len(pts)-1].Ts,
			Points: len(pts), SpanDays: span,
		}
	}
	return nil
}

var procResSwapRe = regexp.MustCompile(`^(mp|dp)__processes__(.+)_(\d+)_res_swap$`)

// procPoint is one Res+Swap reading for a process, tagged with the PID it
// came from so PID changes (restarts) stay visible after merging series.
type procPoint struct {
	ts    time.Time
	value float64
	pid   string
}

// median is used for the post-restart level so a single spike or a slow
// ramp doesn't distort what the process actually settled at.
func median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := make([]float64, len(v))
	copy(s, v)
	sort.Float64s(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

// processSuspects ranks processes by Res+Swap growth and by how much a
// restart handed back, attributing a share of the available-memory decline
// to each. All PIDs of a process are merged into one timeline first, since
// a restart changes the PID and so starts a new counter series.
//
// Absolute size is deliberately not the ranking key: several PAN-OS
// processes are legitimately large. What is ranked is growth, and the
// memory a restart reclaimed and did not re-acquire.
func processSuspects(byName map[string][]CounterSample, plane string, dropKB float64) ([]MemSuspect, []string) {
	type agg struct {
		pts      []procPoint
		counters map[string]bool
		pids     map[string]bool
	}
	byProc := map[string]*agg{}

	for name, pts := range byName {
		m := procResSwapRe.FindStringSubmatch(name)
		if m == nil || m[1] != plane || len(pts) == 0 {
			continue
		}
		proc, pid := m[2], m[3]
		a := byProc[proc]
		if a == nil {
			a = &agg{counters: map[string]bool{}, pids: map[string]bool{}}
			byProc[proc] = a
		}
		a.counters[name] = true
		a.pids[pid] = true
		for _, p := range pts {
			a.pts = append(a.pts, procPoint{ts: p.Ts, value: p.Value, pid: pid})
		}
	}

	var out []MemSuspect
	var dups []string

	for proc, a := range byProc {
		if len(a.pts) < 2 {
			continue
		}
		sort.Slice(a.pts, func(i, j int) bool { return a.pts[i].ts.Before(a.pts[j].ts) })

		start := a.pts[0].value
		end := a.pts[len(a.pts)-1].value
		peak := start
		restarted := false
		lastRestart := -1

		for i, p := range a.pts {
			if p.value > peak {
				peak = p.value
			}
			if i > 0 {
				prev := a.pts[i-1]
				// two independent restart signals: the PID changed, or memory
				// fell steeply within one PID
				pidChanged := p.pid != prev.pid
				steepFall := prev.value > 0 && p.value < prev.value*restartDrop
				if pidChanged || steepFall {
					restarted = true
					lastRestart = i
				}
			}
		}

		// where it settled after the last restart
		postKB, reclaimedKB := 0.0, 0.0
		if restarted && lastRestart >= 0 && lastRestart < len(a.pts) {
			var after []float64
			for _, p := range a.pts[lastRestart:] {
				after = append(after, p.value)
			}
			postKB = median(after)
			reclaimedKB = peak - postKB
		}

		// The ranking figure. For a process that restarted, the memory the
		// restart gave back is the strongest evidence available — a process
		// sitting at 1.4 GB that runs steadily at 700 MB afterwards was
		// holding ~700 MB it did not need. Otherwise fall back to the climb.
		growth := end - start
		if restarted {
			if climb := peak - start; climb > growth {
				growth = climb
			}
			if reclaimedKB > growth {
				growth = reclaimedKB
			}
		}
		if growth <= 0 {
			continue // flat or shrinking with no restart evidence
		}

		pct := 0.0
		if dropKB > 0 {
			pct = growth / dropKB * 100
		}

		counters := make([]string, 0, len(a.counters))
		for c := range a.counters {
			counters = append(counters, c)
		}
		sort.Strings(counters)
		pids := make([]string, 0, len(a.pids))
		for p := range a.pids {
			pids = append(pids, p)
		}
		sort.Strings(pids)

		// "Multiple instances" means several PIDs alive at the *same* sample,
		// which for a process meant to be a singleton is itself a fault.
		// Several PIDs merely seen over the window is just a restart, so
		// counting distinct PIDs would report every restart as a duplicate.
		if len(pids) > 1 {
			seen := map[int64]string{}
			concurrent := false
			for _, p := range a.pts {
				key := p.ts.Unix()
				if prev, ok := seen[key]; ok && prev != p.pid {
					concurrent = true
					break
				}
				seen[key] = p.pid
			}
			if concurrent {
				dups = append(dups, proc)
			}
		}

		out = append(out, MemSuspect{
			Name: proc, Counter: counters[0], Counters: counters, PIDs: pids,
			StartKB: start, EndKB: end, PeakKB: peak,
			GrowthKB: growth, PctOfDrop: pct, Restarted: restarted,
			PostRestartKB: postKB, ReclaimedKB: reclaimedKB,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].GrowthKB != out[j].GrowthKB {
			return out[i].GrowthKB > out[j].GrowthKB
		}
		return out[i].Name < out[j].Name
	})
	sort.Strings(dups)
	return out, dups
}

// kernelSuspects looks for kernel-side growth: unreclaimable slab first,
// then the individual slab caches that make it up.
func kernelSuspects(byName map[string][]CounterSample, plane string, dropKB float64) []MemSuspect {
	var out []MemSuspect

	add := func(name, label string, toKB float64) {
		pts := byName[name]
		if len(pts) < 2 {
			return
		}
		start, end := pts[0].Value*toKB, pts[len(pts)-1].Value*toKB
		growth := end - start
		if growth <= 0 {
			return
		}
		pct := 0.0
		if dropKB > 0 {
			pct = growth / dropKB * 100
		}
		out = append(out, MemSuspect{
			Name: label, Counter: name, Counters: []string{name},
			StartKB: start, EndKB: end, PeakKB: end,
			GrowthKB: growth, PctOfDrop: pct,
		})
	}

	add(plane+"__memorydetail__sunreclaim", "Unreclaimable slab (SUnreclaim)", 1)
	add(plane+"__memorydetail__slab", "Slab total", 1)

	slabPrefix := plane + "__slabinfo__"
	for name := range byName {
		if strings.HasPrefix(name, slabPrefix) && strings.HasSuffix(name, "_totalactsize") {
			cache := strings.TrimSuffix(strings.TrimPrefix(name, slabPrefix), "_totalactsize")
			add(name, "slab cache "+cache, 1/bytesPerKB)
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].GrowthKB > out[j].GrowthKB })
	return out
}

const (
	// below this share of the decline explained by user-space growth, a
	// kernel-side leak becomes the more likely explanation
	userspaceExplainsThreshold = 50.0
	// only report suspects that account for a meaningful slice of the drop
	minSuspectPct = 5.0
	maxSuspects   = 12
)

// AnalyzeMemory correlates OOM events, the available-memory trend, per
// process growth and kernel slab growth into a single verdict. plane is
// "mp" (management) or "dp" (dataplane).
func AnalyzeMemory(samples []CounterSample, oom []OOMEvent, plane string) MemoryAnalysis {
	a := MemoryAnalysis{OOMEvents: oom, Suspects: []MemSuspect{}, KernelSuspects: []MemSuspect{}}
	if len(oom) > 0 {
		// OOMs often cascade; the first one in the window is the one worth
		// investigating, the rest are usually consequences
		first := oom[0]
		a.FirstOOM = &first
	}

	byName := bySeries(samples)
	a.Trend = pickAvailTrend(byName, plane)
	dropKB := 0.0
	if a.Trend != nil {
		dropKB = a.Trend.DropKB
	}

	allSuspects, dups := processSuspects(byName, plane, dropKB)
	a.Duplicates = dups

	// how much of the decline user-space growth can account for
	var explained float64
	for _, s := range allSuspects {
		if s.GrowthKB > 0 {
			explained += s.GrowthKB
		}
	}
	if dropKB > 0 {
		a.Explained = explained / dropKB * 100
	}

	for _, s := range allSuspects {
		if len(a.Suspects) >= maxSuspects {
			break
		}
		if dropKB > 0 && s.PctOfDrop < minSuspectPct && !s.Restarted {
			continue
		}
		a.Suspects = append(a.Suspects, s)
	}

	a.KernelSuspects = kernelSuspects(byName, plane, dropKB)
	a.KernelLikely = dropKB > 0 && a.Explained < userspaceExplainsThreshold && len(a.KernelSuspects) > 0

	a.Findings = buildFindings(&a, plane)

	// Every slice must be non-nil: encoding/json turns a nil slice into
	// `null`, and the UI does `.length`/`.map` on these directly. An archive
	// with no OOM events is the normal case, so this is not a corner case.
	if a.OOMEvents == nil {
		a.OOMEvents = []OOMEvent{}
	}
	if a.Suspects == nil {
		a.Suspects = []MemSuspect{}
	}
	if a.KernelSuspects == nil {
		a.KernelSuspects = []MemSuspect{}
	}
	if a.Duplicates == nil {
		a.Duplicates = []string{}
	}
	if a.Findings == nil {
		a.Findings = []Finding{}
	}
	return a
}

// fmtGB renders a kB figure as GB for prose in findings.
func fmtGB(kb float64) string {
	return trimZeros(kb/1024/1024) + " GB"
}

// trimZeros formats to at most 2 decimals without trailing zero noise.
func trimZeros(v float64) string {
	s := strconv.FormatFloat(v, 'f', 2, 64)
	s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
	if s == "" || s == "-" || s == "-0" {
		return "0"
	}
	return s
}

func buildFindings(a *MemoryAnalysis, plane string) []Finding {
	var f []Finding

	if len(a.OOMEvents) > 0 {
		ev := a.FirstOOM
		detail := "The OOM killer ran " + strconv.Itoa(len(a.OOMEvents)) + " time(s). " +
			"First event"
		if ev != nil {
			if !ev.Ts.IsZero() {
				detail += " at " + ev.Ts.Format("2006-01-02 15:04:05")
			}
			if ev.InvokedBy != "" {
				detail += "; allocation requested by " + ev.InvokedBy
			}
			if ev.Killed != "" {
				detail += "; kernel killed " + ev.Killed
				if ev.KilledPid != "" {
					detail += " (pid " + ev.KilledPid + ")"
				}
			}
			detail += ". Neither of those processes is necessarily the cause — " +
				"the requester merely asked for memory next, and the victim was chosen by OOM score."
		}
		f = append(f, Finding{Severity: "critical", Title: "OOM killer invoked", Detail: detail})
		if len(a.OOMEvents) > 1 {
			f = append(f, Finding{
				Severity: "info", Title: "Multiple OOMs in the window",
				Detail: "OOMs frequently cascade once memory is exhausted; the first event is the one to investigate. " +
					"The later ones are usually consequences.",
			})
		}
	}

	if a.Trend == nil {
		f = append(f, Finding{
			Severity: "info", Title: "No available-memory trend",
			Detail: "None of " + plane + "__memorydetail__memavailable, " + plane +
				"__memory__mem_available or " + plane + "__top__avail_mem had enough samples in this archive, " +
				"so memory growth could not be trended.",
		})
		return f
	}

	t := a.Trend
	if t.DropKB > 0 {
		sev := "medium"
		if t.DropKB > 2*1024*1024 { // > 2 GB
			sev = "high"
		}
		f = append(f, Finding{
			Severity: sev, Title: "Available memory declined by " + fmtGB(t.DropKB),
			Detail: "From " + fmtGB(t.StartKB) + " to " + fmtGB(t.EndKB) + " over " +
				trimZeros(t.SpanDays) + " day(s), low point " + fmtGB(t.MinKB) +
				". Read from " + t.Counter + " (available memory, not free memory).",
		})
	} else {
		f = append(f, Finding{
			Severity: "info", Title: "Available memory stable",
			Detail: "No net decline over the window (" + fmtGB(t.StartKB) + " to " + fmtGB(t.EndKB) +
				"), read from " + t.Counter + ".",
		})
	}

	if len(a.Suspects) > 0 {
		top := a.Suspects[0]
		f = append(f, Finding{
			Severity: "high", Title: "Largest user-space growth: " + top.Name,
			Detail: top.Name + " grew " + fmtGB(top.GrowthKB) + " (" + trimZeros(top.PctOfDrop) +
				"% of the decline). User-space growth explains " + trimZeros(a.Explained) +
				"% of the drop in total. High absolute usage alone is not suspicious — this is ranked by growth " +
				"that tracks the available-memory decline.",
		})
	}

	if a.KernelLikely {
		detail := "User-space processes account for only " + trimZeros(a.Explained) +
			"% of the decline, so the growth is likely kernel-side rather than a leaking process."
		if len(a.KernelSuspects) > 0 {
			k := a.KernelSuspects[0]
			detail += " Largest kernel growth: " + k.Name + " +" + fmtGB(k.GrowthKB) + " (" + k.Counter + ")."
		}
		f = append(f, Finding{Severity: "high", Title: "Kernel memory growth suspected", Detail: detail})
	}

	for _, d := range a.Duplicates {
		f = append(f, Finding{
			Severity: "medium", Title: "Multiple instances of " + d,
			Detail: d + " appears under more than one PID in the process table. For processes that should be " +
				"a single instance this is itself a fault worth chasing; for legitimately multi-instance " +
				"processes it is expected.",
		})
	}

	for _, s := range a.Suspects {
		if s.Restarted {
			f = append(f, Finding{
				Severity: "medium", Title: s.Name + " appears to have restarted",
				Detail: "Its resident memory fell sharply mid-window. A large drop after a restart is itself " +
					"an indication that the process had been leaking.",
			})
		}
	}

	sort.SliceStable(f, func(i, j int) bool {
		return findingRank(f[i].Severity) > findingRank(f[j].Severity)
	})
	return f
}

func findingRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}

/* ---------- config-size risk (low-memory VMs) ---------- */

// mergespRe matches the merged running config inside the archive; its size
// is the "config size" that can push configd into an OOM on small VMs.
var mergespRe = regexp.MustCompile(`(?i)(^|/)mergesp\.xml$`)

const (
	mergespWarnBytes = 26 << 20        // 26 MB
	lowMemVMTotalKB  = 9 * 1024 * 1024 // < 9 GB total RAM
)

// ConfigSizeRisk flags the low-memory-VM combination that drives configd
// memory spikes: a large merged config on a box with under 9 GB of RAM.
// Report generation and short content-update intervals compound it, but
// those live in the config rather than the counters, so they're named in
// the advice instead of tested here.
func ConfigSizeRisk(entries []ArchiveEntry, samples []CounterSample, plane string) []Finding {
	var mergespSize int64 = -1
	for _, e := range entries {
		if mergespRe.MatchString(e.Path) {
			if e.Size > mergespSize {
				mergespSize = e.Size
			}
		}
	}

	var totalKB float64
	byName := bySeries(samples)
	for _, n := range []string{plane + "__memorydetail__memtotal", plane + "__memory__mem_total"} {
		if pts := byName[n]; len(pts) > 0 {
			totalKB = pts[0].Value
			break
		}
	}
	if totalKB == 0 {
		if pts := byName[plane+"__top__mem_total"]; len(pts) > 0 {
			totalKB = pts[0].Value * kbPerMiB
		}
	}

	f := []Finding{} // never nil: marshalled straight into the UI
	lowMem := totalKB > 0 && totalKB < lowMemVMTotalKB

	if mergespSize >= 0 {
		sev := "info"
		detail := "mergesp.xml is " + trimZeros(float64(mergespSize)/1024/1024) + " MB."
		if mergespSize > mergespWarnBytes {
			sev = "medium"
			detail += " Above the 26 MB mark where configd memory use becomes a concern."
			if lowMem {
				sev = "high"
				detail += " This device has " + fmtGB(totalKB) +
					" of RAM (under 9 GB), the configuration most prone to configd spiking into an OOM." +
					" Report generation and short content-update intervals make it worse."
			}
		}
		f = append(f, Finding{Severity: sev, Title: "Config size", Detail: detail})
	} else if lowMem {
		f = append(f, Finding{
			Severity: "info", Title: "Low-memory device",
			Detail: "Total RAM is " + fmtGB(totalKB) + " (under 9 GB). Watch config size (mergesp.xml over 26 MB), " +
				"report generation and content-update frequency, which together can spike configd. " +
				"mergesp.xml was not present in this archive.",
		})
	}
	return f
}
