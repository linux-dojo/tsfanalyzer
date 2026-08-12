// Package parser: counter_anomalies.go derives anomalies from the counter
// time series rather than from log text, so threshold breaches (CPU load,
// iowait, per-process CPU) and slow trends (growing socket queues) show up
// in the same Anomalies list as OOM-killer and OSPF/LACP log events.
//
// Each breaching sample becomes one occurrence, so the Anomalies graph
// plots exactly when a threshold was crossed and clicking a point shows the
// value that crossed it.
package parser

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

/* ---------- thresholds ---------- */

const (
	loadWarnLevel = 2.5 // 1/5/15-minute load average
	loadHighLevel = 5.0

	iowaitWarnLevel = 2.0 // %
	iowaitCritLevel = 5.0

	cpuPctLevel     = 80.0 // plane CPU avg/max %
	procCPUPctLevel = 85.0 // single process CPU %

	// a socket queue is normally drained to ~0; sustained growth means a
	// consumer is not keeping up
	queueMinSamples = 5
	queueHighBytes  = 100000
)

/* ---------- counter name patterns ---------- */

var (
	loadAvgAnomRe = regexp.MustCompile(`^(mp|dp)__cpu_load_avg__i_(1|5|15)$`)
	iowaitAnomRe  = regexp.MustCompile(`^(mp|dp)__top__cpu__iowait_pct$`)
	// plane CPU: the "Last 180 seconds" avg/max, and the per-core 15-minute table
	cpuBlockAnomRe = regexp.MustCompile(`^(mp|dp)__cpu__last_3m_(avg|max)_pct$`)
	cpuCoreAnomRe  = regexp.MustCompile(`^(mp|dp)__cpu__(\d+)_(avg|max)$`)
	// per-process CPU from the processes table and from top
	procCPUAnomRe    = regexp.MustCompile(`^(mp|dp)__processes__(.+)_(\d+)_cpu$`)
	topProcCPUAnomRe = regexp.MustCompile(`^(mp|dp)__topprocess__(.+)_(\d+)__cpu$`)
	// socket queues per proto+program
	queueAnomRe = regexp.MustCompile(`^(mp|dp)__netstat_detail__(.+)_(recv_q|send_q)$`)
)

// band describes one severity step of a threshold rule. Bands are checked
// highest-first and a sample is attributed to only one band, so a load of 6
// is reported as "above 5" and not also as "above 2.5".
type band struct {
	level    float64
	severity string
	suffix   string // e.g. "above 5"
}

var loadBands = []band{
	{loadHighLevel, "critical", "above 5"},
	{loadWarnLevel, "critical", "above 2.5"},
}

var iowaitBands = []band{
	{iowaitCritLevel, "critical", "above 5"},
	{iowaitWarnLevel, "high", "above 2"},
}

var cpuBands = []band{
	{cpuPctLevel, "critical", "above 80%"},
}

var procCPUBands = []band{
	{procCPUPctLevel, "high", "above 85%"},
}

// anomAccum collects occurrences per label while preserving first-seen order.
type anomAccum struct {
	groups map[string]*AnomalyGroup
	order  []string
}

func newAnomAccum() *anomAccum {
	return &anomAccum{groups: map[string]*AnomalyGroup{}}
}

func (a *anomAccum) add(label, severity, subtype string, ts time.Time, desc string) {
	g, ok := a.groups[label]
	if !ok {
		g = &AnomalyGroup{Label: label, Severity: severity, Subtype: subtype, Sample: desc}
		a.groups[label] = g
		a.order = append(a.order, label)
	}
	if severityRank(severity) > severityRank(g.Severity) {
		g.Severity = severity
	}
	g.Count++
	g.Occurrences = append(g.Occurrences, AnomalyOccurrence{Ts: ts, Description: desc})
}

func (a *anomAccum) result() []AnomalyGroup {
	out := make([]AnomalyGroup, 0, len(a.order))
	for _, l := range a.order {
		g := a.groups[l]
		sort.Slice(g.Occurrences, func(i, j int) bool { return g.Occurrences[i].Ts.Before(g.Occurrences[j].Ts) })
		if g.Occurrences == nil {
			g.Occurrences = []AnomalyOccurrence{}
		}
		out = append(out, *g)
	}
	return out
}

// fmtVal renders a counter value without trailing zero noise.
func fmtVal(v float64) string {
	s := strconv.FormatFloat(v, 'f', 2, 64)
	s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
	if s == "" {
		return "0"
	}
	return s
}

// applyBands attributes each breaching sample to its highest matching band.
func applyBands(a *anomAccum, pts []Point, bands []band, subtype string,
	labelFor func(b band) string, descFor func(b band, p Point) string) {
	for _, p := range pts {
		for _, b := range bands {
			if p.Value > b.level {
				a.add(labelFor(b), b.severity, subtype, p.Ts, descFor(b, p))
				break // highest band only
			}
		}
	}
}

// CounterAnomalies turns threshold breaches and growing socket queues in the
// counter series into AnomalyGroups.
func CounterAnomalies(byName Series) []AnomalyGroup {
	a := newAnomAccum()

	for name, pts := range byName {
		switch {
		case loadAvgAnomRe.MatchString(name):
			m := loadAvgAnomRe.FindStringSubmatch(name)
			plane, window := m[1], m[2]
			applyBands(a, pts, loadBands, "cpu",
				func(b band) string { return plane + " cpu " + window + " min load " + b.suffix },
				func(b band, p Point) string {
					return plane + " " + window + "-minute load average " + fmtVal(p.Value) +
						" (threshold " + fmtVal(b.level) + ") — " + name
				})

		case iowaitAnomRe.MatchString(name):
			m := iowaitAnomRe.FindStringSubmatch(name)
			plane := m[1]
			applyBands(a, pts, iowaitBands, "cpu",
				func(b band) string { return plane + " cpu iowait " + b.suffix },
				func(b band, p Point) string {
					return plane + " iowait " + fmtVal(p.Value) + "% (threshold " + fmtVal(b.level) + "%) — " + name
				})

		case cpuBlockAnomRe.MatchString(name):
			m := cpuBlockAnomRe.FindStringSubmatch(name)
			plane, kind := m[1], m[2]
			applyBands(a, pts, cpuBands, "cpu",
				func(b band) string { return plane + " cpu " + kind + " " + b.suffix },
				func(b band, p Point) string {
					return plane + " CPU " + kind + " " + fmtVal(p.Value) + "% — " + name
				})

		case cpuCoreAnomRe.MatchString(name):
			m := cpuCoreAnomRe.FindStringSubmatch(name)
			plane, core, kind := m[1], m[2], m[3]
			// all cores share one group per plane+kind so a busy box doesn't
			// produce dozens of near-identical entries; the core is named in
			// the occurrence instead
			applyBands(a, pts, cpuBands, "cpu",
				func(b band) string { return plane + " cpu core " + kind + " " + b.suffix },
				func(b band, p Point) string {
					return plane + " core " + core + " " + kind + " " + fmtVal(p.Value) + "% — " + name
				})

		case procCPUAnomRe.MatchString(name), topProcCPUAnomRe.MatchString(name):
			re := procCPUAnomRe
			if !re.MatchString(name) {
				re = topProcCPUAnomRe
			}
			m := re.FindStringSubmatch(name)
			plane, proc, pid := m[1], m[2], m[3]
			applyBands(a, pts, procCPUBands, "process",
				func(b band) string { return plane + " process " + proc + " cpu " + b.suffix },
				func(b band, p Point) string {
					return proc + " (pid " + pid + ") cpu " + fmtVal(p.Value) + "% — " + name
				})

		case queueAnomRe.MatchString(name):
			m := queueAnomRe.FindStringSubmatch(name)
			plane, sock, queue := m[1], m[2], m[3]
			if g := growingQueue(pts); g != nil {
				sev := "medium"
				if g.last >= queueHighBytes {
					sev = "high"
				}
				label := plane + " netstat " + sock + " " + queue + " increasing"
				desc := sock + " " + queue + " grew from " + fmtVal(g.first) + " to " + fmtVal(g.last) +
					" bytes — " + name
				// one occurrence per rising sample so the trend is plottable
				for _, p := range g.rising {
					a.add(label, sev, "netstat", p.Ts, desc)
				}
			}
		}
	}

	return SortAnomalies(a.result())
}

type queueTrend struct {
	first, last float64
	rising      []Point
}

// growingQueue reports a socket queue that trends upward and ends non-empty.
// Comparing the median of the first third against the last third avoids
// firing on a single transient spike, which queues do routinely.
func growingQueue(pts []Point) *queueTrend {
	if len(pts) < queueMinSamples {
		return nil
	}
	third := len(pts) / 3
	if third < 1 {
		third = 1
	}
	firstVals := make([]float64, 0, third)
	for _, p := range pts[:third] {
		firstVals = append(firstVals, p.Value)
	}
	lastVals := make([]float64, 0, third)
	for _, p := range pts[len(pts)-third:] {
		lastVals = append(lastVals, p.Value)
	}
	f, l := median(firstVals), median(lastVals)
	final := pts[len(pts)-1].Value
	if l <= f || final <= 0 {
		return nil
	}
	// keep the samples that are above the starting level: those are the
	// points worth plotting
	var rising []Point
	for _, p := range pts {
		if p.Value > f {
			rising = append(rising, p)
		}
	}
	if len(rising) == 0 {
		return nil
	}
	return &queueTrend{first: f, last: l, rising: rising}
}
