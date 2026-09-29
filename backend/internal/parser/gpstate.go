// Package parser: gpstate.go builds the connection timeline from PanGPS.log's
// own state machine rather than from the event log.
//
// # Why this replaced the event-log model
//
// pan_gp_event.log is a summary. It does not record every connection the agent
// attempts, so an attempt could happen — portal pre-login, auth, the lot — and
// never appear on the timeline at all. A timeline that silently omits attempts
// is worse than no timeline, because the reader concludes nothing happened.
//
// PanGPS.log carries the service's own state machine and every stage boundary,
// so it can be walked exhaustively.
//
// # Where an attempt begins
//
// The obvious rule, "an attempt runs from one `--Set state to Disconnected` to
// the next", does not survive contact with the logs:
//
//   - On one Windows collection `Disconnected` appears *mid-cycle*, right after
//     `Discovering network...` and before `Discovery complete`. Cutting there
//     splits one connection into two.
//   - A macOS collection contains no `Disconnected` state at all — it cycles
//     between `Restoring VPN Connection` and `Connected`.
//
// What is reliable in every collection seen is that a cycle opens with
// `--Set state to Retrieving configuration...` and that each cycle contains at
// most one `----Portal Pre-login starts----`.
//
// So an attempt opens on either of those, and — this is the part that matters —
// a portal pre-login *always* opens one if the current attempt already has a
// pre-login. That makes it structurally impossible for a pre-login to go
// unreported, which was the failure being fixed.
package parser

import (
	"archive/tar"
	"bufio"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
)

// StageDisconnected is the terminal stage: how the attempt ended.
//
// It is deliberately a stage rather than a column of its own, so a cycle that
// connected and then dropped reads as one row with a red tail rather than two
// unrelated rows.
const StageDisconnected GPStage = "disconnected"

// GPStateOrder is the stage sequence for the timeline, in the order the agent
// performs them.
var GPStateOrder = []GPStage{
	StagePortalPrelogin, StagePortalAuth, StagePortalConfig,
	StageDiscovery, StageGatewaySelect, StageGatewayAuth,
	StageTunnel, StageHIP, StageDisconnected,
}

var (
	stSetStateRe = regexp.MustCompile(`--Set state to\s+(.+?)\s*$`)
	stStageRe    = regexp.MustCompile(`----\s*(.+?)\s*starts\s*----`)

	// Teardown, which is what distinguishes a real "Portal Processing" from
	// the one the agent emits on its way down.
	stTeardownRe = regexp.MustCompile(`(?i)` +
		`Logging out gateway, reason is StopThreads|` +
		`Going to wait all threads exit|` +
		`threads are gracefully stopped|` +
		`StopThreads (?:starts|ends)`)

	// Failure reasons, best first: PAN-OS records the stage and message itself
	// when it can.
	stTSLogRe  = regexp.MustCompile(`TSLog: Set error_stage = ([^,]+), error = (.+?)\s*$`)
	stStatusRe = regexp.MustCompile(`portal status is\s+(.+?)\s*$`)
	stReasonRes = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(Auth failed for portal)`),
		regexp.MustCompile(`(?i)(cannot restore last portal config[^.]*)`),
		regexp.MustCompile(`(?i)(matching client config not found|no client configuration)`),
		regexp.MustCompile(`(?i)(tunnel creation failed|failed to create tunnel)`),
		regexp.MustCompile(`(?i)(Unable to verify server cert[^.]*)`),
		regexp.MustCompile(`(?i)(gateway login failed[^.]*)`),
	}

	// A handful of lines worth surfacing under each stage when a row is
	// expanded. Kept short on purpose: the point is orientation, not a second
	// copy of the log.
	stNotableRes = []*regexp.Regexp{
		regexp.MustCompile(`(?i)^(Pre-login\.\.\.,\s*verifyportalcert=\w+)`),
		regexp.MustCompile(`(?i)(CheckServerCert return 0x[0-9a-fA-F]+)`),
		regexp.MustCompile(`(?i)^(Portal's ipv4 address .+)`),
		regexp.MustCompile(`(?i)^(SSO enable status is .+)`),
		regexp.MustCompile(`(?i)^(Connect method is .+)`),
		regexp.MustCompile(`(?i)^(Connected ip for portal .+)`),
		regexp.MustCompile(`(?i)^(Using cached identity)`),
		regexp.MustCompile(`(?i)^(chose prefered gateway .+)`),
		regexp.MustCompile(`(?i)^(Try to create tunnel with gateway .+)`),
		regexp.MustCompile(`(?i)^(tunnel to \S+ (?:is created|connected))`),
		regexp.MustCompile(`(?i)^(tunnel interface got ip .+)`),
		regexp.MustCompile(`(?i)^(HIP Report submitted[^.]*)`),
		regexp.MustCompile(`(?i)^(prelogon status is \d)`),
		regexp.MustCompile(`(?i)^(Reverse lookup returns hostname.*)`),
	}
)

// stateStage maps a "----X starts----" name onto a timeline stage.
func stateStage(name string) GPStage {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "portal pre-login":
		return StagePortalPrelogin
	case "portal login":
		return StagePortalAuth
	case "portal processing":
		return StagePortalConfig
	case "network discover":
		return StageDiscovery
	case "gateway pre-login":
		return StageGatewaySelect
	case "gateway login":
		return StageGatewayAuth
	case "tunnel creation":
		return StageTunnel
	}
	return ""
}

// stateLine is one parsed PanGPS line.
type stateLine struct {
	ts   time.Time
	msg  string
	line int
	path string
}

// ExtractGPStateAttempts walks PanGPS.log and returns one attempt per
// connection cycle.
func ExtractGPStateAttempts(r io.ReadSeeker) ([]GPAttempt, error) {
	tr, err := openTar(r)
	if err != nil {
		return nil, err
	}
	type namedBody struct {
		name  string
		lines []stateLine
	}
	var files []namedBody
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		base := strings.ToLower(baseName(hdr.Name))
		if !strings.HasPrefix(base, "pangps") || !strings.HasSuffix(base, ".log") {
			continue
		}
		sc := bufio.NewScanner(tr)
		sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
		var body []stateLine
		for n := 1; sc.Scan(); n++ {
			raw := strings.TrimRight(sc.Text(), "\r")
			ts, msg, ok := gpTraceParts(raw)
			if !ok {
				continue
			}
			body = append(body, stateLine{ts: ts, msg: strings.TrimSpace(msg), line: n, path: normalizePath(hdr.Name)})
		}
		files = append(files, namedBody{name: base, lines: body})
	}
	// Oldest rotation first, so the walk is chronological.
	sort.SliceStable(files, func(i, j int) bool {
		return rotationIndex(files[i].name) > rotationIndex(files[j].name)
	})

	var all []stateLine
	for _, f := range files {
		all = append(all, f.lines...)
	}
	return attemptsFromState(all), nil
}

// attemptsFromState is the walk itself, separated so tests need no archive.
func attemptsFromState(lines []stateLine) []GPAttempt {
	var out []GPAttempt
	var cur *GPAttempt
	seenStage := map[GPStage]bool{}
	var connected bool
	var lastState string
	reasonRank := reasonNone

	closeAttempt := func(end time.Time) {
		if cur == nil {
			return
		}
		cur.End = end
		finishStateAttempt(cur, connected, lastState)
		out = append(out, *cur)
		cur = nil
		seenStage = map[GPStage]bool{}
		connected = false
		lastState = ""
		reasonRank = reasonNone
	}

	open := func(l stateLine, trigger string) {
		closeAttempt(l.ts)
		cur = &GPAttempt{Start: l.ts, Trigger: trigger}
	}

	for i, l := range lines {
		// --- stage boundaries -------------------------------------------
		if m := stStageRe.FindStringSubmatch(l.msg); m != nil {
			st := stateStage(m[1])

			// "Portal Processing" is emitted on the way down as well as on the
			// way up. A teardown burst within the next few lines means this one
			// is the agent shutting the session, not opening one.
			if st == StagePortalConfig && teardownFollows(lines, i, 25) {
				continue
			}
			// A second pre-login means a new cycle. This is what guarantees no
			// pre-login can be swallowed by an attempt that is already open.
			if st == StagePortalPrelogin && (cur == nil || seenStage[StagePortalPrelogin]) {
				open(l, "portal")
			}
			if cur == nil {
				open(l, "portal")
			}
			if st != "" && !seenStage[st] {
				seenStage[st] = true
				cur.Stages = append(cur.Stages, GPStageResult{
					Stage: st, Status: "reached", At: l.ts, Detail: l.msg,
				})
			}
			continue
		}

		// --- state transitions ------------------------------------------
		if m := stSetStateRe.FindStringSubmatch(l.msg); m != nil {
			state := strings.TrimSuffix(strings.TrimSpace(m[1]), "...")
			lastState = state
			switch {
			case strings.EqualFold(state, "Retrieving configuration"):
				// The reliable start of a cycle.
				if cur == nil || seenStage[StagePortalPrelogin] {
					open(l, "portal")
				}
			case strings.EqualFold(state, "Connected"):
				connected = true
				if cur == nil {
					open(l, "reconnect")
				}
				if !seenStage[StageTunnel] {
					seenStage[StageTunnel] = true
					cur.Stages = append(cur.Stages, GPStageResult{
						Stage: StageTunnel, Status: "ok", At: l.ts, Detail: l.msg,
					})
				}
			}
			if cur != nil {
				cur.States = append(cur.States, GPStateChange{At: l.ts, State: state, Line: l.line, Path: l.path})
			}
			continue
		}

		if cur == nil {
			continue
		}
		cur.Events++

		// --- HIP, reasons and notable lines ------------------------------
		if !seenStage[StageHIP] && strings.Contains(strings.ToLower(l.msg), "hip report submitted") {
			seenStage[StageHIP] = true
			cur.Stages = append(cur.Stages, GPStageResult{
				Stage: StageHIP, Status: "ok", At: l.ts, Detail: l.msg,
			})
		}
		// Best reason wins, not the first.
		//
		// Taking the first was wrong in a way that only shows on real logs: a
		// failing pre-login writes "cannot restore last portal config" and
		// "portal status is Invalid portal" a tenth of a second *before*
		// PAN-OS writes its own verdict —
		//
		//	TSLog: Set error_stage = Portal pre-login, error = The network
		//	connection is unreachable or the portal is unresponsive.
		//
		// so first-wins reported a symptom and discarded the diagnosis.
		if reason, stage, rank := stateFailureReason(l.msg); reason != "" && rank < reasonRank {
			reasonRank = rank
			cur.Reason = reason
			if stage != "" {
				cur.FailStage = stage
			}
		}
		noteStateLine(cur, l)
	}
	if cur != nil {
		closeAttempt(cur.Start)
	}
	return out
}

// teardownFollows reports whether the next few lines are a shutdown burst.
func teardownFollows(lines []stateLine, from, within int) bool {
	for i := from + 1; i < len(lines) && i <= from+within; i++ {
		if stTeardownRe.MatchString(lines[i].msg) {
			return true
		}
	}
	return false
}

// reasonRank orders failure reasons by how much they are worth trusting.
// Lower is better.
const (
	reasonTSLog  = 0 // PAN-OS names the stage and the message itself
	reasonStatus = 1 // "portal status is X"
	reasonOther  = 2 // inferred from a symptom line
	reasonNone   = 3
)

// stateFailureReason extracts why an attempt failed, the stage it names, and
// how far it is worth trusting.
func stateFailureReason(msg string) (string, GPStage, int) {
	// PAN-OS records the stage and message itself when it can, which beats
	// anything inferred.
	if m := stTSLogRe.FindStringSubmatch(msg); m != nil {
		return strings.TrimSpace(m[2]), stateStage(m[1]), reasonTSLog
	}
	if m := stStatusRe.FindStringSubmatch(msg); m != nil {
		status := strings.TrimSuffix(strings.TrimSpace(m[1]), ".")
		if strings.EqualFold(status, "Connected") {
			return "", "", reasonNone
		}
		return "portal status: " + status, StagePortalAuth, reasonStatus
	}
	for _, re := range stReasonRes {
		if m := re.FindStringSubmatch(msg); m != nil {
			return strings.TrimSpace(m[1]), "", reasonOther
		}
	}
	return "", "", reasonNone
}

// noteStateLine keeps a few orienting lines per stage for the expanded row.
func noteStateLine(a *GPAttempt, l stateLine) {
	if len(a.Notes) >= 12 {
		return
	}
	for _, re := range stNotableRes {
		if m := re.FindStringSubmatch(l.msg); m != nil {
			a.Notes = append(a.Notes, GPNote{
				At: l.ts, Text: strings.TrimSpace(m[1]), Line: l.line, Path: l.path,
			})
			return
		}
	}
}

// finishStateAttempt decides the outcome and fills the terminal stage.
func finishStateAttempt(a *GPAttempt, connected bool, lastState string) {
	// Mark every stage before the furthest one reached as ok; the furthest is
	// where it stopped.
	idx := map[GPStage]int{}
	for i, s := range GPStateOrder {
		idx[s] = i
	}
	far := -1
	for _, s := range a.Stages {
		if i, ok := idx[s.Stage]; ok && i > far {
			far = i
			a.Reached = s.Stage
		}
	}
	for i := range a.Stages {
		if j := idx[a.Stages[i].Stage]; j < far && a.Stages[i].Status == "reached" {
			a.Stages[i].Status = "ok"
		}
	}

	dropped := strings.EqualFold(lastState, "Disconnected") ||
		strings.EqualFold(lastState, "Disconnecting")

	switch {
	case connected && dropped:
		// It worked and then went away. Both facts matter, so the row keeps
		// its green run and gains a terminal marker rather than turning red.
		a.Outcome = "connected"
		a.Stages = append(a.Stages, GPStageResult{
			Stage: StageDisconnected, Status: "failed", At: a.End,
			Detail: firstNonEmpty(a.Reason, "session ended"),
		})
	case connected:
		a.Outcome = "connected"
	case dropped || a.Reason != "":
		a.Outcome = "failed"
		a.StopAt = a.Reached
		if a.FailStage != "" {
			a.StopAt = a.FailStage
		}
		a.Stages = append(a.Stages, GPStageResult{
			Stage: StageDisconnected, Status: "failed", At: a.End,
			Detail: firstNonEmpty(a.Reason, "disconnected without connecting"),
		})
		for i := range a.Stages {
			if a.Stages[i].Stage == a.StopAt && a.Stages[i].Status != "ok" {
				a.Stages[i].Status = "failed"
			}
		}
	default:
		a.Outcome = "incomplete"
		a.StopAt = a.Reached
	}
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
