package parser

import (
	"strings"
	"testing"
	"time"
)

// sl turns "hh:mm:ss msg" into a parsed line, so a test reads like the log.
func sl(clock, msg string) stateLine {
	t, _ := time.Parse("15:04:05", clock)
	return stateLine{
		ts:  time.Date(2026, 8, 24, t.Hour(), t.Minute(), t.Second(), 0, time.UTC),
		msg: msg,
	}
}

func stageSet(a GPAttempt) map[GPStage]string {
	out := map[GPStage]string{}
	for _, s := range a.Stages {
		out[s.Stage] = s.Status
	}
	return out
}

// The requirement this whole file exists for: an attempt that reaches portal
// pre-login must appear on the timeline. The previous model read a summary log
// and could omit a whole connection, which is worse than showing nothing —
// the reader concludes it never happened.
func TestEveryPortalPreloginOpensAnAttempt(t *testing.T) {
	lines := []stateLine{
		sl("08:29:37", "--Set state to Retrieving configuration..."),
		sl("08:29:37", "----Portal Pre-login starts----"),
		sl("08:29:38", "----Portal Login starts----"),
		sl("08:29:42", "--Set state to Connected"),
		// second cycle, no Retrieving in front of it
		sl("10:00:42", "----Portal Pre-login starts----"),
		sl("10:00:43", "----Portal Login starts----"),
		sl("10:00:43", "Auth failed for portal"),
		sl("10:00:43", "portal status is User authentication failed."),
		sl("10:00:43", "--Set state to Disconnected"),
	}
	at := attemptsFromState(lines)
	if len(at) != 2 {
		t.Fatalf("got %d attempts, want 2 — the 10:00 pre-login was lost", len(at))
	}
	if got := at[1].Start.Format("15:04:05"); got != "10:00:42" {
		t.Errorf("second attempt starts %s, want 10:00:42", got)
	}
	if at[1].Outcome != "failed" {
		t.Errorf("second attempt outcome = %q, want failed", at[1].Outcome)
	}
	if !strings.Contains(at[1].Reason, "authentication failed") &&
		!strings.Contains(at[1].Reason, "Auth failed") {
		t.Errorf("reason = %q, want the authentication failure", at[1].Reason)
	}
}

// A cycle that connects and later drops is one row with a terminal marker, not
// a success followed by an unexplained gap.
func TestConnectedThenDroppedKeepsBothFacts(t *testing.T) {
	at := attemptsFromState([]stateLine{
		sl("08:29:42", "--Set state to Retrieving configuration..."),
		sl("08:29:42", "----Portal Pre-login starts----"),
		sl("08:29:43", "----Tunnel Creation starts----"),
		sl("08:29:44", "--Set state to Connected"),
		sl("08:29:46", "--Set state to Disconnected"),
	})
	if len(at) != 1 {
		t.Fatalf("got %d attempts, want 1", len(at))
	}
	if at[0].Outcome != "connected" {
		t.Errorf("outcome = %q; it did connect, and the drop is the tail", at[0].Outcome)
	}
	if st := stageSet(at[0]); st[StageDisconnected] != "failed" {
		t.Errorf("no terminal disconnected stage: %v", st)
	}
}

// "Portal Processing" is emitted on the way down as well as on the way up. The
// teardown burst that follows is what tells them apart; without that check a
// shutdown registers as a fresh config stage.
func TestTeardownPortalProcessingIsIgnored(t *testing.T) {
	at := attemptsFromState([]stateLine{
		sl("08:17:38", "--Set state to Retrieving configuration..."),
		sl("08:17:40", "----Portal Pre-login starts----"),
		sl("08:17:59", "----Portal Processing starts----"),
		sl("08:17:59", "There are 5 threads running..."),
		sl("08:17:59", "Logging out gateway, reason is StopThreads"),
		sl("08:17:59", "Going to wait all threads exit..."),
	})
	if len(at) != 1 {
		t.Fatalf("got %d attempts, want 1", len(at))
	}
	if _, ok := stageSet(at[0])[StagePortalConfig]; ok {
		t.Error("a teardown Portal Processing should not light the config stage")
	}
}

// A real Portal Processing — one not followed by teardown — must still count.
func TestGenuinePortalProcessingCounts(t *testing.T) {
	at := attemptsFromState([]stateLine{
		sl("18:37:06", "----Portal Processing starts----"),
		sl("18:37:06", "--Set state to Retrieving configuration..."),
		sl("18:37:07", "----Portal Pre-login starts----"),
		sl("18:37:21", "--Set state to Connected"),
	})
	if len(at) == 0 {
		t.Fatal("no attempt")
	}
	if _, ok := stageSet(at[0])[StagePortalConfig]; !ok {
		t.Error("a genuine Portal Processing should light the config stage")
	}
}

// "Disconnected" appears mid-cycle on some Windows collections, between
// Discovering network and Discovery complete. Treating every Disconnected as a
// cycle boundary would split one connection into two.
func TestMidCycleDisconnectedDoesNotSplitTheAttempt(t *testing.T) {
	at := attemptsFromState([]stateLine{
		sl("02:47:45", "--Set state to Retrieving configuration..."),
		sl("02:47:45", "----Portal Pre-login starts----"),
		sl("02:47:45", "----Portal Login starts----"),
		sl("02:47:46", "----Network Discover starts----"),
		sl("02:47:46", "--Set state to Discovering network..."),
		sl("02:47:46", "--Set state to Disconnected"),
		sl("02:47:46", "--Set state to Discovery complete"),
	})
	if len(at) != 1 {
		t.Fatalf("got %d attempts, want 1 — a mid-cycle Disconnected split it", len(at))
	}
}

// PAN-OS names the failing stage itself when it can, which beats inference.
func TestTSLogReasonWins(t *testing.T) {
	reason, stage, rank := stateFailureReason(
		"TSLog: Set error_stage = Portal pre-login, error = The network connection is unreachable or the portal is unresponsive.")
	if rank != reasonTSLog {
		t.Errorf("rank = %d, want the most trusted", rank)
	}
	if !strings.Contains(reason, "unreachable") {
		t.Errorf("reason = %q", reason)
	}
	if stage != StagePortalPrelogin {
		t.Errorf("stage = %q, want portal pre-login", stage)
	}
	// "Connected" is a status, not a failure.
	if r, _, _ := stateFailureReason("portal status is Connected."); r != "" {
		t.Errorf("a healthy status must not read as a failure: %q", r)
	}
}

// The stage order drives the timeline columns; the terminal stage has to be in
// it or the header and the bars fall out of step.
func TestStateOrderIncludesTerminalStage(t *testing.T) {
	last := GPStateOrder[len(GPStateOrder)-1]
	if last != StageDisconnected {
		t.Errorf("last stage = %q, want disconnected", last)
	}
	if len(GPStateOrder) != 9 {
		t.Errorf("stage count = %d; the grid columns are derived from this", len(GPStateOrder))
	}
}

// The diagnosis must beat the symptom even though the symptom is logged first.
//
// A failing pre-login writes "cannot restore last portal config" and "portal
// status is Invalid portal" a tenth of a second before PAN-OS writes its own
// verdict. Taking the first reason seen reported the symptom and threw the
// diagnosis away — which is what the real macOS trace does.
func TestBestReasonWinsNotTheFirst(t *testing.T) {
	at := attemptsFromState([]stateLine{
		sl("08:17:38", "--Set state to Retrieving configuration..."),
		sl("08:17:40", "----Portal Pre-login starts----"),
		sl("08:17:45", "cannot restore last portal config from file /Users/x/PanPortalCfg.dat."),
		sl("08:17:45", "portal status is Invalid portal."),
		sl("08:17:45", "TSLog: Set error_stage = Portal pre-login, error = The network connection is unreachable or the portal is unresponsive."),
		sl("08:17:45", "--Set state to Disconnected"),
	})
	if len(at) != 1 {
		t.Fatalf("got %d attempts, want 1", len(at))
	}
	if !strings.Contains(at[0].Reason, "unreachable") {
		t.Errorf("reason = %q, want PAN-OS's own verdict, not the earlier symptom", at[0].Reason)
	}
	if at[0].FailStage != StagePortalPrelogin {
		t.Errorf("fail stage = %q, want portal pre-login", at[0].FailStage)
	}
}

// The full macOS trace: a failed cycle followed by a successful one, with a
// teardown "Portal Processing" between them that must not register.
func TestMacTraceTwoCycles(t *testing.T) {
	at := attemptsFromState([]stateLine{
		sl("08:17:38", "--Set state to Retrieving configuration..."),
		sl("08:17:40", "----Portal Pre-login starts----"),
		sl("08:17:45", "TSLog: Set error_stage = Portal pre-login, error = The network connection is unreachable or the portal is unresponsive."),
		sl("08:17:45", "--Set state to Disconnected"),
		sl("08:17:59", "----Portal Processing starts----"),
		sl("08:17:59", "Logging out gateway, reason is StopThreads"),
		sl("08:17:59", "--Set state to Retrieving configuration..."),
		sl("08:17:59", "----Portal Pre-login starts----"),
		sl("08:18:01", "----Portal Login starts----"),
		sl("08:18:11", "----Network Discover starts----"),
		sl("08:18:15", "----Gateway Pre-login starts----"),
		sl("08:18:15", "----Gateway Login starts----"),
		sl("08:18:16", "----Tunnel Creation starts----"),
		sl("08:18:17", "--Set state to Connected"),
	})
	if len(at) != 2 {
		t.Fatalf("got %d attempts, want 2", len(at))
	}
	if at[0].Outcome != "failed" || at[1].Outcome != "connected" {
		t.Errorf("outcomes = %q, %q; want failed then connected", at[0].Outcome, at[1].Outcome)
	}
	// the failed cycle lit only pre-login, plus the terminal marker
	first := stageSet(at[0])
	if _, ok := first[StagePortalAuth]; ok {
		t.Error("the failed cycle never reached portal login")
	}
	if first[StageDisconnected] != "failed" {
		t.Error("the failed cycle needs its terminal marker")
	}
	// the successful cycle lit the whole run and has no terminal marker
	second := stageSet(at[1])
	for _, want := range []GPStage{
		StagePortalPrelogin, StagePortalAuth, StageDiscovery,
		StageGatewaySelect, StageGatewayAuth, StageTunnel,
	} {
		if _, ok := second[want]; !ok {
			t.Errorf("successful cycle missing stage %q", want)
		}
	}
	if _, ok := second[StageDisconnected]; ok {
		t.Error("a cycle that connected and stayed up has no terminal marker")
	}
	if _, ok := second[StagePortalConfig]; ok {
		t.Error("the teardown Portal Processing must not light the config stage")
	}
}
