package parser

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

const sampleDpMonitor = `2026-06-09 11:27:40.087 -0700  --- panio
:Global counters:
:Elapsed time since last sampling: 424.219 seconds
:name                                 value     rate
:-------------------------------------------------------------------------------
:pkt_recv                           6452370      103
:pkt_recv_retry                       32864        0
:Total counters shown: 2
:
:Global counters:
:Elapsed time since last sampling: 10.001 seconds
:name                                 value     rate
:-------------------------------------------------------------------------------
:pkt_recv                                99        9
:Total counters shown: 1
:
:Resource monitoring statistics (per minute):
:CPU load (%) during last 15 minutes:
:core    0       1       2       3
:     avg max avg max avg max avg max
:       0   0   1   1   1   1   0   0
:       0   0   1   2   1   2   0   0
:Cache-Type             MAX-Entries Cur-Entries Max.Alloc Cur.SZ(B) Insert-Failure Mem-Pool-Type
:ssl_server_cert        16384       176         176       14080     0              l7_misc
:ssl_cert_cn            1024        12          12        960       0              l7_misc
:		Per pan-task counter statistics
:Counter Name                                      1                    2                Total
:-----------------------------------------------------------------------------------
:pkt_recv                                    1657994              4663514              6321508
:mem_memseg_allocated                              1                    0                    1
2026-06-09 11:29:44.537 -0700  --- cpu
Last 180 seconds
Avg (%)    Max (%)
17         24
Load Avg:
1.44 1.67 1.58 1/1449 498878
2026-06-09 11:30:00.000 -0700  --- ifconfig
 1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/24 scope host lo
    RX:  bytes packets errors dropped  missed   mcast
    2572190192 9666206      0       1       0       0
    TX:  bytes packets errors dropped carrier collsns
    2572190192 9666206      0       0       2       3
2026-06-09 11:31:00.000 -0700  --- memory
Last 180 seconds
Type       Free (kB)     min (kB)      Total (kB)    MemAvailable (kB)
Mem        429592        424240        8111956       1881560
Swap       3096060       3095804       4095996
2026-06-09 12:27:40.973 -0700  --- logrcvr_statistics
Logreceiver-Statistics
 Log incoming rate:             8/sec
 Log written rate:              2/sec
 Traffic logs written:          22176
 Total (MB):                416
 Log incoming rate:             999/sec
2026-06-09 12:28:00.000 -0700  --- netstat_detail
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:28778           0.0.0.0:*               LISTEN      3355/gp_broker
tcp        5      2 0.0.0.0:28776           0.0.0.0:*               LISTEN      3367/sslmgr
tcp6       3      0 :::28769                :::*                    LISTEN      3355/gp_broker
tcp        0      0 127.0.0.1:42660         127.0.0.1:28888         ESTABLISHED -
`

func collectFromString(t *testing.T, content, plane string) map[string][]CounterSample {
	t.Helper()
	tgz := buildMultiTgz(t, map[string]string{"var/log/pan/" + plane + "-monitor.log": content})
	samples, err := CollectAllCounters(bytes.NewReader(tgz))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]CounterSample{}
	for _, s := range samples {
		got[s.Name] = append(got[s.Name], s)
	}
	return got
}

func TestGlobalCountersKeepLongElapsedOnly(t *testing.T) {
	got := collectFromString(t, sampleDpMonitor, "dp")

	ss, ok := got["dp__gc__pkt_recv"]
	if !ok {
		t.Fatal("dp__gc__pkt_recv missing")
	}
	// only the 424s sample; the 10s delta (value 99) must be dropped
	if len(ss) != 1 || ss[0].Value != 6452370 {
		t.Fatalf("dp__gc__pkt_recv = %+v, want single sample 6452370", ss)
	}
	if got["dp__gc__pkt_recv_retry"][0].Value != 32864 {
		t.Fatalf("pkt_recv_retry wrong: %+v", got["dp__gc__pkt_recv_retry"])
	}
}

func TestCpu15mPerMinuteRows(t *testing.T) {
	got := collectFromString(t, sampleDpMonitor, "dp")

	avg1 := got["dp__cpu__01_avg"]
	max1 := got["dp__cpu__01_max"]
	if len(avg1) != 2 || len(max1) != 2 {
		t.Fatalf("core1: got %d avg / %d max samples, want 2/2", len(avg1), len(max1))
	}
	// first row = block ts, second row = one minute earlier
	blockTs, _ := time.Parse("2006-01-02 15:04:05", "2026-06-09 11:27:40")
	// store order follows file order; sample[0] is row 0
	if !avg1[0].Ts.Equal(blockTs) || !avg1[1].Ts.Equal(blockTs.Add(-time.Minute)) {
		t.Fatalf("row timestamps wrong: %v, %v", avg1[0].Ts, avg1[1].Ts)
	}
	if avg1[1].Value != 1 || max1[1].Value != 2 {
		t.Fatalf("core1 row2 = avg %v max %v, want 1/2", avg1[1].Value, max1[1].Value)
	}
	if _, ok := got["dp__cpu__00_avg"]; !ok {
		t.Fatal("zero-padded core name dp__cpu__00_avg missing")
	}
}

func TestCacheTypeTable(t *testing.T) {
	got := collectFromString(t, sampleDpMonitor, "dp")

	want := map[string]float64{
		"dp__ct__ssl_server_cert_max_entries":    16384,
		"dp__ct__ssl_server_cert_cur_entries":    176,
		"dp__ct__ssl_server_cert_max_alloc":      176,
		"dp__ct__ssl_server_cert_cur_sz_b":       14080,
		"dp__ct__ssl_server_cert_insert_failure": 0,
		"dp__ct__ssl_cert_cn_cur_entries":        12,
	}
	for name, v := range want {
		ss, ok := got[name]
		if !ok {
			t.Errorf("missing %s", name)
			continue
		}
		if ss[0].Value != v {
			t.Errorf("%s = %v, want %v", name, ss[0].Value, v)
		}
	}
	for name := range got {
		if name == "dp__ct__ssl_server_cert_l7_misc" {
			t.Error("mem-pool-type must not be tracked")
		}
	}
}

func TestCpuBlock(t *testing.T) {
	got := collectFromString(t, sampleDpMonitor, "dp")

	want := map[string]float64{
		"dp__cpu__last_3m_avg_pct": 17,
		"dp__cpu__last_3m_max_pct": 24,
		"dp__cpu_load_avg__i_1":    1.44,
		"dp__cpu_load_avg__i_5":    1.67,
		"dp__cpu_load_avg__i_15":   1.58,
	}
	for name, v := range want {
		ss, ok := got[name]
		if !ok {
			t.Errorf("missing %s", name)
			continue
		}
		if ss[0].Value != v {
			t.Errorf("%s = %v, want %v", name, ss[0].Value, v)
		}
	}
}

func TestPerTaskCounters(t *testing.T) {
	got := collectFromString(t, sampleDpMonitor, "dp")

	want := map[string]float64{
		"dp__gc01__pkt_recv":             1657994,
		"dp__gc02__pkt_recv":             4663514,
		"dp__gc01__mem_memseg_allocated": 1,
		"dp__gc02__mem_memseg_allocated": 0,
	}
	for name, v := range want {
		ss, ok := got[name]
		if !ok {
			t.Errorf("missing %s", name)
			continue
		}
		if ss[0].Value != v {
			t.Errorf("%s = %v, want %v", name, ss[0].Value, v)
		}
	}
	// the Total column must not become a counter
	for name := range got {
		if name == "dp__gc03__pkt_recv" {
			t.Error("Total column was wrongly mapped")
		}
	}
}

func TestIfconfig(t *testing.T) {
	got := collectFromString(t, sampleDpMonitor, "dp")

	want := map[string]float64{
		"dp__ifconfig__lo_rx_bytes":   2572190192,
		"dp__ifconfig__lo_rx_packets": 9666206,
		"dp__ifconfig__lo_rx_dropped": 1,
		"dp__ifconfig__lo_tx_bytes":   2572190192,
		"dp__ifconfig__lo_tx_carrier": 2,
		"dp__ifconfig__lo_tx_collsns": 3,
		"dp__ifconfig__lo_tx_dropped": 0,
	}
	for name, v := range want {
		ss, ok := got[name]
		if !ok {
			t.Errorf("missing %s", name)
			continue
		}
		if ss[0].Value != v {
			t.Errorf("%s = %v, want %v", name, ss[0].Value, v)
		}
	}
}

func TestMemoryBlock(t *testing.T) {
	got := collectFromString(t, sampleDpMonitor, "dp")

	want := map[string]float64{
		"dp__memory__mem_free":      429592,
		"dp__memory__mem_available": 1881560,
		"dp__memory__mem_total":     8111956,
		"dp__memory__swap_free":     3096060,
		"dp__memory__swap_total":    4095996,
	}
	for name, v := range want {
		ss, ok := got[name]
		if !ok {
			t.Errorf("missing %s", name)
			continue
		}
		if ss[0].Value != v {
			t.Errorf("%s = %v, want %v", name, ss[0].Value, v)
		}
	}
}

func TestLogrcvrStatistics(t *testing.T) {
	got := collectFromString(t, sampleDpMonitor, "dp")

	if v := got["dp__logreceiver_statistics__log_incoming_rate"]; len(v) != 1 || v[0].Value != 8 {
		t.Fatalf("log_incoming_rate = %+v, want single sample 8 (lines after Total must be ignored)", v)
	}
	if v := got["dp__logreceiver_statistics__log_written_rate"]; len(v) != 1 || v[0].Value != 2 {
		t.Fatalf("log_written_rate = %+v", v)
	}
	if v := got["dp__logreceiver_statistics__total_mb"]; len(v) != 1 || v[0].Value != 416 {
		t.Fatalf("total_mb = %+v", v)
	}
	if _, ok := got["dp__logreceiver_statistics__traffic_logs_written"]; ok {
		t.Fatal("traffic_logs_written must not be captured")
	}
}

func TestNetstatDetail(t *testing.T) {
	got := collectFromString(t, sampleDpMonitor, "dp")

	want := map[string]float64{
		"dp__netstat_detail__tcp_gp_broker_recv_q":  0,
		"dp__netstat_detail__tcp_sslmgr_recv_q":     5,
		"dp__netstat_detail__tcp_sslmgr_send_q":     2,
		"dp__netstat_detail__tcp6_gp_broker_recv_q": 3,
	}
	for name, v := range want {
		ss, ok := got[name]
		if !ok {
			t.Errorf("missing %s", name)
			continue
		}
		if ss[0].Value != v {
			t.Errorf("%s = %v, want %v", name, ss[0].Value, v)
		}
	}
	// the ESTABLISHED row without a program must be skipped (no counter named after "-")
	for name := range got {
		if strings.Contains(name, "netstat_detail") && strings.Contains(name, "__tcp__") {
			t.Errorf("unexpected counter from program-less row: %s", name)
		}
	}
}

func TestMpPrefix(t *testing.T) {
	got := collectFromString(t, sampleDpMonitor, "mp")
	if _, ok := got["mp__cpu_load_avg__i_1"]; !ok {
		t.Fatal("mp prefix not applied")
	}
}

const sampleDpExtra = `2026-06-09 13:00:00.000 -0700  --- netstat_stats
Ip:
    Forwarding: 2
    11080749 total packets received
    0 forwarded
    0 incoming packets discarded
    11064314 incoming packets delivered
    10973710 requests sent out
Tcp:
    203928 active connection openings
    175430 passive connection openings
TcpExt:
    173188 TCP sockets finished time wait in fast timer
    2473 time wait sockets recycled by time stamp
IpExt:
    InECT0Pkts: 506
2026-06-09 13:08:37.779 -0700  --- processes
Total num processes: 0
Name                   PID      CPU%  FDs Open   Virt Mem     Res+Swap     State      Res+Swap-Lazy
envoy                  8641     6     40         2281204      20040        S 231028
2026-06-09 14:23:45.233 -0700  --- filesystem
Mount            Used (%)   Used (kB)
/                51         5875792
/dev             0          0
/dev/shm         53         2522168
2026-06-09 15:00:00.000 -0700  --- panio
:Mem-Pool-Type    MaxSz(KB) Threshold MinSz(KB)  CurSz(B) Max.Alloc   Cur.Alloc Total-Alloc Fail-Thresh  Fail-Nomem Local-Reuse(cache)
:ctd_dlp_buf           1016     52480       508         0         0         0           0           0           0           0(0)
:proxy                25600         0         0   3053760   3114864     81673       95234           0           0           0(0)
:clientless_vpn        3399         0         0         0         0         0           0           0           0
:Software Pools
:Id   Name                      Length         Free/Total      HighWm/Populated  Used/Total  DataRange                  CacheSz
:[ 0] memseg_common             (2097152):       86/88              2/88            1/1      0xd001400000-0xd00c400000
:[ 1] Shared Pool 24            (     24):   443976/444000        784/87376         1/6      0xd00c800080-0xd00ca00000* 408
:Pow Atomic Memory Pools
:[ 0] Work Queue Entries        :    25166/25206    0xd0146f8d00
:[ 1] Packet Buffers            :    30076/31141    0x10181f6c0
:User                     Quota     Threshold Min.Alloc Cur.Alloc Max.Alloc Total-Alloc Fail-Thresh Fail-Nomem  Local-Reuse Data(Pool)-SZ
:fptcp_seg                25000     0         0         0         25        3802        0           0           3795        16 (24)
`

func wantValues(t *testing.T, got map[string][]CounterSample, want map[string]float64) {
	t.Helper()
	for name, v := range want {
		ss, ok := got[name]
		if !ok {
			t.Errorf("missing %s", name)
			continue
		}
		if ss[0].Value != v {
			t.Errorf("%s = %v, want %v", name, ss[0].Value, v)
		}
	}
}

func TestNetstatStats(t *testing.T) {
	got := collectFromString(t, sampleDpExtra, "dp")
	wantValues(t, got, map[string]float64{
		"dp__nsstats__ip_forwarding":                 2,
		"dp__nsstats__ip_total_packets_received":     11080749,
		"dp__nsstats__ip_forwarded":                  0,
		"dp__nsstats__ip_incoming_packets_discarded": 0,
		"dp__nsstats__ip_incoming_packets_delivered": 11064314,
		"dp__nsstats__ip_requests_sent_out":          10973710,
		"dp__nsstats__tcp_active_connection_openings":                       203928,
		"dp__nsstats__tcp_passive_connection_openings":                      175430,
		"dp__nsstats__tcpext_tcp_sockets_finished_time_wait_in_fast_timer":  173188,
		"dp__nsstats__tcpext_time_wait_sockets_recycled_by_time_stamp":      2473,
		"dp__nsstats__ipext_inect0pkts":                                     506,
	})
}

func TestProcesses(t *testing.T) {
	got := collectFromString(t, sampleDpExtra, "dp")
	wantValues(t, got, map[string]float64{
		"dp__processes__envoy_8641_cpu":           6,
		"dp__processes__envoy_8641_fds_open":      40,
		"dp__processes__envoy_8641_virt_mem":      2281204,
		"dp__processes__envoy_8641_res_swap":      20040,
		"dp__processes__envoy_8641_res_swap_lazy": 231028,
	})
	for name := range got {
		if name == "dp__processes__name_pid_cpu" {
			t.Error("header row was parsed as a process")
		}
	}
}

func TestFilesystem(t *testing.T) {
	got := collectFromString(t, sampleDpExtra, "dp")
	wantValues(t, got, map[string]float64{
		"dp__filesystem__root_pct":         51,
		"dp__filesystem__root_used_kb":     5875792,
		"dp__filesystem__dev_pct":          0,
		"dp__filesystem__dev_used_kb":      0,
		"dp__filesystem__dev_shm_pct":      53,
		"dp__filesystem__dev_shm_used_kb":  2522168,
	})
}

func TestMemPool(t *testing.T) {
	got := collectFromString(t, sampleDpExtra, "dp")
	wantValues(t, got, map[string]float64{
		"dp__pool__mempool__ctd_dlp_buf_max_sz_b":   1016,
		"dp__pool__mempool__ctd_dlp_buf_threshold":  52480,
		"dp__pool__mempool__ctd_dlp_buf_min_sz_b":   508,
		"dp__pool__mempool__proxy_cur_sz_b":         3053760,
		"dp__pool__mempool__proxy_max_alloc":        3114864,
		"dp__pool__mempool__proxy_cur_alloc":        81673,
		"dp__pool__mempool__proxy_total_alloc":      95234,
		"dp__pool__mempool__proxy_local_reuse":      0,
		"dp__pool__mempool__clientless_vpn_max_sz_b": 3399,
	})
	// short row: clientless_vpn has no Local-Reuse column
	if _, ok := got["dp__pool__mempool__clientless_vpn_local_reuse"]; ok {
		t.Error("short row should not emit a missing trailing column")
	}
}

func TestSoftPool(t *testing.T) {
	got := collectFromString(t, sampleDpExtra, "dp")
	wantValues(t, got, map[string]float64{
		"dp__pool__softpool__memseg_common":  86,
		"dp__pool__softpool__shared_pool_24": 443976,
	})
	if v := got["dp__pool__softpool__memseg_common_pct"]; len(v) != 1 || v[0].Value != 86.0/88.0 {
		t.Fatalf("memseg_common_pct = %+v, want %v", v, 86.0/88.0)
	}
}

func TestPowPool(t *testing.T) {
	got := collectFromString(t, sampleDpExtra, "dp")
	wantValues(t, got, map[string]float64{
		"dp__pool__powpool__work_queue_entries": 25166,
		"dp__pool__powpool__packet_buffers":     30076,
	})
	if v := got["dp__pool__powpool__packet_buffers_pct"]; len(v) != 1 || v[0].Value != 30076.0/31141.0 {
		t.Fatalf("packet_buffers_pct = %+v, want %v", v, 30076.0/31141.0)
	}
}

func TestSharedPool(t *testing.T) {
	got := collectFromString(t, sampleDpExtra, "dp")
	wantValues(t, got, map[string]float64{
		"dp__pool__sharedpool__fptcp_seg_quota":       25000,
		"dp__pool__sharedpool__fptcp_seg_threshold":   0,
		"dp__pool__sharedpool__fptcp_seg_max_alloc":   25,
		"dp__pool__sharedpool__fptcp_seg_total_alloc": 3802,
		"dp__pool__sharedpool__fptcp_seg_local_reuse": 3795,
	})
	// Data(Pool)-SZ must not be emitted
	if _, ok := got["dp__pool__sharedpool__fptcp_seg_data_pool_sz"]; ok {
		t.Error("Data(Pool)-SZ column should be excluded")
	}
}
