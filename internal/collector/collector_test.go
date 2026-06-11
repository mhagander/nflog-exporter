package collector

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mhagander/nflog_exporter/internal/packet"
)

func TestParseLabels(t *testing.T) {
	got, err := ParseLabels("dst_port,proto,group")
	if err != nil {
		t.Fatalf("ParseLabels: %v", err)
	}
	// Must come back in canonical order regardless of input order.
	want := []string{"group", "proto", "dst_port"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got %v, want %v", got, want)
	}

	if _, err := ParseLabels("group,nope"); err == nil {
		t.Errorf("expected error for unknown label")
	}
	if _, err := ParseLabels(""); err == nil {
		t.Errorf("expected error for empty labels")
	}
	// Duplicates collapse.
	got, _ = ParseLabels("proto,proto")
	if len(got) != 1 {
		t.Errorf("duplicate not collapsed: %v", got)
	}
}

func TestObserveExposesSelectedLabels(t *testing.T) {
	reg := prometheus.NewRegistry()
	c, err := New(reg, []string{LabelProto, LabelDstPort}, "", "test", "go-test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	tcp1234 := packet.Info{Proto: "tcp", SrcPort: 50000, DstPort: 1234, HasPorts: true, WireLen: 100}
	c.Observe(5, "in-1234", 0, 0, tcp1234) // 100 bytes
	c.Observe(5, "in-1234", 0, 0, tcp1234) // +100 -> 200 bytes, 2 packets

	icmp := packet.Info{Proto: "icmp", WireLen: 84} // no ports
	c.Observe(5, "ping", 0, 0, icmp)

	const wantPackets = `
# HELP nflog_packets_total Total number of packets logged via NFLOG, by the selected labels.
# TYPE nflog_packets_total counter
nflog_packets_total{dst_port="",proto="icmp"} 1
nflog_packets_total{dst_port="1234",proto="tcp"} 2
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(wantPackets), "nflog_packets_total"); err != nil {
		t.Errorf("packets metric mismatch:\n%v", err)
	}

	const wantBytes = `
# HELP nflog_bytes_total Total on-wire bytes of packets logged via NFLOG, by the selected labels.
# TYPE nflog_bytes_total counter
nflog_bytes_total{dst_port="",proto="icmp"} 84
nflog_bytes_total{dst_port="1234",proto="tcp"} 200
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(wantBytes), "nflog_bytes_total"); err != nil {
		t.Errorf("bytes metric mismatch:\n%v", err)
	}
}

func TestSubsystemRenamesTrafficCounters(t *testing.T) {
	reg := prometheus.NewRegistry()
	c, err := New(reg, []string{LabelDstPort}, "dropped", "test", "go-test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.Observe(5, "", 0, 0, packet.Info{Proto: "tcp", DstPort: 1234, HasPorts: true, WireLen: 100})
	c.Received(5)

	// Traffic counters carry the subsystem word.
	const wantPackets = `
# HELP nflog_dropped_packets_total Total number of packets logged via NFLOG, by the selected labels.
# TYPE nflog_dropped_packets_total counter
nflog_dropped_packets_total{dst_port="1234"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(wantPackets), "nflog_dropped_packets_total"); err != nil {
		t.Errorf("subsystem packets metric mismatch:\n%v", err)
	}

	// Operational counter keeps its original name.
	const wantReceived = `
# HELP nflog_received_packets_total Total NFLOG callbacks received per group, before decoding.
# TYPE nflog_received_packets_total counter
nflog_received_packets_total{group="5"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(wantReceived), "nflog_received_packets_total"); err != nil {
		t.Errorf("operational metric should be unchanged:\n%v", err)
	}
}

func TestValidateSubsystem(t *testing.T) {
	for _, ok := range []string{"", "dropped", "fw_drops", "X1"} {
		if err := ValidateSubsystem(ok); err != nil {
			t.Errorf("ValidateSubsystem(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"1abc", "has-dash", "has space", "trailing\n", "uri:colon"} {
		if err := ValidateSubsystem(bad); err == nil {
			t.Errorf("ValidateSubsystem(%q) = nil, want error", bad)
		}
	}
}

func TestReceivedAndDecodeErrorCounters(t *testing.T) {
	reg := prometheus.NewRegistry()
	c, err := New(reg, []string{LabelProto}, "", "test", "go-test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.Received(7)
	c.Received(7)
	c.DecodeError(7)

	const want = `
# HELP nflog_received_packets_total Total NFLOG callbacks received per group, before decoding.
# TYPE nflog_received_packets_total counter
nflog_received_packets_total{group="7"} 2
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "nflog_received_packets_total"); err != nil {
		t.Errorf("received metric mismatch:\n%v", err)
	}
}
