package packet

import (
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// serialize builds an on-wire byte slice from the given layers, computing
// lengths and checksums.
func serialize(t *testing.T, ls ...gopacket.SerializableLayer) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ls...); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return buf.Bytes()
}

func TestDecodeIPv4TCP(t *testing.T) {
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IP{10, 0, 0, 1},
		DstIP:    net.IP{10, 0, 0, 2},
	}
	tcp := &layers.TCP{SrcPort: 51000, DstPort: 1234, SYN: true}
	tcp.SetNetworkLayerForChecksum(ip)
	payload := serialize(t, ip, tcp, gopacket.Payload([]byte("hello")))

	d := New()
	info, err := d.Decode(ethTypeIPv4, payload)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if info.Proto != "tcp" {
		t.Errorf("proto = %q, want tcp", info.Proto)
	}
	if info.SrcIP != "10.0.0.1" || info.DstIP != "10.0.0.2" {
		t.Errorf("ips = %s -> %s", info.SrcIP, info.DstIP)
	}
	if !info.HasPorts || info.SrcPort != 51000 || info.DstPort != 1234 {
		t.Errorf("ports = %d -> %d (has=%v)", info.SrcPort, info.DstPort, info.HasPorts)
	}
	if info.WireLen != len(payload) {
		t.Errorf("WireLen = %d, want %d", info.WireLen, len(payload))
	}
}

func TestDecodeIPv4UDP(t *testing.T) {
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IP{192, 168, 1, 5},
		DstIP:    net.IP{8, 8, 8, 8},
	}
	udp := &layers.UDP{SrcPort: 40000, DstPort: 53}
	udp.SetNetworkLayerForChecksum(ip)
	payload := serialize(t, ip, udp, gopacket.Payload([]byte("dnsquery")))

	info, err := New().Decode(ethTypeIPv4, payload)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if info.Proto != "udp" || info.DstPort != 53 || !info.HasPorts {
		t.Errorf("got %+v", info)
	}
	if info.WireLen != len(payload) {
		t.Errorf("WireLen = %d, want %d", info.WireLen, len(payload))
	}
}

func TestDecodeIPv6TCP(t *testing.T) {
	ip := &layers.IPv6{
		Version:    6,
		NextHeader: layers.IPProtocolTCP,
		HopLimit:   64,
		SrcIP:      net.ParseIP("2001:db8::1"),
		DstIP:      net.ParseIP("2001:db8::2"),
	}
	tcp := &layers.TCP{SrcPort: 12345, DstPort: 443, SYN: true}
	tcp.SetNetworkLayerForChecksum(ip)
	payload := serialize(t, ip, tcp)

	info, err := New().Decode(ethTypeIPv6, payload)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if info.Proto != "tcp" || info.DstPort != 443 {
		t.Errorf("got %+v", info)
	}
	// IPv6 WireLen = payload length + 40-byte fixed header == total bytes here.
	if info.WireLen != len(payload) {
		t.Errorf("WireLen = %d, want %d", info.WireLen, len(payload))
	}
	if info.SrcIP != "2001:db8::1" {
		t.Errorf("SrcIP = %q", info.SrcIP)
	}
}

func TestDecodeICMPv4NoPorts(t *testing.T) {
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		Protocol: layers.IPProtocolICMPv4,
		SrcIP:    net.IP{10, 0, 0, 1},
		DstIP:    net.IP{10, 0, 0, 2},
	}
	icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0)}
	payload := serialize(t, ip, icmp, gopacket.Payload([]byte("ping")))

	info, err := New().Decode(ethTypeIPv4, payload)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if info.Proto != "icmp" {
		t.Errorf("proto = %q, want icmp", info.Proto)
	}
	if info.HasPorts {
		t.Errorf("icmp should not have ports")
	}
}

// TestWireLenFromHeaderNotPayload proves bytes accounting uses the IP header's
// length field, not the (possibly truncated) captured payload length.
func TestWireLenFromHeaderNotPayload(t *testing.T) {
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.IP{10, 0, 0, 1},
		DstIP:    net.IP{10, 0, 0, 2},
	}
	udp := &layers.UDP{SrcPort: 1, DstPort: 2}
	udp.SetNetworkLayerForChecksum(ip)
	full := serialize(t, ip, udp, gopacket.Payload(make([]byte, 1000)))
	fullLen := len(full)

	// Simulate NFLOG copying only the first 64 bytes (Bufsize truncation).
	truncated := full[:64]

	info, err := New().Decode(ethTypeIPv4, truncated)
	if err != nil {
		t.Fatalf("Decode truncated: %v", err)
	}
	if info.WireLen != fullLen {
		t.Errorf("WireLen = %d, want full on-wire %d (must come from IP header)", info.WireLen, fullLen)
	}
	if !info.HasPorts || info.DstPort != 2 {
		t.Errorf("ports lost on truncated packet: %+v", info)
	}
}

func TestDecodeVersionInference(t *testing.T) {
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IP{1, 1, 1, 1},
		DstIP:    net.IP{2, 2, 2, 2},
	}
	tcp := &layers.TCP{SrcPort: 1, DstPort: 80}
	tcp.SetNetworkLayerForChecksum(ip)
	payload := serialize(t, ip, tcp)

	// hwProtocol 0 -> infer from version nibble.
	info, err := New().Decode(0, payload)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if info.Proto != "tcp" || info.DstPort != 80 {
		t.Errorf("got %+v", info)
	}
}

func TestDecodeEmpty(t *testing.T) {
	if _, err := New().Decode(ethTypeIPv4, nil); err == nil {
		t.Errorf("expected error on empty payload")
	}
}
