// Package packet decodes raw IP packets (as delivered by NFLOG) into the small
// set of fields the exporter groups metrics by. It deliberately decodes only the
// network and transport headers, which is all NFLOG copies when a small Bufsize
// is configured.
package packet

import (
	"errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Info holds the decoded fields that may be used as metric labels.
type Info struct {
	Proto    string // "tcp", "udp", "icmp", "icmpv6", or the numeric protocol
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	HasPorts bool // true only for TCP/UDP
	WireLen  int  // on-wire packet size from the IP header, not len(payload)
}

// ErrEmptyPayload is returned when there is nothing to decode.
var ErrEmptyPayload = errors.New("empty payload")

// Ethertypes used by NFLOG's HwProtocol attribute.
const (
	ethTypeIPv4 = 0x0800
	ethTypeIPv6 = 0x86DD
)

// Decoder decodes raw IP payloads. It reuses layer structs and a
// DecodingLayerParser to avoid per-packet allocations on busy links.
//
// A Decoder is NOT safe for concurrent use: give each listener goroutine its
// own Decoder via New.
type Decoder struct {
	ip4     layers.IPv4
	ip6     layers.IPv6
	tcp     layers.TCP
	udp     layers.UDP
	icmp4   layers.ICMPv4
	icmp6   layers.ICMPv6
	v4only  *gopacket.DecodingLayerParser
	v6only  *gopacket.DecodingLayerParser
	decoded []gopacket.LayerType
}

// New returns a ready-to-use Decoder.
func New() *Decoder {
	d := &Decoder{decoded: make([]gopacket.LayerType, 0, 4)}
	// One parser starting at IPv4 and one starting at IPv6. The transport
	// layers are shared; DecodingLayerParser follows NextLayerType from the IP
	// layer to the matching transport decoder.
	d.v4only = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4,
		&d.ip4, &d.tcp, &d.udp, &d.icmp4, &d.icmp6)
	d.v6only = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6,
		&d.ip6, &d.tcp, &d.udp, &d.icmp4, &d.icmp6)
	// Ignore "no decoder for layer type" panics for payloads we don't model
	// (e.g. an unknown L4 protocol after the IP header).
	d.v4only.IgnoreUnsupported = true
	d.v6only.IgnoreUnsupported = true
	return d
}

// Decode parses payload, using hwProtocol (the NFLOG HwProtocol/ethertype) to
// pick the IP version. If hwProtocol is 0 (not provided), the IP version is
// inferred from the first nibble of the payload.
func (d *Decoder) Decode(hwProtocol uint16, payload []byte) (Info, error) {
	if len(payload) == 0 {
		return Info{}, ErrEmptyPayload
	}

	isV6 := false
	switch hwProtocol {
	case ethTypeIPv4:
		isV6 = false
	case ethTypeIPv6:
		isV6 = true
	default:
		// Infer from the IP version nibble.
		switch payload[0] >> 4 {
		case 6:
			isV6 = true
		case 4:
			isV6 = false
		default:
			return Info{}, errors.New("unrecognized IP version")
		}
	}

	parser := d.v4only
	if isV6 {
		parser = d.v6only
	}

	d.decoded = d.decoded[:0]
	if err := parser.DecodeLayers(payload, &d.decoded); err != nil {
		// DecodeLayers returns an error for truncated/short packets even when
		// it managed to decode the leading layers. We still want the fields it
		// did decode (notably the IP header for addresses and WireLen), so we
		// fall through and report whatever layers landed in d.decoded.
		if len(d.decoded) == 0 {
			return Info{}, err
		}
	}

	var info Info
	gotIP := false
	for _, lt := range d.decoded {
		switch lt {
		case layers.LayerTypeIPv4:
			gotIP = true
			info.SrcIP = d.ip4.SrcIP.String()
			info.DstIP = d.ip4.DstIP.String()
			info.WireLen = int(d.ip4.Length)
			info.Proto = protoName(uint8(d.ip4.Protocol), false)
		case layers.LayerTypeIPv6:
			gotIP = true
			info.SrcIP = d.ip6.SrcIP.String()
			info.DstIP = d.ip6.DstIP.String()
			// IPv6 Length is the payload length; add the 40-byte fixed header.
			info.WireLen = int(d.ip6.Length) + 40
			info.Proto = protoName(uint8(d.ip6.NextHeader), true)
		case layers.LayerTypeTCP:
			info.SrcPort = uint16(d.tcp.SrcPort)
			info.DstPort = uint16(d.tcp.DstPort)
			info.HasPorts = true
		case layers.LayerTypeUDP:
			info.SrcPort = uint16(d.udp.SrcPort)
			info.DstPort = uint16(d.udp.DstPort)
			info.HasPorts = true
		}
	}

	if !gotIP {
		return Info{}, errors.New("no IP header decoded")
	}
	return info, nil
}
