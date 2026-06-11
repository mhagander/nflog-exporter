package packet

import "strconv"

// protoName maps an IP protocol number to a short lowercase name used as the
// "proto" label value. Unknown protocols fall back to their decimal number so
// no information is lost. v6 selects icmpv6 naming for protocol 58.
func protoName(proto uint8, v6 bool) string {
	switch proto {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmpv6"
	case 2:
		return "igmp"
	case 47:
		return "gre"
	case 50:
		return "esp"
	case 51:
		return "ah"
	case 89:
		return "ospf"
	case 132:
		return "sctp"
	default:
		_ = v6
		return strconv.Itoa(int(proto))
	}
}
