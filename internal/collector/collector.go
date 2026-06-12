// Package collector holds the Prometheus metrics and translates a decoded
// packet into label values according to the operator-selected label set.
package collector

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/mhagander/nflog_exporter/internal/packet"
)

// metricNamespace is the fixed prefix on every metric. The optional --subsystem
// word is inserted between it and the traffic counter names.
const metricNamespace = "nflog"

// subsystemRe validates the operator-supplied --subsystem word so the composed
// metric name stays a legal Prometheus identifier.
var subsystemRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]*$`)

// ValidateSubsystem reports whether s is a usable --subsystem value. An empty
// string is valid and means "no subsystem".
func ValidateSubsystem(s string) error {
	if s == "" {
		return nil
	}
	if !subsystemRe.MatchString(s) {
		return fmt.Errorf("invalid subsystem %q: must match %s", s, subsystemRe.String())
	}
	return nil
}

// Label tokens accepted by --labels, in their canonical ordering. The order
// here defines the order of label columns on the per-packet metrics.
const (
	LabelGroup   = "group"
	LabelPrefix  = "prefix"
	LabelProto   = "proto"
	LabelSrcIP   = "src_ip"
	LabelDstIP   = "dst_ip"
	LabelSrcPort = "src_port"
	LabelDstPort = "dst_port"
	LabelInIf    = "in_if"
	LabelOutIf   = "out_if"
)

// canonicalOrder is the fixed order in which selected labels are emitted.
var canonicalOrder = []string{
	LabelGroup, LabelPrefix, LabelProto,
	LabelSrcIP, LabelDstIP, LabelSrcPort, LabelDstPort,
	LabelInIf, LabelOutIf,
}

var allowed = func() map[string]struct{} {
	m := make(map[string]struct{}, len(canonicalOrder))
	for _, l := range canonicalOrder {
		m[l] = struct{}{}
	}
	return m
}()

// AllowedLabels returns the valid label tokens in canonical order (for help text).
func AllowedLabels() []string {
	out := make([]string, len(canonicalOrder))
	copy(out, canonicalOrder)
	return out
}

// ParseLabels parses and validates a comma-separated --labels value. It
// returns the selected labels in canonical order with duplicates removed.
func ParseLabels(spec string) ([]string, error) {
	seen := make(map[string]struct{})
	for _, tok := range strings.Split(spec, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if _, ok := allowed[tok]; !ok {
			return nil, fmt.Errorf("unknown label %q (allowed: %s)", tok, strings.Join(canonicalOrder, ", "))
		}
		seen[tok] = struct{}{}
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("at least one label is required")
	}
	out := make([]string, 0, len(seen))
	for _, l := range canonicalOrder {
		if _, ok := seen[l]; ok {
			out = append(out, l)
		}
	}
	return out, nil
}

// Metric tokens accepted by --metrics.
const (
	MetricPackets = "packets"
	MetricBytes   = "bytes"
)

// Metrics selects which traffic counters are exported. At least one is always
// enabled.
type Metrics struct {
	Packets bool
	Bytes   bool
}

// AllowedMetrics returns the valid --metrics tokens (for help text).
func AllowedMetrics() []string { return []string{MetricPackets, MetricBytes} }

// ParseMetrics parses and validates a comma-separated --metrics value.
func ParseMetrics(spec string) (Metrics, error) {
	var m Metrics
	for _, tok := range strings.Split(spec, ",") {
		tok = strings.TrimSpace(tok)
		switch tok {
		case "":
			continue
		case MetricPackets:
			m.Packets = true
		case MetricBytes:
			m.Bytes = true
		default:
			return Metrics{}, fmt.Errorf("unknown metric %q (allowed: %s)", tok, strings.Join(AllowedMetrics(), ", "))
		}
	}
	if !m.Packets && !m.Bytes {
		return Metrics{}, fmt.Errorf("at least one metric is required")
	}
	return m, nil
}

// Collector owns all exporter metrics.
type Collector struct {
	labels []string // selected per-packet labels, canonical order

	packets *prometheus.CounterVec
	bytes   *prometheus.CounterVec

	received    *prometheus.CounterVec // {group}
	decodeError *prometheus.CounterVec // {group}
	buildInfo   *prometheus.GaugeVec

	ifMu    sync.RWMutex
	ifCache map[uint32]string
}

// New builds a Collector for the given (already validated) label set and
// registers all metrics on reg. subsystem is an optional word inserted into the
// traffic counter names (e.g. "dropped" -> nflog_dropped_packets_total); the
// operational metrics are unaffected.
func New(reg prometheus.Registerer, labels []string, subsystem string, metrics Metrics, version, goVersion string) (*Collector, error) {
	if err := ValidateSubsystem(subsystem); err != nil {
		return nil, err
	}
	c := &Collector{
		labels:  labels,
		ifCache: make(map[uint32]string),
	}

	if metrics.Packets {
		c.packets = prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricNamespace,
			Subsystem: subsystem,
			Name:      "packets_total",
			Help:      "Total number of packets logged via NFLOG, by the selected labels.",
		}, labels)
	}
	if metrics.Bytes {
		c.bytes = prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricNamespace,
			Subsystem: subsystem,
			Name:      "bytes_total",
			Help:      "Total on-wire bytes of packets logged via NFLOG, by the selected labels.",
		}, labels)
	}
	c.received = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "nflog_received_packets_total",
		Help: "Total NFLOG callbacks received per group, before decoding.",
	}, []string{"group"})
	c.decodeError = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "nflog_decode_errors_total",
		Help: "Total packets that could not be decoded, per group.",
	}, []string{"group"})
	c.buildInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "nflog_build_info",
		Help: "Build information for nflog_exporter (always 1).",
	}, []string{"version", "goversion"})

	cols := []prometheus.Collector{c.received, c.decodeError, c.buildInfo}
	if c.packets != nil {
		cols = append(cols, c.packets)
	}
	if c.bytes != nil {
		cols = append(cols, c.bytes)
	}
	for _, col := range cols {
		if err := reg.Register(col); err != nil {
			return nil, err
		}
	}
	c.buildInfo.WithLabelValues(version, goVersion).Set(1)
	return c, nil
}

// Received increments the per-group received counter (called for every
// callback, regardless of decode success).
func (c *Collector) Received(group uint16) {
	c.received.WithLabelValues(strconv.FormatUint(uint64(group), 10)).Inc()
}

// DecodeError increments the per-group decode-error counter.
func (c *Collector) DecodeError(group uint16) {
	c.decodeError.WithLabelValues(strconv.FormatUint(uint64(group), 10)).Inc()
}

// Observe records a successfully decoded packet against the per-packet metrics.
func (c *Collector) Observe(group uint16, prefix string, inIf, outIf uint32, info packet.Info) {
	vals := make([]string, len(c.labels))
	for i, l := range c.labels {
		vals[i] = c.value(l, group, prefix, inIf, outIf, info)
	}
	if c.packets != nil {
		c.packets.WithLabelValues(vals...).Inc()
	}
	if c.bytes != nil {
		c.bytes.WithLabelValues(vals...).Add(float64(info.WireLen))
	}
}

func (c *Collector) value(label string, group uint16, prefix string, inIf, outIf uint32, info packet.Info) string {
	switch label {
	case LabelGroup:
		return strconv.FormatUint(uint64(group), 10)
	case LabelPrefix:
		return strings.TrimRight(prefix, "\x00 ")
	case LabelProto:
		return info.Proto
	case LabelSrcIP:
		return info.SrcIP
	case LabelDstIP:
		return info.DstIP
	case LabelSrcPort:
		if info.HasPorts {
			return strconv.FormatUint(uint64(info.SrcPort), 10)
		}
		return ""
	case LabelDstPort:
		if info.HasPorts {
			return strconv.FormatUint(uint64(info.DstPort), 10)
		}
		return ""
	case LabelInIf:
		return c.ifName(inIf)
	case LabelOutIf:
		return c.ifName(outIf)
	default:
		return ""
	}
}

// ifName resolves an interface index to its name, caching results. Index 0
// (no interface, e.g. the OUTPUT side of an INPUT rule) maps to "".
func (c *Collector) ifName(idx uint32) string {
	if idx == 0 {
		return ""
	}
	c.ifMu.RLock()
	name, ok := c.ifCache[idx]
	c.ifMu.RUnlock()
	if ok {
		return name
	}
	name = strconv.FormatUint(uint64(idx), 10) // fallback to index
	if iface, err := net.InterfaceByIndex(int(idx)); err == nil {
		name = iface.Name
	}
	c.ifMu.Lock()
	c.ifCache[idx] = name
	c.ifMu.Unlock()
	return name
}
