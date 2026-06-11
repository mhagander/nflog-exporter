// Package listener subscribes to NFLOG groups and feeds decoded packets to the
// collector.
package listener

import (
	"context"
	"fmt"
	"log"

	nflog "github.com/florianl/go-nflog/v2"

	"github.com/mhagander/nflog_exporter/internal/collector"
	"github.com/mhagander/nflog_exporter/internal/packet"
)

// bufsize is the number of bytes copied from each packet to userspace. We only
// need the IP + TCP/UDP headers (addresses, ports) and the IP length field, so
// a small value keeps kernel->userspace overhead low. 256 bytes comfortably
// covers IPv6 (40) + max TCP header (60) plus options.
const bufsize = 256

// Listener wraps a single open NFLOG group connection.
type Listener struct {
	group uint16
	conn  *nflog.Nflog
}

// Open subscribes to one NFLOG group and registers a hook that decodes each
// packet and records it in c. The subscription runs until ctx is cancelled.
func Open(ctx context.Context, group uint16, c *collector.Collector) (*Listener, error) {
	conn, err := nflog.Open(&nflog.Config{
		Group:    group,
		Copymode: nflog.CopyPacket,
		Bufsize:  bufsize,
	})
	if err != nil {
		return nil, fmt.Errorf("open nflog group %d: %w", group, err)
	}

	// One decoder per listener: DecodingLayerParser is not concurrency-safe,
	// and the hook runs on this connection's single receive goroutine.
	dec := packet.New()

	hook := func(a nflog.Attribute) int {
		c.Received(group)

		if a.Payload == nil {
			c.DecodeError(group)
			return 0
		}
		info, err := dec.Decode(hwProto(a.HwProtocol), *a.Payload)
		if err != nil {
			c.DecodeError(group)
			return 0
		}

		var prefix string
		if a.Prefix != nil {
			prefix = *a.Prefix
		}
		c.Observe(group, prefix, derefU32(a.InDev), derefU32(a.OutDev), info)
		return 0
	}

	errFn := func(e error) int {
		log.Printf("nflog group %d: receive error: %v", group, e)
		return 0 // keep receiving
	}

	if err := conn.RegisterWithErrorFunc(ctx, hook, errFn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("register nflog group %d: %w", group, err)
	}

	return &Listener{group: group, conn: conn}, nil
}

// Group returns the NFLOG group number this listener is attached to.
func (l *Listener) Group() uint16 { return l.group }

// Close tears down the NFLOG connection.
func (l *Listener) Close() error { return l.conn.Close() }

func hwProto(p *uint16) uint16 {
	if p == nil {
		return 0
	}
	return *p
}

func derefU32(p *uint32) uint32 {
	if p == nil {
		return 0
	}
	return *p
}
