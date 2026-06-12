# nflog_exporter

A Prometheus exporter for Linux **NFLOG** (netfilter log) data.

Firewall rules send matching packets to a numbered NFLOG group; this exporter
subscribes to one or more groups, decodes each packet's headers, and exposes
per-packet counters on a Prometheus-scrapeable HTTP endpoint. The operator
chooses **which dimensions to group by** on the command line, so a question like
*"how many packets destined for port 1234 were logged?"* becomes a simple query:

```promql
nflog_packets_total{dst_port="1234"}
```

## Metrics

| Metric | Type | Labels | Description |
| --- | --- | --- | --- |
| `nflog_packets_total` | counter | *selected* (`--labels`) | Packets logged via NFLOG. |
| `nflog_bytes_total` | counter | *selected* (`--labels`) | On-wire bytes (from the IP header length, not the captured length). |

The two traffic counters (`*_packets_total`, `*_bytes_total`) can be renamed with
`--subsystem` (see below), and `--metrics` selects which of them are exported
(`--metrics packets`, `--metrics bytes`, or the default `packets,bytes`). The
operational counters below are always exported and never renamed.
| `nflog_received_packets_total` | counter | `group` | Callbacks received per group, before decoding. |
| `nflog_decode_errors_total` | counter | `group` | Packets that could not be decoded. |
| `nflog_build_info` | gauge | `version`, `goversion` | Always 1. |

Plus the standard Go and process collectors.

## Label dimensions (`--labels`)

Comma-separated, any of:

`group`, `prefix`, `proto`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `in_if`, `out_if`

- `prefix` is the `--nflog-prefix` / `prefix` string set in the firewall rule.
- `proto` is `tcp`/`udp`/`icmp`/`icmpv6`/… (numeric for uncommon protocols).
- `src_port`/`dst_port` are populated only for TCP/UDP (empty otherwise).
- `in_if`/`out_if` are resolved to interface names (numeric index on lookup miss).

> ⚠️ **Cardinality:** `src_ip`, `dst_ip`, `src_port`, and `dst_port` can produce a
> very large number of time series on busy rules. Enable them only for rules
> whose traffic you know to be bounded, or scope them with a narrow firewall match.

## Building

Requires Go 1.24+.

```sh
go build -o nflog_exporter .
# optionally stamp a version:
go build -ldflags "-X main.version=$(git describe --tags --always 2>/dev/null || echo dev)" -o nflog_exporter .
```

## Privileges

Reading NFLOG requires `CAP_NET_ADMIN`. Either run as root, or grant the
capability to the binary:

```sh
sudo setcap cap_net_admin=+ep ./nflog_exporter
```

## Running

```sh
./nflog_exporter --group 5 --labels group,prefix,proto,dst_port --listen :9712
```

Flags:

| Flag | Default | Description |
| --- | --- | --- |
| `--group` | *(required)* | NFLOG group to watch. Repeatable, or comma-separated. |
| `--labels` | `group,proto` | Metric label dimensions (see above). |
| `--metrics` | `packets,bytes` | Which traffic counters to export: `packets`, `bytes`, or both. |
| `--subsystem` | *(empty)* | Word inserted into the traffic counter names (see below). |
| `--listen` | `127.0.0.1:9712` | Address to serve metrics on (localhost only; use `:9712` for all interfaces). |
| `--metrics-path` | `/metrics` | HTTP path for metrics. |
| `--version` | | Print version and exit. |

## Renaming the traffic counters (`--subsystem`)

NFLOG is most often attached to a DROP rule, so you may want the counters to
read as drops. `--subsystem` inserts an operator-chosen word between the `nflog`
namespace and the traffic counter names:

```sh
./nflog_exporter --group 5 --labels dst_port --subsystem dropped
```

yields:

```
nflog_dropped_packets_total{dst_port="1234"} 7
nflog_dropped_bytes_total{dst_port="1234"} 812
```

The word must be a valid Prometheus identifier component (`^[a-zA-Z][a-zA-Z0-9_]*$`).
With no `--subsystem` the names stay `nflog_packets_total` / `nflog_bytes_total`.
The operational counters (`nflog_received_packets_total`,
`nflog_decode_errors_total`, `nflog_build_info`) are never renamed.

## Generating NFLOG data

Add a rule that logs to a group (and optionally tags it with a prefix):

**iptables**

```sh
iptables -A INPUT -p tcp --dport 1234 -j NFLOG --nflog-group 5 --nflog-prefix "in-1234"
```

**nftables**

```nft
table inet filter {
    chain input {
        tcp dport 1234 log group 5 prefix "in-1234"
    }
}
```

Then scrape:

```sh
curl -s localhost:9712/metrics | grep nflog_
```

## How it works

- `internal/packet` decodes the raw IP payload (IPv4/IPv6 + TCP/UDP/ICMP) with
  `gopacket`, using a reused `DecodingLayerParser` to avoid per-packet
  allocations. Byte accounting uses the IP header length field so it stays
  correct even though only packet headers are copied to userspace.
- `internal/collector` builds the `*_total` counter vectors with exactly the
  selected label names and translates each decoded packet into label values.
- `internal/listener` opens one `go-nflog` connection per group (small copy
  buffer — headers only) and registers the decode→record hook.
- `main.go` wires flags, the Prometheus registry, the HTTP server, and
  graceful shutdown on `SIGINT`/`SIGTERM`.
