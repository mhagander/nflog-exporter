// Command nflog_exporter subscribes to one or more Linux NFLOG groups and
// exposes per-packet counters on a Prometheus-scrapeable HTTP endpoint.
//
// The operator chooses which dimensions to group by with --labels, e.g.
//
//	nflog_exporter --group 5 --labels group,prefix,proto,dst_port
//
// answers questions like "how many packets destined for port 1234 were logged"
// via nflog_packets_total{dst_port="1234"}.
//
// Reading NFLOG requires CAP_NET_ADMIN (run as root, or
// `setcap cap_net_admin=+ep ./nflog_exporter`).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/mhagander/nflog_exporter/internal/collector"
	"github.com/mhagander/nflog_exporter/internal/listener"
)

// version is overridable at build time with -ldflags "-X main.version=...".
var version = "dev"

// groupFlag is a repeatable --group flag collecting NFLOG group numbers.
type groupFlag []uint16

func (g *groupFlag) String() string {
	parts := make([]string, len(*g))
	for i, v := range *g {
		parts[i] = strconv.FormatUint(uint64(v), 10)
	}
	return strings.Join(parts, ",")
}

func (g *groupFlag) Set(s string) error {
	// Accept both repeated flags and a single comma-separated value.
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		n, err := strconv.ParseUint(tok, 10, 16)
		if err != nil {
			return fmt.Errorf("invalid group %q: %w", tok, err)
		}
		*g = append(*g, uint16(n))
	}
	return nil
}

func main() {
	var (
		groups      groupFlag
		labelsSpec  = flag.String("labels", "group,proto", "comma-separated metric labels; any of: "+strings.Join(collector.AllowedLabels(), ", "))
		subsystem   = flag.String("subsystem", "", "optional word inserted into the traffic counter names, e.g. \"dropped\" -> nflog_dropped_packets_total")
		listenAddr  = flag.String("listen", "127.0.0.1:9712", "address to serve metrics on (use :9712 to listen on all interfaces)")
		metricsPath = flag.String("metrics-path", "/metrics", "HTTP path for metrics")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Var(&groups, "group", "NFLOG group to watch (repeatable, or comma-separated)")
	flag.Parse()

	if *showVersion {
		fmt.Printf("nflog_exporter %s (%s)\n", version, runtime.Version())
		return
	}

	if len(groups) == 0 {
		log.Fatal("at least one --group is required")
	}

	labels, err := collector.ParseLabels(*labelsSpec)
	if err != nil {
		log.Fatalf("--labels: %v", err)
	}

	if err := collector.ValidateSubsystem(*subsystem); err != nil {
		log.Fatalf("--subsystem: %v", err)
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	coll, err := collector.New(reg, labels, *subsystem, version, runtime.Version())
	if err != nil {
		log.Fatalf("register metrics: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var listeners []*listener.Listener
	for _, g := range groups {
		l, err := listener.Open(ctx, g, coll)
		if err != nil {
			closeAll(listeners)
			log.Fatalf("%v", err)
		}
		listeners = append(listeners, l)
		log.Printf("watching NFLOG group %d", g)
	}
	defer closeAll(listeners)

	mux := http.NewServeMux()
	mux.Handle(*metricsPath, promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, "<html><head><title>nflog_exporter</title></head><body>\n"+
			"<h1>nflog_exporter</h1>\n<p><a href=%q>Metrics</a></p>\n"+
			"<p>Watching groups: %s</p>\n<p>Labels: %s</p>\n</body></html>\n",
			*metricsPath, groups.String(), strings.Join(labels, ", "))
	})

	srv := &http.Server{Addr: *listenAddr, Handler: mux}

	go func() {
		log.Printf("serving metrics on %s%s (labels: %s)", *listenAddr, *metricsPath, strings.Join(labels, ", "))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server: %v", err)
		}
	}()

	<-ctx.Done()
	log.Print("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("http shutdown: %v", err)
	}
}

func closeAll(ls []*listener.Listener) {
	for _, l := range ls {
		if err := l.Close(); err != nil {
			log.Printf("close group %d: %v", l.Group(), err)
		}
	}
}
