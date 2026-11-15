// Package metrics exposes counters and gauges in the Prometheus text
// format (version 0.0.4), which Prometheus and most monitoring tools
// scrape, and which is readable with curl. It has no dependencies.
package metrics

import (
	"bufio"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Registry is a set of metrics served together.
type Registry struct {
	mu    sync.Mutex
	items []item
	names map[string]bool
}

type item struct {
	name, help, typ string
	collect         func(emit func(labels []string, v float64))
}

func NewRegistry() *Registry { return &Registry{names: map[string]bool{}} }

func (r *Registry) add(it item) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.names[it.name] {
		panic("metrics: duplicate metric " + it.name)
	}
	r.names[it.name] = true
	r.items = append(r.items, it)
}

// Counter is a value that only goes up.
type Counter struct{ v atomic.Int64 }

func (c *Counter) Add(n int64) { c.v.Add(n) }
func (c *Counter) Inc()        { c.v.Add(1) }
func (c *Counter) Value() int64 {
	if c == nil {
		return 0
	}
	return c.v.Load()
}

// Counter registers a new counter.
func (r *Registry) Counter(name, help string) *Counter {
	c := &Counter{}
	r.CounterFunc(name, help, func() float64 { return float64(c.Value()) })
	return c
}

// CounterFunc registers a counter whose value f reads from elsewhere.
func (r *Registry) CounterFunc(name, help string, f func() float64) {
	r.add(item{name, help, "counter", func(emit func([]string, float64)) { emit(nil, f()) }})
}

// GaugeFunc registers a value that goes up and down, read by f.
func (r *Registry) GaugeFunc(name, help string, f func() float64) {
	r.add(item{name, help, "gauge", func(emit func([]string, float64)) { emit(nil, f()) }})
}

// Collect registers a family with labels: on every scrape, f calls emit
// once per series with alternating label names and values, e.g.
// emit([]string{"path", "direct"}, 3). typ is "counter" or "gauge".
func (r *Registry) Collect(name, help, typ string, f func(emit func(labels []string, v float64))) {
	r.add(item{name, help, typ, f})
}

// ServeHTTP writes all metrics.
func (r *Registry) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	bw := bufio.NewWriter(w)
	r.Write(bw)
	bw.Flush()
}

// Write writes all metrics in the text format.
func (r *Registry) Write(w *bufio.Writer) {
	r.mu.Lock()
	items := append([]item(nil), r.items...)
	r.mu.Unlock()
	sort.Slice(items, func(i, j int) bool { return items[i].name < items[j].name })
	for _, it := range items {
		w.WriteString("# HELP " + it.name + " " + escapeHelp(it.help) + "\n")
		w.WriteString("# TYPE " + it.name + " " + it.typ + "\n")
		it.collect(func(labels []string, v float64) {
			w.WriteString(it.name)
			if len(labels) > 0 {
				w.WriteByte('{')
				for i := 0; i+1 < len(labels); i += 2 {
					if i > 0 {
						w.WriteByte(',')
					}
					w.WriteString(labels[i] + `="` + escapeLabel(labels[i+1]) + `"`)
				}
				w.WriteByte('}')
			}
			w.WriteByte(' ')
			w.WriteString(formatValue(v))
			w.WriteByte('\n')
		})
	}
}

func formatValue(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case math.IsNaN(v):
		return "NaN"
	case v == math.Trunc(v) && math.Abs(v) < 1e15:
		return strconv.FormatInt(int64(v), 10)
	}
	// 12 significant digits hide floating-point noise (0.01356, not
	// 0.013560000000000001) and are far more than any metric needs.
	return strconv.FormatFloat(v, 'g', 12, 64)
}

var helpEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`)
var labelEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`)

func escapeHelp(s string) string  { return helpEscaper.Replace(s) }
func escapeLabel(s string) string { return labelEscaper.Replace(s) }
