#!/usr/bin/env python3
"""Draw the performance charts in docs/images from measured figures.

Update the numbers below from `make perf` (tests/perf/throughput.sh) and
`make bench`, then run:  python3 tests/perf/charts.py

Charts are static SVGs (GitHub shows docs images without scripts), so values
are labelled on the bars; docs/performance.md carries the same numbers as
tables. They follow the viewer's light/dark preference.
"""
import html
import os

# ---- measured figures (i9-11950H laptop, Linux) ----

# tests/perf/throughput.sh (kernel TUN) and BenchmarkThroughput (userspace,
# MB/s × 8), Mbit/s.
THROUGHPUT = {
    "Direct path": {"Kernel TUN": 928, "Userspace (in-process)": 374},
    "Through the relay": {"Kernel TUN": 613, "Userspace (in-process)": 353},
}
UNDERLAY_MBIT = 20008

# tests/perf/throughput.sh, TCP round trip in µs.
LATENCY = {
    "Bare network": {"p50": 30, "p99": 57},
    "Tunnel, direct": {"p50": 156, "p99": 273},
    "Tunnel, relay": {"p50": 268, "p99": 383},
}

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "docs", "images")

# ---- drawing ----

# Validated categorical slots 1 and 2 (light / dark), see the dataviz palette.
STYLE = """
  .surface { fill: #fcfcfb; stroke: #e3e6ea; }
  .t1 { fill: #0b0b0b; } .t2 { fill: #52514e; } .t3 { fill: #6f6e69; }
  .grid { stroke: #e7e6e2; } .axis { stroke: #c9c8c2; }
  .s1 { fill: #2a78d6; } .s2 { fill: #eb6834; }
  @media (prefers-color-scheme: dark) {
    .surface { fill: #1a1a19; stroke: #33332f; }
    .t1 { fill: #f0efec; } .t2 { fill: #c3c2b7; } .t3 { fill: #9a998f; }
    .grid { stroke: #2e2e2b; } .axis { stroke: #4a4a45; }
    .s1 { fill: #3987e5; } .s2 { fill: #d95926; }
  }
  text { font-family: system-ui, -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif; }
"""


def esc(s):
    return html.escape(str(s), quote=True)


def svg(width, height, title, desc, body):
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
        f'role="img" aria-labelledby="t d">\n<title id="t">{esc(title)}</title>\n<desc id="d">{esc(desc)}</desc>\n'
        f"<style>{STYLE}</style>\n"
        f'<rect class="surface" x="0.5" y="0.5" width="{width - 1}" height="{height - 1}" rx="12"/>\n'
        + "\n".join(body)
        + "\n</svg>\n"
    )


def hbar(x, y, w, h, cls):
    """Horizontal bar from the baseline x, with a 4px rounded data end."""
    r = min(4, w / 2, h / 2)
    if w <= 0:
        return ""
    return (
        f'<path class="{cls}" d="M{x:.1f},{y:.1f} H{x + w - r:.1f} '
        f"Q{x + w:.1f},{y:.1f} {x + w:.1f},{y + r:.1f} V{y + h - r:.1f} "
        f'Q{x + w:.1f},{y + h:.1f} {x + w - r:.1f},{y + h:.1f} H{x:.1f} Z"/>'
    )


def legend(x, y, items):
    out, cx = [], x
    for label, cls in items:
        out.append(f'<rect class="{cls}" x="{cx}" y="{y - 9}" width="12" height="12" rx="3"/>')
        out.append(f'<text class="t2" x="{cx + 18}" y="{y + 1}" font-size="13">{esc(label)}</text>')
        cx += 18 + 7.4 * len(label) + 26
    return out


def grouped_hbars(fname, title, subtitle, data, series, unit, axis_max, ticks, fmt, desc, width=760):
    left, right, top = 190, 110, 96
    bar_h, gap, group_gap = 18, 2, 26
    groups = list(data.items())
    group_h = len(series) * bar_h + (len(series) - 1) * gap
    plot_h = len(groups) * group_h + (len(groups) - 1) * group_gap
    height = top + plot_h + 52
    pw = width - left - right
    sx = lambda v: left + pw * v / axis_max
    body = [
        f'<text class="t1" x="24" y="36" font-size="17" font-weight="600">{esc(title)}</text>',
        f'<text class="t2" x="24" y="58" font-size="13">{esc(subtitle)}</text>',
    ]
    body += legend(24, 82, [(label, c) for _, label, c in series])
    axis_y = top + plot_h + 10
    for i, t in enumerate(ticks):
        X = sx(t)
        label = fmt(t) + (f" {unit}" if i == len(ticks) - 1 else "")  # the unit rides on the last tick
        body.append(f'<line class="grid" x1="{X:.1f}" y1="{top - 6}" x2="{X:.1f}" y2="{axis_y}" stroke-width="1"/>')
        body.append(f'<text class="t3" x="{X:.1f}" y="{axis_y + 18}" font-size="12" text-anchor="middle">{esc(label)}</text>')
    body.append(f'<line class="axis" x1="{left}" y1="{top - 6}" x2="{left}" y2="{axis_y}" stroke-width="1"/>')
    y = top
    for name, vals in groups:
        body.append(f'<text class="t1" x="{left - 12}" y="{y + group_h / 2 + 5:.1f}" font-size="13.5" text-anchor="end">{esc(name)}</text>')
        for key, _, cls in series:
            v = vals[key]
            body.append(hbar(left, y, sx(v) - left, bar_h, cls))
            body.append(f'<text class="t2" x="{sx(v) + 6:.1f}" y="{y + bar_h - 4.5:.1f}" font-size="12.5">{esc(fmt(v))} {esc(unit)}</text>')
            y += bar_h + gap
        y += group_gap - gap
    with open(os.path.join(OUT, fname), "w") as f:
        f.write(svg(width, height, title, desc, body))


def main():
    grouped_hbars(
        "perf-throughput.svg",
        "Tunnel throughput",
        f"TCP over the tunnel between two machines. Bare network for reference: {UNDERLAY_MBIT:,} Mbit/s.",
        THROUGHPUT,
        [("Kernel TUN", "Kernel TUN", "s1"), ("Userspace (in-process)", "Userspace (in-process)", "s2")],
        "Mbit/s", 1000, [0, 250, 500, 750, 1000], lambda v: f"{v:,.0f}",
        "; ".join(f"{g}: " + ", ".join(f"{s} {v} Mbit/s" for s, v in d.items()) for g, d in THROUGHPUT.items()),
    )
    grouped_hbars(
        "perf-latency.svg",
        "TCP round-trip time",
        "One-byte request and reply, kernel TUN. Shorter is better.",
        LATENCY,
        [("p50", "p50 (median)", "s1"), ("p99", "p99", "s2")],
        "µs", 400, [0, 100, 200, 300, 400], lambda v: f"{v:,.0f}",
        "; ".join(f"{g}: p50 {d['p50']} µs, p99 {d['p99']} µs" for g, d in LATENCY.items()),
    )
    print("wrote perf-throughput.svg and perf-latency.svg to docs/images")


if __name__ == "__main__":
    main()
