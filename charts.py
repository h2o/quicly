"""Generate a static, self-contained report from completed measurements."""
import csv
import html
import json
import math
import os
import tempfile
import time
from pathlib import Path
from datetime import datetime

BASE = Path(__file__).resolve().parent
CORE = ['tcp_cubic', 'tcp_bbr', 'quic_cubic', 'quic_rapid_abba_v2']

def write(path, text):
    with tempfile.NamedTemporaryFile(mode='w', dir=path.parent, prefix=path.name+'.', suffix='.tmp', delete=False) as f:
        f.write(text)
        tmp = Path(f.name)
    tmp.replace(path)

def chart(folder, trace, results, policies, column, capacity, styles=None):
    styles = styles or {}
    filename = 'delivery.svg' if column == 1 else 'forwarded.svg'
    legend_extra = max(0, ((len(policies) + 1) // 2 - 4) * 23)
    width, height = 1000, 470 + legend_extra
    left, top, plotw, ploth = 85, 155 + legend_extra, 880, 250
    ceiling = trace['IP_capacity_bytes'] / 1e6
    x = lambda ms: left + (ms - trace['start_ms']) / trace['duration_ms'] * plotw
    y = lambda value: top + ploth * (1 - value / 1e6 / ceiling)
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}"><rect width="100%" height="100%" fill="white"/><g font-family="sans-serif" font-size="14">']
    title = 'Application bytes delivered (MB)' if column == 1 else 'IP bytes forwarded (MB)'
    parts.append(f'<text x="85" y="25" font-size="20">{title}</text>')
    for i in range(6):
        xx = left + plotw * i / 5
        yy = top + ploth * i / 5
        parts += [f'<path d="M{left} {yy}h{plotw}" stroke="#ddd"/>',
                  f'<text x="75" y="{yy+5}" text-anchor="end">{ceiling*(1-i/5):.1f}</text>',
                  f'<text x="{xx}" y="{430+legend_extra}" text-anchor="middle">{trace["duration_ms"]*i/5000:.1f}</text>']
    parts.append(f'<text x="500" y="{458+legend_extra}" text-anchor="middle">Elapsed trace time (seconds)</text>')
    def line(points, color, dashed=False):
        stride = max(1, len(points) // 1600)
        selected = points[::stride]
        if selected[-1] != points[-1]: selected.append(points[-1])
        path = ' '.join(('M' if i == 0 else 'L') + f'{x(ms):.2f},{y(value):.2f}' for i, (ms, value) in enumerate(selected))
        dash = '5 4' if dashed is True else dashed
        parts.append(f'<path d="{path}" fill="none" stroke="{color}" stroke-width="2"' + (f' stroke-dasharray="{dash}"' if dash else '') + '/>')
    if column == 2:
        line(capacity, '#888', True)
        parts.append(f'<text x="85" y="{143+legend_extra}" fill="#777">Gray dashed: IP link capacity</text>')
    for i, (name, (label, color)) in enumerate(policies.items()):
        if name not in results: continue
        xx, yy = 85 + (i % 2) * 450, 55 + (i // 2) * 23
        dash = f' stroke-dasharray="{styles[name]}"' if styles.get(name) else ''
        parts.append(f'<path d="M{xx} {yy-4}h24" stroke="{color}" stroke-width="2"{dash}/><text x="{xx+32}" y="{yy}" fill="{color}">{html.escape(label)}</text>')
        points = []
        for row in (folder / (name + '.dat')).read_text().splitlines():
            if row.startswith('#'): continue
            values = list(map(int, row.split()))
            points.append((values[0], values[column]))
        assert points[-1][1] == results[name]['plaintext_delivered' if column == 1 else 'downstream_IP_forwarded']
        line(points, color, styles.get(name,False))
    parts.append('</g></svg>')
    write(folder / filename, ''.join(parts))

def delay_density(folder, results, policies, styles=None):
    """Probability density of per-sample delays, one line per policy, on a logarithmic delay axis that spans from the smallest
    delay to 2000 ms; density is per log10(ms), so that equal areas mean equal probability. Vertical lines mark the average,
    p50, p90, and p99 of each policy, labeled above the plot and reaching into its top 10%."""
    styles = styles or {}
    legend_extra = max(0, ((len(policies) + 1) // 2 - 4) * 23)
    left, plotw, ploth = 85, 880, 250
    latencies = {name: results[name]['latency'] for name in policies if results[name].get('latency')}
    ticks = [m * 10 ** e for e in range(0, 6) for m in (1, 2, 5)]
    lo = max(t for t in ticks if t <= min(l[0] for l in latencies.values()))
    hi = 2000
    llo, lhi, bins = math.log10(lo), math.log10(hi), 60
    bin_width = (lhi - llo) / bins
    x = lambda log_ms: left + (log_ms - llo) / (lhi - llo) * plotw
    densities = {}
    for name, l in latencies.items():
        counts = [0] * bins
        for v in l:
            b = int((math.log10(v) - llo) / bin_width)
            if 0 <= b < bins:
                counts[b] += 1
        densities[name] = [c / (len(l) * bin_width) for c in counts]
    # marks (x, label, color, dash) of the statistics, each placed in the lowest row of labels where it does not overlap
    marks = []
    for name, (_, color) in policies.items():
        if name not in latencies: continue
        l = latencies[name]
        for label, v in [('avg', sum(l) / len(l))] + [(f'p{round(q * 100)}', l[max(0, math.ceil(q * len(l)) - 1)]) for q in (.5, .9, .99)]:
            if lo <= v <= hi:
                marks.append((x(math.log10(v)), label, color, styles.get(name)))
    rows, mark_rows = [], []
    for xx, label, _, _ in sorted(marks):
        start = xx - len(label) * 3.5
        r = next((i for i, end in enumerate(rows) if end + 3 <= start), len(rows))
        if r == len(rows): rows.append(0)
        rows[r] = xx + len(label) * 3.5
        mark_rows.append(r)
    band = len(rows) * 12 + 4
    top = 130 + legend_extra + band
    width, height = 1000, 445 + legend_extra + band
    peak = max(max(d) for d in densities.values())
    ystep = next(m * 10 ** e for e in range(-3, 3) for m in (1, 2, 5) if m * 10 ** e * 6 >= peak)
    ysteps = math.ceil(peak / ystep)
    ymax = ystep * ysteps
    y = lambda density: top + ploth * (1 - density / ymax)
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}"><rect width="100%" height="100%" fill="white"/><g font-family="sans-serif" font-size="14">',
             '<text x="85" y="25" font-size="20">Delay distribution (probability density per log10 ms)</text>']
    for i in range(ysteps + 1):
        yy = top + ploth * i / ysteps
        parts += [f'<path d="M{left} {yy}h{plotw}" stroke="#ddd"/>',
                  f'<text x="75" y="{yy+5}" text-anchor="end">{ystep*(ysteps-i):g}</text>']
    for t in ticks:
        if lo <= t <= hi:
            xx = x(math.log10(t))
            parts += [f'<path d="M{xx:.2f} {top}v{ploth}" stroke="#eee"/>',
                      f'<text x="{xx:.2f}" y="{top+ploth+25}" text-anchor="middle">{t}</text>']
    parts.append(f'<text x="500" y="{top+ploth+53}" text-anchor="middle">Delay (ms, log scale)</text>')
    for (xx, label, color, dash), r in zip(sorted(marks), mark_rows):
        ly = top - 6 - r * 12
        parts += [f'<path d="M{xx:.2f} {ly+2}V{top+ploth*.1:.2f}" stroke="{color}" stroke-width="1"' + (f' stroke-dasharray="{dash}"' if dash else '') + '/>',
                  f'<text x="{xx:.2f}" y="{ly}" font-size="10" text-anchor="middle" fill="{color}">{label}</text>']
    for i, (name, (label, color)) in enumerate(policies.items()):
        if name not in densities: continue
        xx, yy = 85 + (i % 2) * 450, 55 + (i // 2) * 23
        dash = f' stroke-dasharray="{styles[name]}"' if styles.get(name) else ''
        parts.append(f'<path d="M{xx} {yy-4}h24" stroke="{color}" stroke-width="2"{dash}/><text x="{xx+32}" y="{yy}" fill="{color}">{html.escape(label)}</text>')
        path = ' '.join(('M' if b == 0 else 'L') + f'{x(llo + (b + 0.5) * bin_width):.2f},{y(d):.2f}'
                        for b, d in enumerate(densities[name]))
        parts.append(f'<path d="{path}" fill="none" stroke="{color}" stroke-width="2"{dash}/>')
    parts.append('</g></svg>')
    write(folder / 'delay.svg', ''.join(parts))
