"""Generate a static, self-contained report from completed measurements."""
import csv
import html
import json
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
