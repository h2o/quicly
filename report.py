"""Generate aggregate tables and paired per-trace SVGs from fresh-host runs."""
import argparse
import csv
import html
import json
from pathlib import Path
import shutil
import charts

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('output', type=Path)
a = p.parse_args()
root = a.output.resolve()
result_paths = sorted(root.glob('*/*/*/result.json'))
quic_ccs = set()
codel_queues = set()
for path in result_paths:
    m = json.loads((path.parent / 'metadata.json').read_text())
    if m.get('dry_run'):
        continue
    if m['protocol'] == 'quic':
        quic_ccs.add(m['cc'])
    if m['condition'] in ('codel', 'codel_noabe'):
        if not m['queue'].startswith('codel:'):
            p.error(f"Expected ECN-capable CoDel queue: {path.parent}")
        codel_queues.add(m['queue'])
settings_path = root / 'matrix-settings.json'
settings = json.loads(settings_path.read_text()) if settings_path.exists() else None
if settings is not None:
    quic_ccs.add(settings.get('quic_cc', 'cubic'))
    codel_queues.add('codel:' + settings.get('codel', '5:100'))
if len(codel_queues) > 1:
    p.error('Use separate result roots for different CoDel settings (including matrix-settings.json)')
codel = next(iter(codel_queues), None)
codel_label = 'CoDel' + (' ' + html.escape(codel.removeprefix('codel:')) if codel else '')
assert len(quic_ccs) <= 1, 'Use separate result roots for different QUIC controllers'
quic_cc = next(iter(quic_ccs), 'cubic')
assert quic_cc in ('cubic', 'cuback'), 'Unsupported QUIC controller'
quic_label = quic_cc.upper()
policies = {
    'tcp_cubic': ('TCP CUBIC', '#2ca02c'),
    'tcp_bbr': ('TCP BBR', '#9467bd'),
    f'quic_{quic_cc}': (f'QUIC {quic_label}', '#1f77b4'),
    f'quic_{quic_cc}_abba': (f'QUIC {quic_label} + ABBA', '#d62728'),
    f'quic_{quic_cc}_off': (f'QUIC {quic_label} (ABE off)', '#1f77b4'),
    f'quic_{quic_cc}_abba_off': (f'QUIC {quic_label} + ABBA (ABE off)', '#d62728'),
}
data, traces, csv_rows = {}, {}, []
for path in result_paths:
    m = json.loads((path.parent / 'metadata.json').read_text())
    if m.get('dry_run'):
        continue
    r = json.loads(path.read_text())
    policy = m['protocol'] + '_' + m['cc'] + ('_abba' if m['abba'] else '')
    assert not m['rapid_start'] and policy in policies, 'This matrix report requires ordinary startup and the selected QUIC controller'
    condition = 'codel' if m['condition'] == 'codel_noabe' else m['condition']
    assert condition in ['tail', 'codel'], 'Use a separate report for drops-only CoDel'
    if m['condition'] == 'codel_noabe':
        policy += '_off'
    tid = m['trace_id']
    signature = tuple(m[k] for k in ['trace_sha256', 'start_ms', 'end_ms', 'buffer_bytes', 'capacity_bytes'])
    if tid in traces:
        assert traces[tid]['signature'] == signature, 'Mismatched measurement windows or traces'
    trace = dict(id=tid, start_ms=m['start_ms'], end_ms=m['end_ms'], duration_ms=m['duration_ms'],
                 IP_capacity_bytes=m['capacity_bytes'], signature=signature)
    traces[tid] = trace
    rows = data.setdefault((tid, condition), {})
    assert policy not in rows, 'Put each repetition in a separate output root'
    rows[policy] = dict(plaintext_delivered=r['application_bytes'], downstream_IP_forwarded=r['IP_forwarded'],
        downstream_IP_received=r['IP_received'], run=str(path.parent.relative_to(root)), metadata=m)
    folder = root / 'plots' / tid / condition
    folder.mkdir(parents=True, exist_ok=True)
    with (path.parent / 'curves.csv').open() as src, (folder / (policy + '.dat')).open('w') as dst:
        for row in csv.DictReader(src):
            ms = m['start_ms'] + round(float(row['elapsed_seconds']) * 1000)
            dst.write(f"{ms} {row['application_bytes']} {row['IP_forwarded']} {row['IP_received']}\n")
    saved_trace = root / 'traces' / tid
    if not saved_trace.exists():
        saved_trace.parent.mkdir(exist_ok=True)
        shutil.copy2(m['trace_path'], saved_trace)
    csv_rows.append([tid, m['condition'], policies[policy][0], r['application_bytes'], r['goodput_Mbps'],
                     r['IP_utilization'], r['IP_not_delivered'], rows[policy]['run']])

def table(rows, duration, capacity):
    headings = ['Policy', 'Application MB', 'Goodput Mbps', 'IP utilization', 'IP not delivered (MB)', 'Application vs BBR']
    result = '<table><tr>' + ''.join('<th>' + h + '</th>' for h in headings) + '</tr>'
    for policy, (label, _) in policies.items():
        if policy not in rows:
            continue
        r = rows[policy]
        ratio = f"{r['plaintext_delivered'] / rows['tcp_bbr']['plaintext_delivered']:.2%}" if 'tcp_bbr' in rows else '—'
        values = [label, f"{r['plaintext_delivered']/1e6:.3f}", f"{r['plaintext_delivered']*.008/duration:.3f}",
                  f"{r['downstream_IP_forwarded']/capacity:.2%}",
                  f"{(r['downstream_IP_received']-r['downstream_IP_forwarded'])/1e6:.3f}", ratio]
        result += '<tr>' + ''.join('<td>' + html.escape(v) + '</td>' for v in values) + '</tr>'
    return result + '</table>'

with (root / 'summary.csv').open('w') as f:
    writer = csv.writer(f)
    writer.writerow(['Trace', 'Condition', 'Policy', 'Application bytes', 'Goodput Mbps', 'IP utilization', 'IP not delivered bytes', 'Run directory'])
    writer.writerows(csv_rows)
page = ['<!doctype html><meta charset="utf-8"><title>Fresh-host CC benchmark</title>',
    '<style>body{font:16px system-ui;margin:2em}table{border-collapse:collapse}td,th{padding:.4em;border-bottom:1px solid #ddd;text-align:right}td:first-child,th:first-child{text-align:left}.pair{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1em}.panel{overflow:auto}img{width:100%}@media(max-width:1000px){.pair{display:block}}</style>',
    f'<h1>Congestion-control trace benchmark</h1><p>{len(csv_rows)} fresh measurements. TCP references were measured on this host and appear once per queue condition; both QUIC ABE settings share those TCP measurements. <a href="summary.csv">CSV and run-directory links</a>. Each run retains commands, build hashes and provenance.</p>',
    f'<h2>Scenarios</h2><p>NYC cellular traces; TCP CUBIC and BBR, QUIC {quic_label} and {quic_label} + ABBA. Tail drop and {codel_label} with ECN, optionally including QUIC ABE off. Ordinary QUIC startup, IW30, pacing, 60ms base RTT, 1472-byte QUIC UDP payload, zero random loss, and a queue of 60ms at the peak one-second-bin rate.</p>',
    '<p>MB are decimal. IP not delivered includes packets remaining in the emulator at cutoff. Single runs have no confidence intervals. Aggregate rows use the same complete trace set; partial runs are shown per trace.</p>',
    '<h2>Aggregate comparison</h2>']
if settings is not None:
    cpus = settings['cpus']
    mode = ('Unpinned sequential execution' if cpus == [None] else
            f'CPU-pinned execution: up to {len(cpus)} concurrent workers on logical CPUs ' + ', '.join(map(str, cpus)))
    if settings['smoke']:
        mode += '; two-second smoke captures (not full-trace measurements)'
    page.insert(4, '<p>' + html.escape(mode) + '.</p>')
noabe = any(any(k.endswith('_off') for k in rows) for rows in data.values())
for condition in ['tail', 'codel']:
    expected = list(policies) if condition == 'codel' and noabe else list(policies)[:4]
    matched = [tid for tid in traces if all(k in data.get((tid, condition), {}) for k in expected)]
    page.append(f'<h3>{"Tail drop" if condition == "tail" else "CoDel ECN"}: {len(matched)} matched traces</h3>')
    if matched:
        sums = {k: {field: sum(data[(tid, condition)][k][field] for tid in matched)
                    for field in ['plaintext_delivered', 'downstream_IP_forwarded', 'downstream_IP_received']} for k in expected}
        page.append(table(sums, sum(traces[tid]['duration_ms'] for tid in matched), sum(traces[tid]['IP_capacity_bytes'] for tid in matched)))
for tid, trace in traces.items():
    entries = map(int, (root / 'traces' / tid).read_text().splitlines())
    capacity, total = [(trace['start_ms'], 0)], 0
    for ms in entries:
        if trace['start_ms'] <= ms < trace['end_ms']:
            total += 1500
            capacity.append((ms, total))
    capacity.append((trace['end_ms'], total))
    assert total == trace['IP_capacity_bytes']
    page.append('<h2>' + html.escape(tid) + '</h2><div class="pair">')
    for condition in ['tail', 'codel']:
        rows = data.get((tid, condition), {})
        page.append('<section class="panel"><h3>' + ('Tail drop' if condition == 'tail' else 'CoDel ECN') + '</h3>')
        if rows:
            selected = {k: v for k, v in policies.items() if k in rows}
            folder = root / 'plots' / tid / condition
            for column in [1, 2]:
                charts.chart(folder, trace, rows, selected, column, capacity, {k: '7 4' for k in rows if k.endswith('_off')})
            page.append(table(rows, trace['duration_ms'], trace['IP_capacity_bytes']))
            for name in ['delivery', 'forwarded']:
                page.append(f'<img src="plots/{html.escape(tid)}/{condition}/{name}.svg" alt="{name}">')
        page.append('</section>')
    page.append('</div>')
charts.write(root / 'index.html', ''.join(page))
print(root / 'index.html')
