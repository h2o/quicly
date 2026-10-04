"""Generate aggregate tables and paired per-trace SVGs from fresh-host runs."""
import argparse
from array import array
from concurrent.futures import ThreadPoolExecutor
import csv
import html
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
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
# latency.py processes each run with --latency; do it before reading, in parallel, as all captures have completed
latency_runs = [path.parent for path in result_paths
                if (path.parent / 'tunulator.pktlog').exists() and not (path.parent / 'latency.csv').exists()]
with ThreadPoolExecutor(os.cpu_count()) as pool:
    list(pool.map(lambda run: subprocess.run([sys.executable, str(Path(__file__).with_name('latency.py')), str(run)],
                                             stdout=subprocess.DEVNULL, check=True), latency_runs))

def read_latency(run):
    """Sorted per-sample delays (ms) of a run, or None if not measured."""
    if not (run / 'latency.csv').exists():
        return None
    with (run / 'latency.csv').open() as f:
        return array('d', sorted(float(row['latency_ms']) for row in csv.DictReader(f)))

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
        downstream_IP_received=r['IP_received'], latency=read_latency(path.parent), run=str(path.parent.relative_to(root)),
        metadata=m)
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

def delay_stats(weighted):
    """Average, p50, p90 and p99 of delays given as (delay, weight) pairs sorted by delay."""
    total = sum(w for _, w in weighted)
    stats, acc, quantiles = [sum(d * w for d, w in weighted) / total], 0, [.5, .9, .99]
    for d, w in weighted:
        acc += w
        while quantiles and acc >= quantiles[0] * total:
            stats.append(d)
            quantiles.pop(0)
    return stats

def metrics(r, duration, capacity):
    app, fwd, rcv = r['plaintext_delivered'], r['downstream_IP_forwarded'], r['downstream_IP_received']
    return dict(goodput_mbps=app * .008 / duration, goodput_util=app / capacity, ip_mbps=fwd * .008 / duration,
                ip_util=fwd / capacity, not_delivered=(rcv - fwd) / rcv,
                delay=delay_stats([(d, 1) for d in r['latency']]) if r['latency'] else None)

def table(stats):
    headings = ['Policy', 'Goodput (Mbps / utilization)', 'IP forwarded (Mbps / utilization)', 'Not delivered',
                'Delay avg (ms)', 'Delay p50 (ms)', 'Delay p90 (ms)', 'Delay p99 (ms)']
    result = '<table><tr>' + ''.join('<th>' + h + '</th>' for h in headings) + '</tr>'
    for policy, (label, _) in policies.items():
        if policy not in stats:
            continue
        m = stats[policy]
        values = [label, f"{m['goodput_mbps']:.2f} / {m['goodput_util']:.1%}", f"{m['ip_mbps']:.2f} / {m['ip_util']:.1%}",
                  f"{m['not_delivered']:.2%}"]
        values += [f"{v:.1f}" for v in m['delay']] if m['delay'] else ['—'] * 4
        result += '<tr>' + ''.join('<td>' + html.escape(v) + '</td>' for v in values) + '</tr>'
    return result + '</table>'

with (root / 'summary.csv').open('w') as f:
    writer = csv.writer(f)
    writer.writerow(['Trace', 'Condition', 'Policy', 'Application bytes', 'Goodput Mbps', 'IP utilization', 'IP not delivered bytes', 'Run directory'])
    writer.writerows(csv_rows)
page = ['<!doctype html><meta charset="utf-8"><title>Fresh-host CC benchmark</title>',
    '<style>body{font:16px system-ui;margin:2em}table{border-collapse:collapse}td,th{padding:.4em;border-bottom:1px solid #ddd;text-align:right}td:first-child,th:first-child{text-align:left}.panel{overflow:auto}img{width:100%;max-width:1000px}</style>',
    f'<h1>Congestion-control trace benchmark</h1><p>{len(csv_rows)} measurements. <a href="summary.csv">CSV and run-directory links</a>.</p>',
    f'<h2>Policies</h2><ul><li>TCP CUBIC, TCP BBR: the host kernel\'s implementations, over TLS, with pacing and an initial window of 30.</li><li>QUIC {quic_label}, QUIC {quic_label} + ABBA: quicly with an initial window of 30, pacing, ordinary startup (no Rapid Start or Jump Start), and a 1472-byte UDP payload.</li><li>QUIC with ABE off: the same QUIC policies built with QUICLY_USE_ABE=0, measured under CoDel only. ABE only affects QUIC, so the TCP rows of the CoDel table serve both settings.</li></ul>',
    f'<h2>Scenarios</h2><ul><li>Traces: NYC cellular traces set the downstream bandwidth; each is measured from 5 seconds into the trace until 5 seconds before its end.</li><li>Network: emulated by tunulator, which sits between the client and the server and plays back the trace as the downstream bandwidth, with 60ms base RTT, a queue of 60ms at the trace\'s peak one-second-bin rate, and no random loss.</li><li>Queue disciplines: tail drop, and {codel_label} with ECN.</li></ul>',
    '<p>Goodput is plaintext delivered to the application; its utilization is a few percent below that of IP forwarded, as both divide by the IP capacity, counted in IP bytes including headers and TLS or QUIC overhead. Not delivered is the share of IP bytes received by tunulator but not forwarded; it includes packets remaining in tunulator at cutoff, while CE-marked packets are forwarded.</p>',
    '<p>Delay is measured for every 15000th byte of the stream: from when tunulator first received a packet carrying it to when the client received it, so it includes propagation, queueing, loss recovery and head-of-line blocking.</p>',
    '<h2>Aggregate comparison</h2><p>Aggregate tables weight each trace equally: goodput, IP forwarded and not delivered are averages of the per-trace values, and delay statistics are computed over the samples of all traces, weighted so that every trace counts equally.</p>']
if settings is not None:
    cpus = settings['cpus']
    mode = ('Unpinned sequential execution' if cpus == [None] else
            f'CPU-pinned execution: up to {len(cpus)} concurrent workers on logical CPUs ' + ', '.join(map(str, cpus)))
    if settings['smoke']:
        mode += '; two-second smoke captures (not full-trace measurements)'
    page.insert(5, '<p>' + html.escape(mode) + '.</p>')
noabe = any(any(k.endswith('_off') for k in rows) for rows in data.values())
for condition in ['tail', 'codel']:
    expected = list(policies) if condition == 'codel' and noabe else list(policies)[:4]
    matched = [tid for tid in traces if all(k in data.get((tid, condition), {}) for k in expected)]
    page.append(f'<h3>{"Tail drop" if condition == "tail" else "CoDel ECN"}: {len(matched)} matched traces</h3>')
    if matched:
        # each trace is weighted equally: metrics are averaged across traces, and each trace's delay samples carry a total
        # weight of one
        stats = {}
        for k in expected:
            per_trace = [metrics(data[(tid, condition)][k], traces[tid]['duration_ms'], traces[tid]['IP_capacity_bytes'])
                         for tid in matched]
            stats[k] = {f: sum(m[f] for m in per_trace) / len(matched) for f in per_trace[0] if f != 'delay'}
            latencies = [data[(tid, condition)][k]['latency'] for tid in matched]
            stats[k]['delay'] = delay_stats(sorted((d, 1 / len(l)) for l in latencies for d in l)) if all(latencies) else None
        page.append(table(stats))
for tid, trace in traces.items():
    entries = map(int, (root / 'traces' / tid).read_text().splitlines())
    capacity, total = [(trace['start_ms'], 0)], 0
    for ms in entries:
        if trace['start_ms'] <= ms < trace['end_ms']:
            total += 1500
            capacity.append((ms, total))
    capacity.append((trace['end_ms'], total))
    assert total == trace['IP_capacity_bytes']
    page.append('<hr><h2>' + html.escape(tid) + '</h2><div class="pair">')
    for condition in ['tail', 'codel']:
        rows = data.get((tid, condition), {})
        page.append('<section class="panel"><h3>' + ('Tail drop' if condition == 'tail' else 'CoDel ECN') + '</h3>')
        if rows:
            selected = {k: v for k, v in policies.items() if k in rows}
            folder = root / 'plots' / tid / condition
            styles = {k: '7 4' for k in rows if k.endswith('_off')}
            for column in [1, 2]:
                charts.chart(folder, trace, rows, selected, column, capacity, styles)
            names = ['delivery', 'forwarded']
            if any(rows[k]['latency'] for k in selected):
                charts.delay_density(folder, rows, selected, styles)
                names.append('delay')
            page.append(table({k: metrics(rows[k], trace['duration_ms'], trace['IP_capacity_bytes']) for k in rows}))
            for name in names:
                page.append(f'<img src="plots/{html.escape(tid)}/{condition}/{name}.svg" alt="{name}">')
        page.append('</section>')
    page.append('</div>')
charts.write(root / 'index.html', ''.join(page))
print(root / 'index.html')
