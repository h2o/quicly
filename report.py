"""Generate aggregate tables and paired per-trace SVGs from fresh-host runs."""
import argparse
from array import array
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import csv
import functools
import html
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import charts

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('output', type=Path)
a = p.parse_args()
root = a.output.resolve()
settings_path = root / 'matrix-settings.json'
settings = json.loads(settings_path.read_text()) if settings_path.exists() else None
# QUIC policies are named CC[+abe][+abba]; the color is chosen by the controller and ABBA, as ABE is told apart by the dash
quic_colors = {('cubic', False): '#1f77b4', ('cubic', True): '#d62728', ('cuback', False): '#ff7f0e',
               ('cuback', True): '#8c564b', ('pico', False): '#e377c2'}
# The QUIC policies given to the matrix, in order; only these are shown. Roots predating the list show all their QUIC runs.
quic_specs = settings['quic_cc'] if settings is not None and isinstance(settings.get('quic_cc'), list) else None

def quic_names(condition):
    """The names of the QUIC policies shown under a condition, in order; ABE is omitted under tail drop."""
    names = quic_specs if condition != 'tail' else [spec.replace('+abe', '') for spec in quic_specs]
    return list(dict.fromkeys(names))

def policy_of(m):
    """The queue condition and the policy of a run."""
    assert not m['rapid_start'], 'This matrix report requires ordinary startup'
    assert m['condition'] in ['tail', 'codel', 'codel_noabe'], 'Use a separate report for drops-only CoDel'
    if m['condition'] != 'tail' and not m['queue'].startswith('codel:'):
        p.error(f"Expected ECN-capable CoDel queue: {m['queue']}")
    condition = 'tail' if m['condition'] == 'tail' else f"codel-{m['queue'].removeprefix('codel:').replace(':', '-')}"
    if m['protocol'] == 'tcp':
        assert m['cc'] in ('cubic', 'bbr') and not m['abba']
        return condition, 'tcp_' + m['cc']
    # ABE only changes the response to ECN marks, so it is ignored under tail drop; runs predating the abe key used the
    # codel_noabe condition for ABE off
    abe = m['condition'] == 'codel' and m.get('abe', True)
    assert (m['cc'], m['abba']) in quic_colors, 'Unsupported QUIC controller'
    return condition, 'quic_' + m['cc'] + ('+abe' if abe else '') + ('+abba' if m['abba'] else '')

# (directory, metadata, condition, policy) of each run shown
runs = []
for path in sorted(root.glob('*/*/*/result.json')):
    m = json.loads((path.parent / 'metadata.json').read_text())
    if m.get('dry_run'):
        continue
    condition, policy = policy_of(m)
    if quic_specs is None or not policy.startswith('quic_') or policy.removeprefix('quic_') in quic_names(condition):
        runs.append((path.parent, m, condition, policy))
codel_settings = set()
@functools.cache
def tree_of(commit, diff):
    """The git tree a build was made from, i.e., the recorded commit with the recorded diff applied."""
    if not diff:
        return subprocess.check_output(['git', 'rev-parse', commit + '^{tree}'], text=True).strip()
    with tempfile.TemporaryDirectory() as tmp:
        env = dict(os.environ, GIT_INDEX_FILE=os.path.join(tmp, 'index'))
        subprocess.run(['git', 'read-tree', commit], env=env, check=True)
        subprocess.run(['git', 'apply', '--cached'], input=diff, text=True, env=env, check=True)
        return subprocess.check_output(['git', 'write-tree'], env=env, text=True).strip()

def source_label(b, run):
    """The commit whose tree a build was made from; if none, the base commit and where its diff is recorded."""
    tree = tree_of(b['commit'], b['source_diff'])
    if tree not in commits_by_tree:
        return f"{b['commit'][:8]} with the changes recorded in {run.relative_to(root)}/metadata.json (tree {tree[:8]})"
    return commits_by_tree[tree][:8]

commits_by_tree = {}
for line in subprocess.check_output(['git', 'log', '--all', '--reverse', '--format=%H %T'], text=True).splitlines():
    commit, tree = line.split()
    commits_by_tree.setdefault(tree, commit)

# environment of the runs: for each item, the number of runs with each value
environment = {'quicly': Counter(), 'Kernel': Counter()}
for run, m, condition, policy in runs:
    environment['quicly'][source_label(m['build_metadata'], run)] += 1
    environment['Kernel'][m['kernel']] += 1
    if condition != 'tail':
        codel_settings.add(m['queue'].removeprefix('codel:'))
if settings is not None:
    codel_settings.update([settings['codel']] if isinstance(settings.get('codel'), str) else settings.get('codel', ['5:100']))
codel_settings = sorted(codel_settings, key=lambda c: tuple(map(int, c.split(':'))))
# (key, label) of each queue condition; the key names the plot directory
conditions = [('tail', 'Tail drop')] + [(f"codel-{c.replace(':', '-')}", f'CoDel {c} ECN') for c in codel_settings]
# latency.py processes each run with --latency; do it before reading, in parallel, as all captures have completed
latency_runs = [run for run, *_ in runs if (run / 'tunulator.pktlog').exists() and not (run / 'latency.csv').exists()]
with ThreadPoolExecutor(os.cpu_count()) as pool:
    list(pool.map(lambda run: subprocess.run([sys.executable, str(Path(__file__).with_name('latency.py')), str(run)],
                                             stdout=subprocess.DEVNULL, check=True), latency_runs))

def read_latency(run):
    """Sorted per-sample delays (ms) of a run, or None if not measured."""
    if not (run / 'latency.csv').exists():
        return None
    with (run / 'latency.csv').open() as f:
        return array('d', sorted(float(row['latency_ms']) for row in csv.DictReader(f)))

data, traces = {}, {}
for run, m, condition, policy in runs:
    r = json.loads((run / 'result.json').read_text())
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
        downstream_IP_received=r['IP_received'], latency=read_latency(run), run=str(run.relative_to(root)),
        metadata=m)
    folder = root / 'plots' / tid / condition
    folder.mkdir(parents=True, exist_ok=True)
    with (run / 'curves.csv').open() as src, (folder / (policy + '.dat')).open('w') as dst:
        for row in csv.DictReader(src):
            ms = m['start_ms'] + round(float(row['elapsed_seconds']) * 1000)
            dst.write(f"{ms} {row['application_bytes']} {row['IP_forwarded']} {row['IP_received']}\n")
    saved_trace = root / 'traces' / tid
    if not saved_trace.exists():
        saved_trace.parent.mkdir(exist_ok=True)
        shutil.copy2(m['trace_path'], saved_trace)

# QUIC policies are in the order given to the matrix, under each condition; roots predating that order are ordered by
# controller, ABBA and ABE
present = {policy.removeprefix('quic_') for *_, policy in runs if policy.startswith('quic_')}
if quic_specs is not None:
    # each spec followed by its tail-drop name, so that the order holds under every condition
    names = [name for spec in quic_specs for name in (spec, spec.replace('+abe', ''))]
    quic_policies = sorted(present, key=names.index)
else:
    quic_policies = sorted(present, key=lambda name: (list(quic_colors).index((name.split('+')[0], '+abba' in name)),
                                                      '+abe' not in name))
policies = {'tcp_cubic': ('TCP CUBIC', '#2ca02c'), 'tcp_bbr': ('TCP BBR', '#9467bd')}
for name in quic_policies:
    policies['quic_' + name] = ('QUIC ' + name.upper(), quic_colors[(name.split('+')[0], '+abba' in name)])
quic_labels = [label for k, (label, _) in policies.items() if k.startswith('quic_')]

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

page = ['<!doctype html><meta charset="utf-8"><title>Fresh-host CC benchmark</title>',
    '<style>body{font:16px system-ui;margin:2em}table{border-collapse:collapse}td,th{padding:.4em;border-bottom:1px solid #ddd;text-align:right}td:first-child,th:first-child{text-align:left}.panel{overflow:auto}img{width:100%;max-width:1000px}</style>',
    '<h1>Congestion-control trace benchmark</h1>',
    f'<h2>Policies</h2><ul><li>TCP CUBIC, TCP BBR: the host kernel\'s implementations, over TLS, with pacing and an initial window of 30.</li><li>{html.escape(', '.join(quic_labels))}: quicly with an initial window of 30, pacing, ordinary startup (no Rapid Start or Jump Start), and a 1472-byte UDP payload. Each is named by the congestion controller, followed by +ABE when built with QUICLY_USE_ABE=1 (otherwise 0), and +ABBA when ABBA is enabled. ABE only affects the response to ECN marks, so it is omitted under tail drop; in the CoDel charts, policies without ABE are dashed.</li></ul>',
    f'<h2>Scenarios</h2><ul><li>Traces: <a href="https://github.com/Soheil-ab/Cellular-Traces-NYC">NYC cellular traces</a> set the downstream bandwidth; each is measured from 5 seconds into the trace until 5 seconds before its end.</li><li>Network: emulated by tunulator, which sits between the client and the server and plays back the trace as the downstream bandwidth, with 60ms base RTT, a queue of 60ms at the trace\'s peak one-second-bin rate, and no random loss.</li><li>Queue disciplines: tail drop, and CoDel {html.escape(' and '.join(codel_settings))} (target:interval in ms) with ECN.</li></ul>',
    '<p>Goodput is plaintext delivered to the application; its utilization is a few percent below that of IP forwarded, as both divide by the IP capacity, counted in IP bytes including headers and TLS or QUIC overhead. Not delivered is the share of IP bytes received by tunulator but not forwarded; it includes packets remaining in tunulator at cutoff, while CE-marked packets are forwarded.</p>',
    '<p>Delay is measured for every 15000th byte of the stream: from when tunulator first received a packet carrying it to when the client received it, so it includes propagation, queueing, loss recovery and head-of-line blocking.</p>',
    '<hr><h2>Aggregate comparison</h2><p>Aggregate tables weight each trace equally: goodput, IP forwarded and not delivered are averages of the per-trace values, and delay statistics are computed over the samples of all traces, weighted so that every trace counts equally.</p>']
if settings is not None and settings['smoke']:
    page.insert(5, '<p>These are two-second smoke captures, not full-trace measurements.</p>')
items = []
for name, values in environment.items():
    text = ', '.join(v + (f' ({n} runs)' if len(values) > 1 else '') for v, n in values.most_common())
    items.append(f'<li>{html.escape(name)}: {html.escape(text)}</li>')
page.insert(5, '<h2>Environment</h2><ul>' + ''.join(items) + '</ul>')
for condition, label in conditions:
    present = {k for (tid, c), rows in data.items() if c == condition for k in rows}
    expected = [k for k in policies if k in present]
    matched = [tid for tid in traces if all(k in data.get((tid, condition), {}) for k in expected)]
    page.append(f'<h3>{label}: {len(matched)} matched traces</h3>')
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
    for condition, label in conditions:
        rows = data.get((tid, condition), {})
        page.append('<section class="panel"><h3>' + label + '</h3>')
        if rows:
            selected = {k: v for k, v in policies.items() if k in rows}
            folder = root / 'plots' / tid / condition
            styles = {k: '7 4' for k in rows if condition != 'tail' and k.startswith('quic_') and '+abe' not in k}
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
