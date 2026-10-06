"""Fresh-host matrix with optional isolated, CPU-pinned parallel workers."""
import argparse
from collections import deque
import fcntl
import hashlib
import json
import os
import platform
from pathlib import Path
import signal
import subprocess
import sys
import time
from workers import parse_cpus


def parse_quic_cc(value):
    """Parses CC[+abe][+abba] into (CC, abe, abba)."""
    cc, *features = value.split('+')
    if cc not in ('cubic', 'cuback', 'pico') or not set(features) <= {'abe', 'abba'} or len(set(features)) != len(features):
        raise argparse.ArgumentTypeError(f'invalid QUIC policy: {value}')
    if 'abba' in features and cc == 'pico':
        raise argparse.ArgumentTypeError('ABBA applies only to cubic and cuback')
    return cc, 'abe' in features, 'abba' in features


def quic_cc_name(cc, abe, abba):
    return cc + ('+abe' if abe else '') + ('+abba' if abba else '')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--traces', type=Path, required=True)
    p.add_argument('--build', type=Path, required=True)
    p.add_argument('--noabe-build', type=Path)
    p.add_argument('--codel', action='append',
                   help='CoDel target:interval in ms for the CoDel conditions; repeat for several (default: 5:100)')
    p.add_argument('--quic-cc', action='append', type=parse_quic_cc,
                   help='QUIC policy CC[+abe][+abba], CC being cubic, cuback or pico; repeat for several '
                        '(default: cubic+abe and cubic+abe+abba)')
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--smoke', action='store_true', help='Two-second taxi3 runs')
    p.add_argument('--trace-id', action='append', help='Only this trace ID; repeat to select several')
    p.add_argument('--cpus', type=parse_cpus, help='One worker per logical CPU, e.g. 1-15 or 2,4,8-15')
    p.add_argument('--dry-run', action='store_true', help='Write commands/metadata, without captures or reports')
    a = p.parse_args()
    kit = Path(__file__).resolve().parent
    traces = sorted(t for t in a.traces.glob('trace-*') if t.name != 'trace-info')
    if a.trace_id:
        wanted = set(a.trace_id)
        traces = [t for t in traces if t.name.removeprefix('trace-') in wanted]
        if {t.name.removeprefix('trace-') for t in traces} != wanted:
            p.error('Selected trace is missing')
    elif not a.smoke:
        assert len(traces) == 23, f'Expected 23 cellular traces, found {len(traces)}'
    if a.smoke:
        traces = [t for t in traces if t.name == 'trace-2768760-taxi3']
    if not traces:
        p.error('No traces selected')
    cpus = a.cpus if a.cpus is not None else [None]
    codels = a.codel or ['5:100']
    quic_ccs = a.quic_cc or [parse_quic_cc('cubic+abe'), parse_quic_cc('cubic+abe+abba')]
    if any(not abe for _, abe, _ in quic_ccs) and a.noabe_build is None:
        p.error('QUIC policies without +abe require --noabe-build')
    # (directory, condition, CoDel setting); runs of each CoDel setting are in directories named after it
    conditions = [('tail', 'tail', None)] + [(f"codel-{codel.replace(':', '-')}", 'codel', codel) for codel in codels]
    a.output.mkdir(parents=True, exist_ok=True)
    output_lock = (a.output / 'matrix.lock').open('a')
    fcntl.flock(output_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    # Pin the controller/reporting process to CPUs excluded from the workers when possible.
    controller_cpus = sorted(os.sched_getaffinity(0) - set(a.cpus or []))
    signature = dict(cpus=cpus, traces=[t.name for t in traces], smoke=a.smoke,
                     dry_run=a.dry_run, noabe=bool(a.noabe_build),
                     controller_cpus=controller_cpus, kernel=platform.release(),
                     quic_cc=[quic_cc_name(*c) for c in quic_ccs], codel=codels)
    manifest = a.output / 'matrix-settings.json'
    write_manifest = not manifest.exists()
    if manifest.exists():
        previous = json.loads(manifest.read_text())
        previous.setdefault('quic_cc', 'cubic')  # Older matrices used CUBIC exclusively.
        previous.setdefault('codel', '5:100')  # Older matrices used the fixed CoDel setting.
        if isinstance(previous['codel'], str):  # Older matrices had one CoDel setting.
            previous['codel'] = [previous['codel']]
        # CoDel settings can be added to an existing root
        assert previous['codel'] == codels[:len(previous['codel'])], 'Matrix settings changed; use a fresh output root'
        write_manifest = previous['codel'] != codels
        previous['codel'] = codels
        assert previous == signature, 'Matrix settings changed; use a fresh output root'
    (a.output / 'matrix.pid').write_text(str(os.getpid()) + '\n')
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    signal.signal(signal.SIGINT, lambda *_: sys.exit(130))
    jobs = {cpu: deque() for cpu in cpus}
    trace_info = {}
    for trace in traces:
        raw = trace.read_bytes()
        trace_info[trace] = (int(raw.splitlines()[-1]), hashlib.sha256(raw).hexdigest())
    job_index = 0
    for trace in sorted(traces, key=lambda t: trace_info[t][0]):
        for directory, condition, codel in conditions:
            queue = 'fifo' if codel is None else f'codel:{codel}'
            # ABE only changes the response to ECN marks, so it is omitted under tail drop
            quic = [(cc, abe and condition != 'tail', abba) for cc, abe, abba in quic_ccs]
            policies = [('tcp', 'cubic', False, False), ('tcp', 'bbr', False, False)]
            policies += [('quic', *c) for c in dict.fromkeys(quic)]
            for protocol, cc, abe, abba in policies:
                cpu = cpus[job_index % len(cpus)]
                job_index += 1
                policy = protocol + '_' + (quic_cc_name(cc, abe, abba) if protocol == 'quic' else cc)
                build = a.noabe_build if protocol == 'quic' and condition == 'codel' and not abe else a.build
                out = a.output / trace.name.removeprefix('trace-') / directory / policy
                if (out / 'result.json').exists():
                    m = json.loads((out / 'metadata.json').read_text())
                    json.loads((out / 'result.json').read_text())
                    assert (out / 'curves.csv').is_file(), f'Missing curves: {out}'
                    assert not m['dry_run'] and not a.dry_run
                    assert m['kernel'] == signature['kernel'], f'Kernel changed: {out}'
                    assert m['trace_sha256'] == trace_info[trace][1]
                    # runs predating --abe used the codel_noabe condition for ABE off, and had ABE on under codel otherwise
                    recorded_abe = m.get('abe', m['protocol'] == 'quic' and m['condition'] == 'codel')
                    recorded_condition = 'codel' if m['condition'] == 'codel_noabe' else m['condition']
                    assert (m['protocol'], m['cc'], m['abba'], recorded_abe, recorded_condition, m['queue'], m['rapid_start']) == \
                        (protocol, cc, abba, abe, condition, queue, False)
                    assert m['start_ms'] == 5000
                    assert m['end_ms'] == (7000 if a.smoke else trace_info[trace][0] - 5000)
                    for binary, digest in m['binary_sha256'].items():
                        assert hashlib.sha256((build / Path(binary).name).read_bytes()).hexdigest() == digest
                    print('Already complete:', out, flush=True)
                    continue
                assert not out.exists(), f'Preserve incomplete directory outside result root before resuming: {out}'
                command = [sys.executable, str(kit / 'run-one.py'), protocol, '--cc', cc,
                           '--trace', str(trace), '--queue', queue, '--condition', condition,
                           '--build', str(build), '--output', str(out), '--latency']
                if codel is not None:
                    command += ['--codel', codel]
                if cpu is not None:
                    command += ['--cpu', str(cpu)]
                if abba:
                    command += ['--abba']
                if abe:
                    command += ['--abe']
                if a.smoke:
                    command += ['--end', '7000']
                if a.dry_run:
                    command += ['--dry-run']
                jobs[cpu].append((command, out))
    # Copied completed variants are valid inputs. Record settings only after
    # validating them all, so a rejected import does not bind the output root.
    if write_manifest:
        manifest.write_text(json.dumps(signature, indent=2) + '\n')
    # Finish shared provenance preparation before any capture workers can read it.
    for build in dict.fromkeys(b.resolve() for b in (a.build, a.noabe_build) if b is not None):
        subprocess.run([sys.executable, str(kit / 'record-build.py'), '--build', str(build)], check=True)
    original_affinity = os.sched_getaffinity(0)
    active = {}
    report = None
    try:
        while any(jobs.values()) or active:
            for cpu in cpus:
                if cpu in active:
                    proc, log, out = active[cpu]
                    status = proc.poll()
                    if status is None:
                        continue
                    log.close()
                    del active[cpu]
                    if status:
                        raise RuntimeError(f'Capture failed ({status}): {out}; see runner log')
                    print('Completed:', out, flush=True)
                if jobs[cpu]:
                    command, out = jobs[cpu].popleft()
                    logdir = a.output / 'runner-logs'
                    logdir.mkdir(exist_ok=True)
                    log = (logdir / ('__'.join(out.relative_to(a.output).parts) + '.log')).open('a')
                    # Child runner must inherit access to its assigned CPU; it pins itself before launching endpoints.
                    os.sched_setaffinity(0, original_affinity)
                    try:
                        proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                    except BaseException:
                        log.close()
                        raise
                    active[cpu] = (proc, log, out)
                    if a.cpus and controller_cpus:
                        os.sched_setaffinity(0, controller_cpus)
                    print(f'Started CPU {cpu}: {out}', flush=True)
            time.sleep(0.1)
        # Render once captures finish to avoid report CPU/I/O load during measurements.
        if not a.dry_run:
            report = subprocess.Popen([sys.executable, str(kit / 'report.py'), str(a.output)])
            if report.wait():
                raise RuntimeError('Report generation failed')
    finally:
        for proc, _, _ in active.values():
            if proc.poll() is None:
                proc.terminate()
        for proc, log, _ in active.values():
            proc.wait()  # runner SIGTERM handler reaps every endpoint/emulator group
            log.close()
        if report is not None and report.poll() is None:
            report.terminate()
            report.wait()
        os.sched_setaffinity(0, original_affinity)
    print('Complete:', a.output, flush=True)


if __name__ == '__main__':
    main()
