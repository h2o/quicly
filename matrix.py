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
from workers import parse_cpus, worker


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--traces', type=Path, required=True)
    p.add_argument('--build', type=Path, required=True)
    p.add_argument('--noabe-build', type=Path)
    p.add_argument('--codel', action='append',
                   help='CoDel target:interval in ms for codel/codel_noabe conditions; repeat for several (default: 5:100)')
    p.add_argument('--quic-cc', choices=['cubic', 'cuback'], default='cubic',
                   help='QUIC controller (default: cubic); startup and IW30 remain unchanged')
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
    # (directory, condition, CoDel setting, build); runs of each CoDel setting are in directories named after it
    conditions = [('tail', 'tail', None, a.build)]
    for codel in codels:
        conditions.append((f"codel-{codel.replace(':', '-')}", 'codel', codel, a.build))
        if a.noabe_build:
            conditions.append((f"codel_noabe-{codel.replace(':', '-')}", 'codel_noabe', codel, a.noabe_build))
    a.output.mkdir(parents=True, exist_ok=True)
    output_lock = (a.output / 'matrix.lock').open('a')
    fcntl.flock(output_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    # Pin the controller/reporting process to CPUs excluded from the workers when possible.
    controller_cpus = sorted(os.sched_getaffinity(0) - set(a.cpus or []))
    signature = dict(cpus=cpus, traces=[t.name for t in traces], smoke=a.smoke,
                     dry_run=a.dry_run, noabe=bool(a.noabe_build),
                     controller_cpus=controller_cpus, kernel=platform.release(), quic_cc=a.quic_cc, codel=codels)
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
    # Jobs of the first CoDel setting come first, so that adding a setting does not change the CPUs assigned to existing runs.
    groups = [[c for c in conditions if c[2] in (None, codels[0])]]
    groups += [[c for c in conditions if c[2] == codel] for codel in codels[1:]]
    for group in groups:
        for trace in sorted(traces, key=lambda t: trace_info[t][0]):
            for directory, condition, codel, build in group:
                queue = 'fifo' if codel is None else f'codel:{codel}'
                policies = [('tcp', 'cubic', False), ('tcp', 'bbr', False),
                            ('quic', a.quic_cc, False), ('quic', a.quic_cc, True)]
                if condition == 'codel_noabe':
                    policies = policies[2:]
                for protocol, cc, abba in policies:
                    cpu = cpus[job_index % len(cpus)]
                    job_index += 1
                    policy = protocol + '_' + cc + ('_abba' if abba else '')
                    out = a.output / trace.name.removeprefix('trace-') / directory / policy
                    if (out / 'result.json').exists():
                        m = json.loads((out / 'metadata.json').read_text())
                        json.loads((out / 'result.json').read_text())
                        assert (out / 'curves.csv').is_file(), f'Missing curves: {out}'
                        assert not m['dry_run'] and not a.dry_run
                        assert m['kernel'] == signature['kernel'], f'Kernel changed: {out}'
                        assert m['trace_sha256'] == trace_info[trace][1]
                        assert (m['protocol'], m['cc'], m['abba'], m['condition'], m['queue'], m['rapid_start']) == (protocol, cc, abba, condition, queue, False)
                        assert m['start_ms'] == 5000
                        assert m['end_ms'] == (7000 if a.smoke else trace_info[trace][0] - 5000)
                        if cpu is not None:
                            assert m['worker'] == worker(cpu)
                        else:
                            assert m['worker']['cpu'] is None
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
    for build in dict.fromkeys(build.resolve() for _, _, _, build in conditions):
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
