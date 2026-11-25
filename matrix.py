"""Fresh-host matrix with optional isolated, CPU-pinned parallel workers."""
import argparse
from collections import deque
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from workers import parse_cpus

# Earlier builds of hq_server whose completed runs are kept on resume: the build before blackhole detection was disabled,
# which differs only in closing a connection after 2 TLPs and 5 RTOs without progress; none of its kept runs was closed.
EARLIER_HQ_SERVER_SHA256 = {'da990e15b79e8035c719330391bc4909e57305c6105194aef1da115221cb509b'}


def parse_quic_cc(value):
    """Parses CC[+abe][+abba][+l4s][+txtime][+rapid] into (CC, abe, abba, l4s, txtime, rapid)."""
    cc, *features = value.split('+')
    if cc not in ('cubic', 'cuback', 'pico') or not set(features) <= {'abe', 'abba', 'l4s', 'txtime', 'rapid'} or \
            len(set(features)) != len(features):
        raise argparse.ArgumentTypeError(f'invalid QUIC policy: {value}')
    if 'abba' in features and cc == 'pico':
        raise argparse.ArgumentTypeError('ABBA applies only to cubic and cuback')
    if 'l4s' in features and cc != 'cuback':
        raise argparse.ArgumentTypeError('L4S applies only to cuback')
    return cc, 'abe' in features, 'abba' in features, 'l4s' in features, 'txtime' in features, 'rapid' in features


def quic_cc_name(cc, abe, abba, l4s, txtime, rapid):
    return cc + ('+abe' if abe else '') + ('+abba' if abba else '') + ('+l4s' if l4s else '') + ('+txtime' if txtime else '') + \
        ('+rapid' if rapid else '')


def parse_tcp_cc(value):
    """Parses NAME[=DIR] into (NAME, DIR); DIR is the checkout from which the kernel module tcp_NAME was built and loaded."""
    name, sep, source = value.partition('=')
    if not name.isidentifier() or name in ('cubic', 'bbr') or (sep and not source):
        raise argparse.ArgumentTypeError(f'invalid TCP CC to add (CUBIC and BBR always run): {value}')
    return name, Path(source) if source else None


def parse_quiche_cc(value):
    """Parses NAME=DIR into (NAME, DIR); DIR is the checkout of Google QUICHE in which quiche/build-quiche.sh built hq_server."""
    name, sep, source = value.partition('=')
    if name != 'bbr3' or not source:
        raise argparse.ArgumentTypeError(f'invalid QUICHE CC (hq_server runs bbr3 only), expected bbr3=DIR: {value}')
    return name, Path(source)


CONDITIONS = ('tail', 'codel', 'dualpi2')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--traces', type=Path, required=True)
    p.add_argument('--build', type=Path, required=True)
    p.add_argument('--noabe-build', type=Path)
    p.add_argument('--codel', action='append',
                   help='CoDel target:interval in ms for the CoDel conditions; repeat for several (default: 5:100)')
    p.add_argument('--quic-cc', action='append', type=parse_quic_cc,
                   help='QUIC policy CC[+abe][+abba][+l4s][+txtime][+rapid], CC being cubic, cuback or pico; +txtime requires '
                        '--cpus; +rapid uses Jump Start and Rapid Start; '
                        'repeat for several '
                        '(default: cubic+abe and cubic+abe+abba)')
    p.add_argument('--no-tcp', action='store_true', help='Run the QUIC policies only, without TCP CUBIC and BBR')
    p.add_argument('--tcp-cc', action='append', type=parse_tcp_cc,
                   help='TCP CC to run in addition to CUBIC and BBR, as NAME, or NAME=DIR when it is the kernel module tcp_NAME '
                        'built and loaded from the checkout DIR, whose commit is then recorded; repeat for several')
    p.add_argument('--quiche-cc', action='append', type=parse_quiche_cc,
                   help='QUICHE policy to run, as bbr3=DIR, DIR being the checkout of Google QUICHE in which '
                        'quiche/build-quiche.sh built hq_server, whose commit is then recorded')
    p.add_argument('--dualpi2-device', type=int, default=0,
                   help='Device buffer between DualPI2 and the link, in packets, for the dualpi2 condition (default: none)')
    p.add_argument('--condition', action='append', choices=CONDITIONS,
                   help='Queue condition; repeat for several (default: tail and codel)')
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
    if any(txtime for *_, txtime, _ in quic_ccs) and a.cpus is None:
        p.error('QUIC policies with +txtime require --cpus')
    if any(not abe for _, abe, *_ in quic_ccs) and a.noabe_build is None:
        p.error('QUIC policies without +abe require --noabe-build')
    tcp_sources = dict(a.tcp_cc or [])
    if len(tcp_sources) != len(a.tcp_cc or []):
        p.error('Each TCP CC can be added once')
    if tcp_sources and a.no_tcp:
        p.error('--tcp-cc adds TCP CCs, which --no-tcp leaves out')
    quiche_sources = dict(a.quiche_cc or [])
    if len(quiche_sources) != len(a.quiche_cc or []):
        p.error('Each QUICHE CC can be added once')
    selected = sorted(set(a.condition or ['tail', 'codel']), key=CONDITIONS.index)
    # (directory, condition, setting); runs of each CoDel setting and of each DualPI2 device buffer size are in directories named
    # after it
    conditions = [('tail', 'tail', None)] if 'tail' in selected else []
    if 'codel' in selected:
        conditions += [(f"codel-{codel.replace(':', '-')}", 'codel', codel) for codel in codels]
    if 'dualpi2' in selected:
        device = a.dualpi2_device
        conditions += [(f'dualpi2-dev{device}' if device else 'dualpi2', 'dualpi2', device or None)]
    a.output.mkdir(parents=True, exist_ok=True)
    output_lock = (a.output / 'matrix.lock').open('a')
    fcntl.flock(output_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    # Pin the controller/reporting process to CPUs excluded from the workers when possible.
    controller_cpus = sorted(os.sched_getaffinity(0) - set(a.cpus or []))
    # The kernel is not a matrix setting: each run records the kernel it was measured on in its metadata.
    signature = dict(cpus=cpus, traces=[t.name for t in traces], smoke=a.smoke,
                     dry_run=a.dry_run, noabe=bool(a.noabe_build),
                     controller_cpus=controller_cpus,
                     quic_cc=[quic_cc_name(*c) for c in quic_ccs], codel=codels, conditions=selected, tcp=not a.no_tcp,
                     tcp_cc=list(tcp_sources), quiche_cc=list(quiche_sources), dualpi2_device=a.dualpi2_device)
    manifest = a.output / 'matrix-settings.json'
    write_manifest = not manifest.exists()
    if manifest.exists():
        stored = json.loads(manifest.read_text())
        previous = dict(stored)
        previous.setdefault('quic_cc', 'cubic')  # Older matrices used CUBIC exclusively.
        previous.setdefault('codel', '5:100')  # Older matrices used the fixed CoDel setting.
        previous.setdefault('conditions', ['tail', 'codel'])  # Older matrices had tail drop and CoDel only.
        previous.setdefault('tcp', True)  # Older matrices always ran TCP.
        previous.setdefault('tcp_cc', [])  # Older matrices ran TCP CUBIC and BBR only.
        previous.setdefault('quiche_cc', [])  # Older matrices ran no QUICHE policies.
        previous.setdefault('dualpi2_device', 0)  # Older matrices had no device buffer.
        previous.pop('kernel', None)  # Older matrices recorded the kernel as a setting.
        if isinstance(previous['codel'], str):  # Older matrices had one CoDel setting.
            previous['codel'] = [previous['codel']]
        # CoDel settings, TCP CCs and QUICHE CCs can be added to an existing root
        for key in ('codel', 'tcp_cc', 'quiche_cc'):
            assert previous[key] == signature[key][:len(previous[key])], 'Matrix settings changed; use a fresh output root'
            previous[key] = signature[key]
        assert previous == signature, 'Matrix settings changed; use a fresh output root'
        write_manifest = stored != signature
    (a.output / 'matrix.pid').write_text(str(os.getpid()) + '\n')
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    signal.signal(signal.SIGINT, lambda *_: sys.exit(130))
    jobs = {cpu: deque() for cpu in cpus}
    trace_info = {}
    for trace in traces:
        raw = trace.read_bytes()
        trace_info[trace] = (int(raw.splitlines()[-1]), hashlib.sha256(raw).hexdigest())
    # jobs to run are assigned to the CPUs in turn, so that those of a resume are spread over all CPUs too
    job_index = 0
    for trace in sorted(traces, key=lambda t: trace_info[t][0]):
        for directory, condition, setting in conditions:
            codel = setting if condition == 'codel' else None
            device = setting if condition == 'dualpi2' else None
            queue = {'tail': 'fifo', 'codel': f'codel:{codel}', 'dualpi2': f'dualpi2:{device}' if device else 'dualpi2'}[condition]
            # ABE only changes the response to ECN marks, so it is omitted under tail drop
            quic = [(cc, abe and condition != 'tail', abba, l4s, txtime, rapid) for cc, abe, abba, l4s, txtime, rapid in quic_ccs]
            policies = [] if a.no_tcp else [('tcp', cc, False, False, False, False, False)
                                            for cc in ['cubic', 'bbr', *tcp_sources]]
            policies += [('quic', *c) for c in dict.fromkeys(quic)]
            policies += [('quiche', cc, False, False, False, False, False) for cc in quiche_sources]
            for protocol, cc, abe, abba, l4s, txtime, rapid in policies:
                policy = protocol + '_' + (quic_cc_name(cc, abe, abba, l4s, txtime, rapid) if protocol == 'quic' else cc)
                # hq_server is built in the QUICHE checkout; the other binaries are those of the build
                binaries = {'hq_server': quiche_sources[cc] / 'bazel-bin' / 'ccbench' / 'hq_server'} if protocol == 'quiche' else {}
                build = a.noabe_build if protocol == 'quic' and condition != 'tail' and not abe else a.build
                out = a.output / trace.name.removeprefix('trace-') / directory / policy
                if (out / 'result.json').exists():
                    m = json.loads((out / 'metadata.json').read_text())
                    json.loads((out / 'result.json').read_text())
                    assert (out / 'curves.csv').is_file(), f'Missing curves: {out}'
                    assert not m['dry_run'] and not a.dry_run
                    assert m['trace_sha256'] == trace_info[trace][1]
                    # runs predating --abe used the codel_noabe condition for ABE off, and had ABE on under codel otherwise
                    recorded_abe = m.get('abe', m['protocol'] == 'quic' and m['condition'] == 'codel')
                    recorded_condition = 'codel' if m['condition'] == 'codel_noabe' else m['condition']
                    assert (m['protocol'], m['cc'], m['abba'], recorded_abe, m.get('l4s', False), m.get('txtime', m.get('fq', False)),
                            recorded_condition, m['queue'], m['rapid_start']) == \
                        (protocol, cc, abba, abe, l4s, txtime, condition, queue, rapid)
                    assert m['start_ms'] == 5000
                    assert m['end_ms'] == (7000 if a.smoke else trace_info[trace][0] - 5000)
                    for binary, digest in m['binary_sha256'].items():
                        if Path(binary).name == 'hq_server' and digest in EARLIER_HQ_SERVER_SHA256:
                            continue
                        path = binaries.get(Path(binary).name, build / Path(binary).name)
                        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest, f'Binary changed: {path}'
                    print('Already complete:', out, flush=True)
                    continue
                assert not out.exists(), f'Preserve incomplete directory outside result root before resuming: {out}'
                cpu = cpus[job_index % len(cpus)]
                job_index += 1
                command = [sys.executable, str(kit / 'run-one.py'), protocol, '--cc', cc,
                           '--trace', str(trace), '--queue', queue, '--condition', condition,
                           '--build', str(build), '--output', str(out), '--latency']
                if codel is not None:
                    command += ['--codel', codel]
                if device is not None:
                    command += ['--dualpi2-device', str(device)]
                if cpu is not None:
                    command += ['--cpu', str(cpu)]
                if abba:
                    command += ['--abba']
                if abe:
                    command += ['--abe']
                if l4s:
                    command += ['--l4s']
                if txtime:
                    command += ['--txtime']
                if rapid:
                    command += ['--rapid-start']
                if protocol == 'tcp' and tcp_sources.get(cc) is not None:
                    command += ['--cc-source', str(tcp_sources[cc])]
                if protocol == 'quiche':
                    command += ['--quiche', str(quiche_sources[cc])]
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
