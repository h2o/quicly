"""Short real-TUN validation: concurrent affinity/delivery, locks, SIGTERM cleanup, resume.

Run after builds and per-CPU TUN setup; output must be a new directory.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from workers import parse_cpus

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--cpus', type=parse_cpus, required=True)
p.add_argument('--build', type=Path, required=True)
p.add_argument('--noabe-build', type=Path, required=True)
p.add_argument('--traces', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=False)
kit = Path(__file__).resolve().parent
active = []
logs = []


def start(command, name):
    log = (a.output / (name + '.log')).open('w')
    logs.append(log)
    proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
    active.append(proc)
    return proc


def await_file(path, proc):
    deadline = time.monotonic() + 20
    while not path.exists():
        assert proc.poll() is None, f'Process exited {proc.returncode}: {path}'
        assert time.monotonic() < deadline, f'Timed out waiting for {path}'
        time.sleep(.05)
    # Writer may still be finishing the tiny JSON file.
    for _ in range(20):
        try:
            return json.loads(path.read_text())
        except json.JSONDecodeError:
            time.sleep(.05)
    raise AssertionError(f'Invalid JSON: {path}')


def assert_gone(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return
    raise AssertionError(f'Child process survived cleanup: {pid}')


def capture(cpu, out, end='10000'):
    return [sys.executable, str(kit / 'run-one.py'), 'quic' if cpu % 2 else 'tcp',
            '--cc', 'cubic', '--trace', str(a.traces / 'trace-2768760-taxi3'),
            '--condition', 'codel', '--queue', 'codel:5:100', '--build', str(a.build),
            '--cpu', str(cpu), '--end', end, '--output', str(out)]


try:
    for build in dict.fromkeys((a.build.resolve(), a.noabe_build.resolve())):
        subprocess.run([sys.executable, str(kit / 'record-build.py'), '--build', str(build)], check=True)
    # All workers run together, each with TCP or QUIC; inspect live child affinities.
    runs = [(cpu, a.output / f'cpu{cpu}') for cpu in a.cpus]
    procs = [start(capture(cpu, out), f'cpu{cpu}') for cpu, out in runs]
    observed = []
    for (cpu, out), proc in zip(runs, procs):
        children = await_file(out / 'processes.json', proc)
        for child in children.values():
            assert child['affinity'] == [cpu]
            assert os.sched_getaffinity(child['pid']) == {cpu}
        observed.extend(child['pid'] for child in children.values())
    # Contention must fail before creating a misleading incomplete output directory.
    conflict = a.output / 'conflict'
    proc = start(capture(a.cpus[0], conflict), 'conflict')
    assert proc.wait(timeout=10) != 0
    assert not conflict.exists()
    assert 'already in use' in (a.output / 'conflict.log').read_text()
    for (_, out), proc in zip(runs, procs):
        assert proc.wait(timeout=20) == 0
        assert json.loads((out / 'result.json').read_text())['application_bytes'] > 0
    for pid in observed:
        assert_gone(pid)
    print(f'{len(runs)} concurrent captures: affinity, delivery, lock rejection and cleanup passed', flush=True)

    matrix_base = [sys.executable, str(kit / 'matrix.py'), '--traces', str(a.traces),
                   '--build', str(a.build), '--noabe-build', str(a.noabe_build),
                   '--quic-cc', 'cubic+abe', '--quic-cc', 'cubic+abe+abba', '--quic-cc', 'cubic', '--quic-cc', 'cubic+abba',
                   '--cpus', ','.join(map(str, a.cpus[:2]))]
    interrupted = a.output / 'interrupted'
    proc = start(matrix_base + ['--trace-id', '2768760-taxi3', '--output', str(interrupted)], 'interrupt')
    children = []
    deadline = time.monotonic() + 20
    while len(children) < min(2, len(a.cpus)):
        assert proc.poll() is None
        assert time.monotonic() < deadline
        files = list(interrupted.glob('*/*/*/processes.json'))
        children = [await_file(f, proc) for f in files]
        time.sleep(.05)
    proc.send_signal(signal.SIGTERM)
    assert proc.wait(timeout=20) == 143
    for group in children:
        for child in group.values():
            assert_gone(child['pid'])
    assert not list(interrupted.glob('*/*/*/result.json'))
    print('Matrix SIGTERM: child cleanup and incomplete-run handling passed', flush=True)
    # Resume must reject incomplete output instead of overwriting it.
    proc = start(matrix_base + ['--trace-id', '2768760-taxi3', '--output', str(interrupted)], 'reject-incomplete')
    assert proc.wait(timeout=20) != 0
    assert 'Preserve incomplete directory' in (a.output / 'reject-incomplete.log').read_text()

    smoke = a.output / 'smoke'
    command = matrix_base + ['--smoke', '--output', str(smoke)]
    proc = start(command, 'smoke')
    assert proc.wait(timeout=90) == 0
    results = {str(f): f.read_bytes() for f in smoke.glob('*/*/*/result.json')}
    assert len(results) == 10
    proc = start(command, 'resume')
    assert proc.wait(timeout=20) == 0
    assert all(Path(f).read_bytes() == value for f, value in results.items())
    assert (smoke / 'index.html').exists()
    assert (a.output / 'resume.log').read_text().count('Already complete:') == 10
    print('Queued workers, ten-policy HTML and completed-run resume passed', flush=True)
    (a.output / 'validation.json').write_text(json.dumps(dict(cpus=a.cpus, passed=True), indent=2) + '\n')
finally:
    for proc in active:
        if proc.poll() is None:
            proc.terminate()
    for proc in active:
        proc.wait()
    for log in logs:
        log.close()
