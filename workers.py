"""Shared CPU-to-network mapping for isolated benchmark workers."""
import argparse
import fcntl
import os
from pathlib import Path


def parse_cpus(value):
    try:
        cpus = []
        for part in value.split(','):
            ends = list(map(int, part.split('-')))
            if any(c < 0 or c > 253 for c in ends):
                raise ValueError()
            if len(ends) == 1:
                cpus.append(ends[0])
            elif len(ends) == 2 and ends[0] <= ends[1]:
                cpus.extend(range(ends[0], ends[1] + 1))
            else:
                raise ValueError()
        if not cpus or len(set(cpus)) != len(cpus) or any(c < 0 or c > 253 for c in cpus):
            raise ValueError()
        if not set(cpus) <= os.sched_getaffinity(0):
            raise ValueError('CPU is not available in this process affinity mask')
        return cpus
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e) or 'Use unique CPU IDs/ranges from 0 through 253')


def worker(cpu):
    return dict(cpu=cpu, tun=f'tun{cpu}', peer=f'192.0.2.{cpu + 1}', port=20000 + cpu)


def acquire_lock(name):
    # Shared across checkouts; never unlink a lock inode while it might be held.
    root = Path('/tmp') / f'quicly-ccbench-{os.getuid()}'
    root.mkdir(mode=0o700, exist_ok=True)
    lock = (root / (name + '.lock')).open('a')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lock.close()
        raise RuntimeError(f'Benchmark resource is already in use: {name}') from None
    return lock
