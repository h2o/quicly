import argparse
from collections import Counter
import csv
import fcntl
import socket
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import time
from workers import acquire_lock, parse_cpus, worker


p = argparse.ArgumentParser()
p.add_argument("protocol", choices=["tcp", "quic"])
p.add_argument("--cc", default="cubic")
p.add_argument("--abba", action="store_true")
p.add_argument("--rapid-start", action="store_true")
p.add_argument("--condition", choices=["tail", "codel", "codel_noabe", "codel_noecn"], required=True)
p.add_argument("--dry-run", action="store_true", help="Write commands and metadata only; no sockets or TUN access")
p.add_argument("--trace", type=Path, required=True)
p.add_argument("--queue", default="fifo")
p.add_argument("--codel", default="5:100", help="CoDel target:interval in ms for codel/codel_noabe/codel_noecn conditions")
p.add_argument("--offset", type=int, default=1000)
p.add_argument("--end", type=int, help="Exclusive trace end in ms; defaults to last timestamp minus 1000")
p.add_argument("--build", type=Path, default=Path("build/ccbench"))
p.add_argument("--output", type=Path, required=True)
p.add_argument("--cpu", type=int, help="Pin all three processes to this CPU; use tunN, peer 192.0.2.(N+1), port 20000+N")
args = p.parse_args()
if args.cpu is not None:
    try:
        parse_cpus(str(args.cpu))
    except argparse.ArgumentTypeError as e:
        p.error(str(e))
lane = worker(args.cpu) if args.cpu is not None else dict(cpu=None, tun='tun0', peer='192.0.2.1', port=None)
if args.cpu is not None:
    # Pin preparation too; children inherit affinity before exec and thread creation.
    os.sched_setaffinity(0, {args.cpu})
if args.protocol == "tcp" and (args.abba or args.rapid_start or args.condition == "codel_noabe"):
    p.error("ABBA, Rapid Start, and the no-ABE variant apply only to QUIC")
expected_queue = {"tail": "fifo", "codel": f"codel:{args.codel}", "codel_noabe": f"codel:{args.codel}",
                  "codel_noecn": f"codel/noecn:{args.codel}"}
if args.queue != expected_queue[args.condition]:
    p.error("queue does not match the named condition")
trace = args.trace.resolve()
entries = [int(line) for line in trace.read_text().splitlines()]
assert entries and entries == sorted(entries) and entries[0] >= 0
end_ms = args.end if args.end is not None else entries[-1] - 1000
assert 0 <= args.offset < end_ms <= entries[-1] + 1
duration_ms = end_ms - args.offset
peak_bytes_per_second = max(Counter(ms // 1000 for ms in entries).values()) * 1500
buffer_bytes = max(1500, (peak_bytes_per_second * 60 + 999) // 1000)
capacity_bytes = sum(args.offset <= ms < end_ms for ms in entries) * 1500
build = args.build.resolve()
build_info_path = build / ".build-info-cache.json"
if not build_info_path.exists():
    subprocess.run([sys.executable, str(Path(__file__).with_name('record-build.py')),
                    '--build', str(build)], check=True)
build_info = json.loads(build_info_path.read_text())
current_hashes = {name: hashlib.sha256((build / name).read_bytes()).hexdigest()
                  for name in ('cli', 'http09', 'tunulator')}
if build_info.get('binary_sha256') != current_hashes:
    p.error('Build provenance is stale; run record-build.py --build with this build directory before capturing')
expect_abe = args.condition != "codel_noabe"
if build_info["abe_enabled"] != expect_abe:
    p.error(f"--build {build} was compiled with QUICLY_USE_ABE={'1' if build_info['abe_enabled'] else '0'}, "
            f"but --condition {args.condition} requires ABE {'enabled' if expect_abe else 'disabled'}")
out = args.output.resolve()
locks = []
if not args.dry_run:
    locks.append(acquire_lock(lane['tun']))
    if args.cpu is not None:
        locks.append(acquire_lock(f'cpu{args.cpu}'))
    if lane['tun'] == 'tun0':
        lock_path = Path("tmp/taxi3-runner.lock")
        lock_path.parent.mkdir(exist_ok=True)
        locks.append(lock_path.open("a"))
        fcntl.flock(locks[-1], fcntl.LOCK_EX | fcntl.LOCK_NB)
port = str(lane['port'] or 4433)
if not args.dry_run and lane['port'] is None:
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = str(reserve.getsockname()[1])
credentials = ["-c", "t/assets/server.crt", "-k", "t/assets/server.key"]
if args.protocol == "tcp":
    binary = build / "http09"
    options = ["-C", args.cc, "-p"]
    request = []
else:
    binary = build / "cli"
    options = ["-C", args.cc + ":30:p", "-y", "aes128gcmsha256",
               "-u", "1472", "-U", "1472", "-M", "16777216",
               "--jumpstart-default", "0", "--jumpstart-max", "0"]
    if args.abba:
        options += ["--abba"]
    if args.rapid_start:
        options[options.index("--jumpstart-default") + 1] = "60"
        del options[options.index("--jumpstart-max"):options.index("--jumpstart-max") + 2]
        options += ["--rapid-start"]
    request = ["--delivery-stats", "-p", "/10000000000"]
commands = {
    "server": [str(binary), *credentials, *options, "127.0.0.1", port],
    "tunulator": [str(build / "tunulator"), "-t", "/dev/net/tun", "-n", lane['tun'],
                  "-F", str(trace), str(args.offset), "-p", "0", "-P", "60000",
                  "-B", str(buffer_bytes), "-r", "0", "-R", "0",
                  "-Q", args.queue, lane['peer'], port],
    "client": [str(binary), *options, *request, lane['peer'], port],
}
route = "dry run: not inspected"
if not args.dry_run:
    route = subprocess.check_output(["ip", "route", "show", lane['peer'] + "/32"], text=True)
    route_fields = route.split()
    assert route_fields[route_fields.index('dev') + 1] == lane['tun'], route
    assert all(s in route for s in ["src 127.0.0.1", "initcwnd 30"]), route
    assert Path(f"/proc/sys/net/ipv4/conf/{lane['tun']}/route_localnet").read_text().strip() == '1'
    assert Path("/proc/sys/net/ipv4/tcp_ecn").read_text().strip() == "1" or "features ecn" in route
metadata = dict(protocol=args.protocol, cc=args.cc, abba=args.abba, rapid_start=args.rapid_start,
    condition=args.condition, trace_id=trace.name.split(".max=")[0].removeprefix("trace-"), trace_path=str(trace),
    queue=args.queue, dry_run=args.dry_run, build_metadata=build_info,
    commands=commands, worker=lane, route=route, kernel=platform.release(),
    commit=build_info["commit"],
    tcp_ecn=Path("/proc/sys/net/ipv4/tcp_ecn").read_text().strip(),
    trace_sha256=hashlib.sha256(trace.read_bytes()).hexdigest(),
    binary_sha256={str(b): hashlib.sha256(b.read_bytes()).hexdigest()
                   for b in [binary, build / "tunulator"]},
    start_ms=args.offset, end_ms=end_ms, duration_ms=duration_ms,
    buffer_bytes=buffer_bytes, capacity_bytes=capacity_bytes)
out.mkdir(parents=True, exist_ok=False)  # never overwrite a previous run
(out / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
if args.dry_run:
    print(json.dumps(metadata, indent=2))
    sys.exit(0)
processes, files = [], []
signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
signal.signal(signal.SIGINT, lambda *_: sys.exit(130))

def start(name):
    stdout = (out / (name + ".jsonl")).open("w")
    stderr = (out / (name + ".log")).open("w")
    files.extend([stdout, stderr])
    processes.append(subprocess.Popen(commands[name], stdout=stdout, stderr=stderr,
                                      start_new_session=True))

try:
    start("server")
    time.sleep(0.05)
    start("tunulator")
    time.sleep(5)
    assert all(proc.poll() is None for proc in processes), "See server/tunulator.log"
    start("client")
    affinities = {name: sorted(os.sched_getaffinity(proc.pid))
                  for name, proc in zip(('server', 'tunulator', 'client'), processes)}
    if args.cpu is not None:
        assert all(mask == [args.cpu] for mask in affinities.values()), affinities
    (out / 'processes.json').write_text(json.dumps({
        name: dict(pid=proc.pid, affinity=affinities[name])
        for name, proc in zip(('server', 'tunulator', 'client'), processes)
    }, indent=2) + '\n')
    deadline = time.monotonic() + duration_ms / 1000 + 1.05
    next_stats = time.monotonic() + 30
    while time.monotonic() < deadline:
        assert all(proc.poll() is None for proc in processes), "See the run's .log files"
        if time.monotonic() >= next_stats:
            if args.protocol == "tcp":
                snapshot = subprocess.check_output(["ss", "-tin", "( sport = :" + port + " or dport = :" + port + " )"], text=True)
                with (out / "ecn-sockets.log").open("a") as log:
                    log.write(snapshot + "\n")
            else:
                os.kill(processes[0].pid, signal.SIGHUP)
            next_stats += 30
        time.sleep(min(1, max(0, deadline - time.monotonic())))
finally:
    for proc in reversed(processes):
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
    for f in files:
        f.close()

application = [int(line) for line in (out / "client.jsonl").read_text().splitlines()]
assert len(application) >= duration_ms
first_up = None
app = forwarded = received = seen = 0
with (out / "tunulator.jsonl").open() as raw, (out / "curves.csv").open("w") as dst:
    writer = csv.writer(dst)
    writer.writerow(["elapsed_seconds", "application_bytes", "IP_forwarded", "IP_received"])
    writer.writerow([0, 0, 0, 0])
    for ms, line in enumerate(raw):
        if ms >= duration_ms:
            break
        flows = json.loads(line)
        if first_up is None and any(v[0] for v in flows.values()):
            first_up = ms
        if first_up is not None:
            app += application[ms - first_up]
        forwarded += sum(v[3] for v in flows.values())
        received += sum(v[2] for v in flows.values())
        seen += 1
        if seen % 10 == 0 or seen == duration_ms:
            writer.writerow([seen / 1000, app, forwarded, received])
assert seen == duration_ms and first_up is not None
assert 0 < app <= forwarded <= capacity_bytes
result = dict(application_bytes=app, IP_forwarded=forwarded, IP_received=received,
    IP_not_delivered=received - forwarded, goodput_Mbps=app * 0.008 / duration_ms,
    IP_utilization=forwarded / capacity_bytes, first_up_ms=first_up)
(out / "result.json.tmp").write_text(json.dumps(result, indent=2) + "\n")
(out / "result.json.tmp").replace(out / "result.json")
print(json.dumps(result, indent=2))
