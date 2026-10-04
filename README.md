# Tunulator congestion-control benchmark

This orphan branch contains the scripts for taking **all measurements from scratch**, including TCP CUBIC and TCP BBR. It contains no quicly source, binaries, or measurement results. From a separate quicly source checkout, check out the suite with:

```sh
git worktree add tmp/tunulator-new-host experiment/tunulator-ccbench
```

Run the commands below from that quicly source checkout, not from the suite worktree. Scripts use paths supplied on the command line and need no old experiment directories or old executables.

Written against quicly **`054e9e387fa8efb0852eb24b2120021fbed71f11`** on 2026-10-04. This revision includes `QUICLY_USE_ABE`, a compile-time switch for disabling ABE (see §4), and the instrumentation the latency measurement needs (tunulator `-L`, `recv-offset` events in the clients' output, `cli --decrypt-packet-batch`). Use this commit for an exact source baseline, or pin and record a newer commit deliberately.

## 1. What is being measured

The client, server, and emulator run on one Linux host. **TUN**, rather than Ethernet TAP, carries IPv4 packets. The client connects to the synthetic peer `192.0.2.1`; the server listens on `127.0.0.1`. Tunulator swaps source/destination addresses and delivers packets back through the kernel. Actual benchmark traffic does not traverse a physical network link.

| Program | Source | Purpose |
|---|---|---|
| `tunulator` | `t/tunulator.c` | Replay bandwidth, add delay, implement tail drop or CoDel, count IP bytes |
| `http09` | `t/http09.c` | TCP/TLS bulk transfer using the selected Linux CC |
| `cli` | `src/cli.c` | QUIC bulk transfer using quicly CC |

The primary matrix uses **ordinary CUBIC startup**, with Rapid Start and Jump Start disabled. Controller and startup choices must be explicit in reports.

| Scenario | TCP, freshly measured | QUIC, freshly measured |
|---|---|---|
| Tail drop | CUBIC, BBR | CUBIC, CUBIC + ABBA |
| CoDel ECN | CUBIC, BBR | CUBIC, CUBIC + ABBA |
| CoDel ECN, QUIC ABE off | Same CoDel TCP measurements | CUBIC, CUBIC + ABBA, using the no-ABE build |

With 23 traces this is **230 distinct transfers**: 92 TCP and 138 QUIC. The recorded durations total about **30 hours of sequential playback**, plus build, reporting, and capture overhead. Without the optional no-ABE build it is 184 transfers, about 24 hours. Repeat the complete matrix in a new result root for additional samples. Measure all compared policies on the same host with consistent settings.

## 2. Contents of this directory

- `run-one.py`: launch one transfer; reads prepared build provenance, saves commands/provenance, collects millisecond counters and cumulative CSV, and cleans up child process groups. With `--latency`, also records what `latency.py` needs.
- `latency.py`: compute the per-offset delay of a transfer captured with `--latency` (see §9).
- `record-build.py`: prepare build provenance (source diff, dependency versions, compiler/CMake configuration, executable hashes) before captures start.
- `matrix.py`: sequential or CPU-pinned parallel matrix, completed-run resume checks, optional two-second smoke matrix, and HTML reporting after captures finish.
- `report.py`, `charts.py`: aggregate tables and per-trace tail/CoDel tables and SVGs, including delay distributions; runs `latency.py` on transfers not yet processed; uses only measurements in the supplied result root.
- `workers.py`: CPU-to-TUN mapping, CPU selection validation, and per-user resource locks.
- `validate-parallel.py`: concurrent capture, affinity, lock contention, cleanup, resume, and report checks.
- `trace-inventory.json`: all 23 original trace hashes, windows, capacities and queue sizes. Contains no performance results.

No source patches are needed at this revision: `--abba` is a native CLI option, and the no-ABE build is a compile-time flag (`-DQUICLY_USE_ABE=0`), not a patch. See §4.

Use Python **3.9 or later**, standard library only. Run commands below from the new quicly checkout root unless stated otherwise. Do not run captures while compiling or making other substantial host changes.

## 3. Source, dependencies, and traces

On Debian/Ubuntu, an administrator can install the required tools:

```sh
sudo apt-get update
sudo apt-get install build-essential cmake git perl libssl-dev python3 iproute2 util-linux systemtap-sdt-dev
```

For a new checkout, clone `https://github.com/h2o/quicly.git` and enter it. Fetch the experiment branch if needed, then pin the desired commit and initialize its submodules:

```sh
git fetch origin kazuho/tunulator-latency
git switch --detach 054e9e387fa8efb0852eb24b2120021fbed71f11
git submodule update --init --recursive
mkdir -p tmp
git clone https://github.com/Soheil-ab/Cellular-Traces-NYC.git tmp/Cellular-Traces-NYC
git -C tmp/Cellular-Traces-NYC checkout ac6717b5f113bf899344e91ffc57e472daf29954
```

The [Cellular-Traces-NYC dataset](https://github.com/Soheil-ab/Cellular-Traces-NYC) has 23 NYC cellular traces, covering stationary users, walking, and bus/taxi rides. Enumerate `trace-*` but exclude `trace-info`; do not include `wired48`. Preserve the dataset attribution to *Classic Meets Modern: a Pragmatic Learning-Based Congestion Control for the Internet*, SIGCOMM 2020, when sharing results.

Each line is a millisecond timestamp granting **1,500 IP bytes** of downstream service. Duplicate timestamps grant multiple packets' worth of service. The files need no conversion. The old names ending in `.max=…Mbps` were renamed copies, not a different trace format.

Verify all original trace contents before running:

```sh
python3 - <<'PY'
from pathlib import Path
import hashlib, json
inventory = json.loads(Path('tmp/tunulator-new-host/trace-inventory.json').read_text())
for t in inventory['traces']:
    p = Path('tmp/Cellular-Traces-NYC') / ('trace-' + t['id'])
    assert hashlib.sha256(p.read_bytes()).hexdigest() == t['sha256'], p
print('All 23 trace hashes match')
PY
```

## 4. Build on the destination host

No source patch is needed at this revision: `--abba` is a native CLI option, and floating-point RTT formatting is already fixed.

```sh
cmake -S . -B build/ccbench -DCMAKE_BUILD_TYPE=Release -DWITH_DTRACE=ON -DWITH_FUSION=ON
cmake --build build/ccbench --target cli http09 tunulator test.t -j 4
build/ccbench/test.t > build/ccbench/tests.log 2>&1
```

Check the test exit code before continuing. The pinned ordinary build passes all 35 unit groups. If a statistical lossy-network assertion fails, retain its log and investigate/repeat explicitly; do not silently label failed tests as passing. Inspect `configure.log`/CMake output if DTrace or Fusion support is unavailable. On a different architecture it may be necessary to use `WITH_FUSION=OFF`; use the same settings for all local variants and record them. Benchmark preparation requires no root privileges.

`matrix.py` runs `record-build.py` to completion for each build before launching capture workers. The helper stores provenance in `<build-dir>/.build-info-cache.json`, keyed by the hashes of all three binaries; changed hashes trigger collection again. Workers only read the prepared file. `validate-parallel.py` performs the same preparation before starting concurrent captures.

Standalone `run-one.py` invokes the helper if the file is missing. If the recorded hashes do not match the binaries, it stops and asks you to prepare provenance again:

```sh
python3 tmp/tunulator-new-host/record-build.py --build build/ccbench
```

For concurrent standalone captures sharing a build, run this preparation command to completion first. Do not rebuild or regenerate shared provenance while captures are running. Git information comes from the current source checkout, compiler information from `cc --version`, and CMake configuration from the supplied build directory.

ABE detection supports the `CMAKE_C_FLAGS=-DQUICLY_USE_ABE=0` convention shown below. It reads the last `-DQUICLY_USE_ABE=...` token in `CMAKE_C_FLAGS`, assumes the header default of 1 when absent, and rejects a mismatch with `--condition` (`codel_noabe` requires ABE off; other conditions require it on). This checks recorded configuration, not the compiled binary; definitions supplied through other flags or source changes are not detected.

### Optional no-ABE build

At this revision, disabling ABE is a single compile-time switch, `QUICLY_USE_ABE` (defaults to 1; defined in `include/quicly/cc.h`), gating every ECN-specific beta/alpha/gain-cap choice in `lib/cc-pico.c`, including ABBA's own. No source patch is required; build from the **same** checkout into a second build directory with the macro forced off:

```sh
cmake -S . -B build/ccbench-noabe -DCMAKE_BUILD_TYPE=Release -DWITH_DTRACE=ON -DWITH_FUSION=ON -DCMAKE_C_FLAGS=-DQUICLY_USE_ABE=0
cmake --build build/ccbench-noabe --target cli http09 tunulator test.t -j 4
build/ccbench-noabe/test.t > build/ccbench-noabe/tests.log 2>&1
```

**Known test gap:** at this revision, `t/cc.c` hardcodes ABE-on expectations (`QUICLY_BETA_ECN`, the `0.8` Reno-ECN alpha, ABBA's `85000`/gain-cap constants) in several subtests without checking `QUICLY_USE_ABE`, so `test.t` built with `-DQUICLY_USE_ABE=0` fails `cubic-abe`, `pico-ecn`, `pico-ecn-rapid-start`, and the ABBA `gain-cap`/`cubic-gain-cap`/`cuback-gain-cap`/`cubic-lifecycle`/`cuback-lifecycle` subtests — this is a pre-existing gap in quicly's own tests, not a benchmark-side patch to apply or a build defect. Confirm the failures are limited to exactly these named subtests (`build/ccbench-noabe/tests.log`) before proceeding; a failure elsewhere is a real regression. Use the ordinary build for TCP; the ABE toggle in this study changes QUIC only.

## 5. One-time host setup

Create a persistent TUN owned by the benchmark user. These commands require an administrator; subsequent captures run as that ordinary user. On an existing host, inspect its route/interface before replacing anything.

```sh
sudo modprobe tun
sudo ip tuntap add dev tun0 mode tun user "$(id -u)"
sudo ip link set dev tun0 mtu 1500 up
sudo sysctl -w net.ipv4.conf.tun0.route_localnet=1
sudo ip route replace 192.0.2.1/32 dev tun0 src 127.0.0.1 initcwnd 30
sudo sysctl -w net.ipv4.tcp_ecn=1
```

Do **not** assign `192.0.2.1` as a local interface address. No NAT or IP forwarding setup is needed. Tunulator disables TUN checksum/segmentation offload when attaching. The existing kernel/firewall must permit the synthetic loopback-address traffic through tun0; diagnose local policy rather than broadly disabling the firewall.

TCP BBR must be available from the destination kernel. If it is modular, an administrator can run `sudo modprobe tcp_bbr`. Do not change the system-wide default CC: `http09 -C` selects it per socket.

Read-only checks, without sudo:

```sh
uname -a
lscpu
ip tuntap show
ip -details link show tun0
ip route show 192.0.2.1/32
sysctl net.ipv4.conf.tun0.route_localnet net.ipv4.tcp_ecn
sysctl net.ipv4.tcp_available_congestion_control net.ipv4.tcp_allowed_congestion_control
tc -s qdisc show dev tun0
```

Keep this host information in the result archive; TCP BBR is the host kernel's implementation, not a portable binary-defined version. Capture the distribution/kernel package version as well as the controller name. The docs explain [TUN ownership](https://docs.kernel.org/networking/tuntap.html) and [`route_localnet`/TCP ECN](https://docs.kernel.org/networking/ip-sysctl.html). A sandbox denying TUN or sockets may require running the capture outside that sandbox; this is separate from running as root. Do not use `sudo -n -l` as a routine preflight.

## 6. Exact shared settings

| Setting | Value |
|---|---|
| Measurement window | `[5000, final_timestamp - 5000)` ms; end excluded |
| Base RTT | 60 ms, via upstream `-p 0`, downstream `-P 60000` (microseconds) |
| Downstream bandwidth | `-F TRACE 5000`; trace playback starts with the first packet the emulator receives |
| Upstream bandwidth | Tunulator default, effectively unconstrained for these profiles |
| Queue | `ceil(peak_bytes_per_second × 0.060)`, minimum 1500 bytes; peak uses whole-trace one-second bins |
| Random loss | `-r 0 -R 0` |
| Initial congestion window | 30 packets: TCP route `initcwnd 30`, QUIC `-C cubic:30:p` |
| TCP pacing | `http09 -p` (1 Gbit/s ceiling) |
| QUIC pacing | `:p` in `-C` |
| QUIC payload/cipher | `-u 1472 -U 1472 -y aes128gcmsha256` |
| Stream window/response | `-M 16777216`, request `/10000000000` |
| Ordinary QUIC startup | `--jumpstart-default 0 --jumpstart-max 0`, no `--rapid-start` |
| ABBA | Add `--abba` on both endpoints only for the ABBA policy |

Tunulator grants 1500 bytes per trace entry, expires unused opportunities, and can wrap. These windows avoid wrapping. The buffer uses the peak rate of the **entire trace**, not just the selected window. The helper computes these values from raw files and includes startup within the window.

For `2768760-taxi3`: `[5000,99814)` ms, duration **94.814 seconds**, peak **20.376 Mbps**, queue **152820 bytes**, IP capacity **113946000 bytes**.

| Queue option | Meaning |
|---|---|
| `-Q fifo` | Tail drop |
| `-Q codel:5:100` | CoDel, target 5 ms, interval 100 ms, CE-mark capable packets and otherwise drop |
| `-Q codel/noecn:5:100` | Same thresholds, drops instead of CE |

Keep ECN enabled at endpoints even when testing `codel/noecn`. QUIC enables ECN by default; omit `--disable-ecn`. Verify actual negotiation/CE feedback in socket or endpoint statistics during smoke testing; configuration alone is not evidence that marks were received. CoDel queueing time excludes configured propagation delay, and ECN mode can still overflow its finite buffer.

The `5:100` target:interval is the default, not fixed: `run-one.py --codel TARGET:INTERVAL` (and matching `--queue codel:TARGET:INTERVAL`) and `matrix.py --codel TARGET:INTERVAL` override it for the `codel`/`codel_noabe` conditions. `run-one.py` still rejects a `--queue` that does not match `--condition`/`--codel`, so both must be changed together. A `matrix.py` run records its `--codel` value in `matrix-settings.json`; resuming or reusing an output root with a different value fails with "Matrix settings changed", same as changing `--quic-cc`.

## 7. Smoke and individual taxi3 runs

The test credentials in `t/assets/server.crt` and `server.key` are appropriate for these local test programs. Their stdout counts decrypted application bytes.

```sh
python3 tmp/tunulator-new-host/matrix.py --traces tmp/Cellular-Traces-NYC \
  --build build/ccbench --noabe-build build/ccbench-noabe \
  --output tmp/ccbench-smoke --smoke
```

This runs ten two-second taxi3 captures, separately from headline measurements. Omit `--noabe-build` for eight captures. Confirm nonzero delivery, the intended CC/startup flags in each `metadata.json`, successful controller selection, and no TUN I/O errors. Two seconds checks plumbing; use a full trace to check CoDel CE behavior.

Examples for full taxi3 captures:

```sh
python3 tmp/tunulator-new-host/run-one.py tcp --cc bbr \
  --trace tmp/Cellular-Traces-NYC/trace-2768760-taxi3 --condition codel --queue codel:5:100 \
  --build build/ccbench --output tmp/taxi3-fresh/tcp-bbr
python3 tmp/tunulator-new-host/run-one.py quic --cc cubic --abba \
  --trace tmp/Cellular-Traces-NYC/trace-2768760-taxi3 --condition codel --queue codel:5:100 \
  --build build/ccbench --output tmp/taxi3-fresh/cubic-abba
```

Plain QUIC CUBIC omits `--abba`; TCP CUBIC uses `tcp --cc cubic`. For no-ABE QUIC use `--condition codel_noabe --queue codel:5:100 --build build/ccbench-noabe`. For a separate drops-only study use `--condition codel_noecn --queue codel/noecn:5:100`; it is not included by the primary matrix/report. For a non-standard target/interval, e.g. 26 ms, add `--codel 26:100` and change `--queue` to match: `--queue codel:26:100` (or `codel/noecn:26:100` for `codel_noecn`).

The single-run helper also supports `--cc cuback --abba --rapid-start` (Jump Start default 60), but keep those results separate from the ordinary-CUBIC matrix. `--dry-run` writes metadata/commands and computes window/queue values without opening sockets or TUN; it is not a performance measurement. Each output directory must be new.

## 8. Full matrix, resume, and results

```sh
python3 tmp/tunulator-new-host/matrix.py --traces tmp/Cellular-Traces-NYC \
  --build build/ccbench --noabe-build build/ccbench-noabe --output tmp/ccbench-fresh
```

Run in a persistent terminal such as tmux, or use `nohup` and redirect to a log outside the result root. Matrix output lists started/completed captures; `runner-logs/` contains per-capture output and errors. Captures lock each TUN and assigned CPU under `/tmp/quicly-ccbench-UID/`, shared across checkouts for this user. The tun0 runner also takes the legacy repository `tmp/taxi3-runner.lock`. Do not use harnesses that bypass those locks concurrently.

`matrix.pid` records the matrix process. SIGTERM to that exact live process terminates the active capture and cleans up its endpoint/emulator process groups. Completed captures have `result.json` written last. Resume with the same command and CPU list: completed entries are checked against the trace hash, window, settings and executable hashes before being skipped. An interrupted directory has no `result.json`; **move that incomplete directory outside the result root** before resuming, preserving its logs. The single-run helper deliberately refuses to overwrite it. Use a fresh output root after changing source, binaries, kernel, or experimental settings.

A fresh TCP CoDel measurement is displayed alongside both QUIC ABE settings because ABE-off modifies only QUIC. Total distinct transfers remain 230, not 276.

Each transfer saves:

- `metadata.json`: exact commands, trace hash/window, kernel, route, TCP ECN setting, executable hashes and build metadata.
- `client.jsonl`, `server.jsonl`, `tunulator.jsonl` and corresponding `.log` files: raw counters and diagnostics. The portable runner leaves raw files uncompressed. `client.jsonl` holds JSON lines: `{"type":"delivered","bytes":N}` per millisecond, and `{"type":"recv-offset","offset":N,"at":T}` when the byte at each multiple of 15000 is received.
- `tunulator.pktlog` and, for QUIC, `keylog` (with `--latency`, which the matrix always passes): the receive time, segment length and first 64 bytes after the IP header of each downstream packet, and the QUIC server's TLS secrets.
- `curves.csv`: cumulative application bytes, IP forwarded, and IP received every 10 ms and at the final cutoff.
- `result.json`: totals and ratios for the selected window.

Leave raw logs available until accounting has been checked. Keep enough disk space for multi-day runs and archive/compress completed logs afterward. Build provenance travels with each transfer already, inline in its own `metadata.json`; there is no separate provenance file to remember to copy. The matrix report copies trace inputs into its result root, so it can redraw without the original dataset path after measurements finish.

## 9. HTML and accounting

The matrix generates the report after all captures finish, keeping report work out of active measurements. To regenerate manually:

```sh
python3 tmp/tunulator-new-host/report.py tmp/ccbench-fresh
```

Open `tmp/ccbench-fresh/index.html`. The report has two aggregate tables and, per trace, tail and CoDel panels listed vertically, each with a table, application-delivery and IP-forwarding curves, and the probability density of delays on a logarithmic delay axis from the smallest delay to 2000 ms. Before rendering, the report runs `latency.py` on each transfer that has a packet log but no `latency.csv` yet. Aggregate tables weight each trace equally: goodput, IP forwarded and not delivered are averages of the per-trace values, and delay statistics are computed over the samples of all traces, weighted so that every trace counts equally. TCP rows/legends come first; QUIC ABE-off rows come last. TCP CUBIC is green, TCP BBR purple, QUIC CUBIC blue, QUIC CUBIC + ABBA red. ABE-off curves use the same QUIC colors with dashed lines. There are no top-level summary charts. `summary.csv` contains the measured values and run-directory paths.

For incomplete matrices, aggregate comparisons include only traces with every displayed policy present. Once no-ABE results exist, the CoDel aggregate requires both QUIC ABE settings. The report displays the recorded CoDel target and interval and rejects mixed CoDel settings, including disagreements with `matrix-settings.json`. Older matrix settings without a `codel` field imply `5:100`. A repetition belongs in a separate result root; this renderer does not average repetitions.

Tunulator emits one JSON object per millisecond with per-flow arrays:

```text
[upstream IP received, upstream IP forwarded,
 downstream IP received, downstream IP forwarded]
```

The capture sums flows because there is one transfer. Client stdout contains application bytes per millisecond. Tunulator starts trace playback and its statistics when it receives the first packet, so the measurement does not depend on how long it took to load the trace and attach the TUN (the client is started 5 seconds after tunulator). The client runs for exactly the selected trace duration; tunulator is stopped a second later, writing its statistics up to then. The window ends 5 seconds before the end of the trace, so the trace never wraps. Client and emulator clocks start separately; the accounting aligns the client's first sample to the emulator's first upstream packet. This is a millisecond approximation, including startup, not exact per-packet clock synchronization. The accounting covers **only the selected trace duration**.

| Metric | Definition |
|---|---|
| Goodput Mbps / utilization | Application bytes × 8 / duration_seconds / 1,000,000; application bytes / sum of trace opportunities in the selected window |
| IP forwarded Mbps / utilization | Same, using IP bytes forwarded |
| Not delivered | (IP received − IP forwarded) / IP received |
| Delay avg, p50, p90, p99 | Of the per-offset delays (see below), in ms |

Goodput utilization is a few percent below IP utilization, as both divide by the IP capacity, which counts headers and TLS or QUIC overhead.

### Delay

`latency.py` measures the delay of every 15000th byte of the stream: from when tunulator first received a downstream packet carrying it, to when the client received it (`recv-offset`). It thus includes propagation, queueing, loss recovery and head-of-line blocking, but not time spent in the sender's buffer. Offsets are TCP stream offsets (sequence number minus server ISN + 1), which include TLS overhead, and QUIC stream offsets. Both timestamps are `CLOCK_MONOTONIC` on the same host. QUIC packets are decrypted from the recorded 64 bytes using `cli --decrypt-packet-batch` and the server's key log; truncated packets are given up to where the tag starts, followed by a dummy tag. `latency.py` writes `latency.csv` (one row per sample) and `latency.json` (percentiles and decoding counts) into the run directory.

**Not delivered is not an exact drop ratio**: it includes bytes still in the emulator at cutoff, including the propagation-delay stage. Forwarded CE-marked packets do not count. Drops before the emulator receives a packet are not counted by tunulator. Retain kernel/interface counters when investigating unexplained loss. Compare the same trace set for every policy.

## 10. Repeatability and prospective parallelism

Start with sequential runs on the new host. Trace timing, ACK batching, startup, and overflow make these experiments nondeterministic. Repeat representative profiles and alternate variant order; a single gain sweep does not establish statistical significance. Record CPU model/topology, affinity, kernel, governor/turbo settings, virtualization if any, and concurrent workloads. Keep settings consistent rather than assuming different hosts produce comparable TCP or QUIC totals.

### Parallel workers on logical CPUs

`--cpus 1-15` enables 15 workers, leaving logical CPU 0 out of the capture affinity masks. Each worker pins its runner, server, client, and tunulator to a single CPU using Linux affinity inherited before exec. CPU N always uses `tunN`, peer `192.0.2.(N+1)`, and server port `20000+N`. Check that these fixed ports are unused and outside the host's configured ephemeral port range. CPU IDs must be unique, available to the process, and between 0 and 253. Existing tun0 remains usable by the unpinned sequential runner (it conflicts intentionally with `--cpus 0`). `workers.py` defines the mapping and locks.

Choose CPU IDs using the destination host's CPU topology (for example, `lscpu -e`). SMT siblings share a physical core. Affinity does not reserve a core from other workloads or pin kernel networking/interrupt work. The CPU lists below are examples; adapt them to the host.

Create the extra TUNs once as an administrator. Inspect existing interfaces/routes first; these commands intentionally fail on an existing interface or route rather than replacing it:

```sh
for cpu in $(seq 1 15); do
  sudo ip tuntap add dev "tun${cpu}" mode tun user "$(id -u)" || break
  sudo ip link set dev "tun${cpu}" mtu 1500 up || break
  sudo sysctl -w "net.ipv4.conf.tun${cpu}.route_localnet=1" || break
  sudo ip route add "192.0.2.$((cpu + 1))/32" dev "tun${cpu}" src 127.0.0.1 initcwnd 30 || break
done
```

TCP ECN must still be enabled as in §5. No extra addresses are assigned locally. The existing compiled binaries work unchanged.

First run a parallel smoke matrix in a new directory:

```sh
python3 tmp/tunulator-new-host/matrix.py --traces tmp/Cellular-Traces-NYC \
  --build build/ccbench --noabe-build build/ccbench-noabe \
  --cpus 1-15 --smoke --output tmp/taxi3-parallel-smoke
```

Taxi3 alone, full duration, all ten policies/conditions, followed by HTML:

```sh
python3 tmp/tunulator-new-host/matrix.py --traces tmp/Cellular-Traces-NYC \
  --build build/ccbench --noabe-build build/ccbench-noabe \
  --cpus 1-15 --trace-id 2768760-taxi3 --output tmp/taxi3-parallel
```

This has ten jobs, so only ten workers are used. Repeat `--trace-id` to select multiple traces. Omit it to run all 23 traces (230 transfers) with up to 15 concurrent captures. This scheduler assigns jobs round-robin to CPU queues before checking completed runs, keeping CPU/network assignment stable on resume. A worker immediately takes its next assigned job when free. `--dry-run` creates planned metadata without acquiring TUNs or producing measurements/HTML; use a separate root from real captures.

Add `--quic-cc cuback` to use QUIC CUBACK and CUBACK + ABBA, including the no-ABE variants. The default is `--quic-cc cubic`. This changes only the QUIC controller: IW stays 30, pacing stays enabled, and Rapid Start and Jump Start stay disabled. TCP remains CUBIC/BBR. Output directory names and HTML/CSV labels reflect the selected controller. Use a new result root when changing controllers; resume rejects a different selection. Older matrix settings without this option are treated as CUBIC.

To reuse TCP measurements with a different QUIC controller, copy the complete `<trace-id>/tail/tcp_cubic`, `tail/tcp_bbr`, `codel/tcp_cubic`, and `codel/tcp_bbr` directories into the same relative paths in a new output root. Do not copy the old `matrix-settings.json` or QUIC directories. Existing completed variants are validated and skipped; only missing variants run. Trace/window, controller/startup, kernel, assigned CPU/network worker, and binary hashes must match. Use the same CPU list and trace selection to preserve worker assignment. Directories without `result.json` are incomplete and must be moved aside, not silently skipped. The new matrix settings are saved after validation succeeds.

For one capture, add `--cpu 3` to `run-one.py` to use CPU 3, tun3, peer 192.0.2.4 and port 20003. `metadata.json` records this mapping and `processes.json` records each child PID and verified affinity. `matrix-settings.json` records worker CPUs and trace selection; resume rejects changed settings. Use fresh roots for different concurrency levels. A failed capture stops the matrix and terminates/reaps the other active captures; retain and move incomplete directories before resuming. Send SIGTERM to `matrix.pid` for the same cleanup. Do not SIGKILL the controller or runners.

Reports are generated once after all workers finish to avoid competing for CPU and I/O during measurement. The controller and final report use non-worker CPUs when available. Reports can also be regenerated manually from completed runs. The execution mode is recorded in `matrix-settings.json`.

Parallel plumbing is testable with short captures, but measurement equivalence is **not established**. Compare repeated isolated and concurrent runs before relying on throughput comparisons; include bursty profiles and check delivery, RTT, emulator deadline lateness, and unintended kernel/TUN drops. Deadline instrumentation still needs adding. Keep original sequential results separate.

`validate-parallel.py` exercises every requested CPU concurrently with short real captures, verifies live child affinity and nonzero delivery, tests lock contention, checks matrix SIGTERM cleanup and rejection of incomplete runs, and tests queued smoke jobs plus completed-run resume and HTML generation:

```sh
python3 tmp/tunulator-new-host/validate-parallel.py --cpus 1-15 \
  --build build/ccbench --noabe-build build/ccbench-noabe \
  --traces tmp/Cellular-Traces-NYC --output tmp/parallel-validation
```

VMs are a possible fallback if shared-host interference is demonstrated, not a prerequisite.

## 11. Provenance and validation

The general background is documented on the [quicly wiki](https://github.com/h2o/quicly/wiki/CC-benchmarking-using-real-world-traces).

Generated metadata includes absolute paths, the full CMake cache, and `git diff HEAD` from the source checkout. Review these files before publishing results: they can contain local configuration and unpublished source changes. Repeat smoke validation on each destination before collecting measurements.
