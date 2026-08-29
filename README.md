# Cuback vs CUBIC newcomer gain experiment

This branch records an experiment comparing how quickly a Cuback or CUBIC newcomer gains bottleneck bandwidth from an established
CUBIC flow. It is a frozen experimental record, not code maintained as part of Quicly's source tree.

The experiment uses Quicly commit `14194a71610049f3ee31c5acee626cd0d2f51f0b`, the same commit as
`experiment/newcomer-startup`. `benchmark.patch` adds efficient deterministic bottleneck-throughput sampling to
`t/simulator.c`; it does not change either congestion controller.

## Policies

The incumbent is current CUBIC in every run, starts at time zero, and uses an initial window of 30 packets with pacing enabled.
Only the newcomer congestion controller changes:

| Role | Simulator options |
|---|---|
| CUBIC incumbent | `-c cubic -i 30 -p` |
| CUBIC newcomer | `-c cubic -i 30 -j 60 -p -R` |
| Cuback newcomer | `-c cuback -i 30 -j 60 -p -R` |

Thus both newcomers use the requested `-i 30 -j 60 -p -R` configuration. This matches the HEAD CUBIC newcomer configuration in
the previous experiment; the incumbent remains unchanged from that experiment.

## Network profiles

Bandwidth is passed to the simulator in bytes per second. Queue depth is expressed as seconds of bottleneck capacity.

| Profile | RTT | Queue | Bandwidth | Chart duration |
|---|---:|---:|---:|---:|
| DSL | 30 ms | 50 ms | 30 Mbit/s | 30 s |
| Half DSL | 30 ms | 50 ms | 15 Mbit/s | 10 s |
| Quarter DSL | 30 ms | 50 ms | 7.5 Mbit/s | 10 s |
| Eighth DSL | 30 ms | 50 ms | 3.75 Mbit/s | 10 s |
| LTE | 60 ms | 120 ms | 30 Mbit/s | 50 s |
| 5G | 40 ms | 80 ms | 100 Mbit/s | 50 s |

The simulator's default packet-size-neutral tail-drop admission, default MTU, MTU normalization, and ECN configuration are used.
Both senders use pacing. The ACK-scheduler option is not enabled.

## Samples

Each profile and newcomer policy has the same 100 predetermined phase/seed combinations:

* Seeds are 1 through 100.
* Seeds 1-20 start the newcomer at 20 seconds, 21-40 at 25 seconds, 41-60 at 30 seconds, 61-80 at 35 seconds, and 81-100 at 40 seconds.
* The incumbent starts at time zero.
* Every run continues for 200 seconds after newcomer arrival.
* The deterministic seed controls the TLS random-byte source used while constructing the simulated connections.

Throughput is measured from bytes dequeued by the bottleneck for the newcomer (`packet-src` 3), rather than bytes delivered in
order to the application. Samples cover trailing windows of five RTTs. Each run must exit successfully and emit exactly
`floor(200 / (5 * RTT))` samples. No failed, incomplete, or low-utilization runs are excluded or replaced.

Charts contain all 100 faint trajectories for each policy. Solid lines are pointwise medians; dashed lines are the 10th and 90th
percentiles.

## Procedure

Starting from a clone containing this orphan experiment branch, create a separate worktree at the pinned source commit and apply
the benchmark changes:

```sh
experiment_dir=$PWD
source_dir=../quicly-cuback-vs-cubic-newcomer-source
commit=14194a71610049f3ee31c5acee626cd0d2f51f0b

git worktree add --detach "$source_dir" "$commit"
git -C "$source_dir" submodule update --init --recursive
git -C "$source_dir" apply "$experiment_dir/benchmark.patch"
```

Build the simulator:

```sh
cmake -S "$source_dir" -B "$source_dir/build/experiment" -DCMAKE_BUILD_TYPE=Release
cmake --build "$source_dir/build/experiment" --target simulator -j
```

Run all 1,200 simulations and draw the SVG charts:

```sh
SIMULATOR="$source_dir/build/experiment/simulator" ruby run.rb
ruby draw.rb
```

`run.rb` accepts profile names as arguments when only part of the matrix is wanted, for example `ruby run.rb DSL LTE`. The
number of worker processes can be changed using `WORKERS`; the default is eight. Raw samples are written below `results/raw`
and are not committed.

## Recorded results

The committed SVG files are the output of the complete matrix described above:

* `results/cuback-vs-cubic-newcomer-dsl.svg`
* `results/cuback-vs-cubic-newcomer-half-dsl.svg`
* `results/cuback-vs-cubic-newcomer-quarter-dsl.svg`
* `results/cuback-vs-cubic-newcomer-eighth-dsl.svg`
* `results/cuback-vs-cubic-newcomer-lte.svg`
* `results/cuback-vs-cubic-newcomer-5g.svg`

The following summary uses the median per-run mean newcomer bandwidth share over each chart's displayed horizon. The paired delta
is the median, across the 100 matched runs, of Cuback share minus CUBIC share.

| Profile | CUBIC | Cuback | Paired delta |
|---|---:|---:|---:|
| DSL | 0.4375 | 0.4567 | +0.0140 |
| Half DSL | 0.4316 | 0.4521 | +0.0110 |
| Quarter DSL | 0.5018 | 0.5064 | +0.0010 |
| Eighth DSL | 0.5130 | 0.5163 | +0.0000 |
| LTE | 0.3972 | 0.4111 | +0.0116 |
| 5G | 0.3617 | 0.3821 | +0.0150 |

Cuback gains bandwidth faster overall on DSL, Half DSL, LTE, and 5G. The distinction is negligible at Quarter DSL and Eighth DSL
rates.
