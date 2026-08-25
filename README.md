# CUBIC newcomer startup experiment

This branch records the experiment comparing four ways of initializing CUBIC after startup. It is a frozen experimental record,
not code maintained as part of Quicly's source tree.

The experiment used Quicly commit `14194a71610049f3ee31c5acee626cd0d2f51f0b`. `benchmark.patch` adds three benchmark-only
variants of the current CUBIC implementation and efficient, deterministic bottleneck-throughput sampling to `t/simulator.c`.
It does not use `cubic-legacy`.

## Policies

The incumbent is current CUBIC in every run, configured with an initial window of 30 packets and pacing enabled. Only the newcomer
policy changes:

| Name in charts | Simulator options | Behavior |
|---|---|---|
| Traditional | `-c cubic-traditional -i 30 -p` | Ordinary 2x slow start. At the first recovery, Wmax is CWND at loss and CWND becomes 0.7 times that value. |
| Rapid Start: Wmax = BDP | `-c cubic-bdp -i 30 -j 60 -p -R` | Rapid Start with Wmax equal to its BDP estimate. |
| Rapid Start: Wmax = BDP; suppress first CA FC | `-c cubic-bdp-nofc -i 30 -j 60 -p -R` | The preceding policy, suppressing Fast Convergence at the first congestion event in congestion avoidance. |
| HEAD Rapid Start: Wmax = 2 x BDP | `-c cubic -i 30 -j 60 -p -R` | Behavior of the pinned Quicly commit. |

The three benchmark policies share current CUBIC's callbacks and state machine. Their differences are limited to the startup rules
listed above.

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

Starting from a clone containing this orphan branch, create a separate worktree at the pinned source commit and apply the benchmark
changes:

```sh
experiment_dir=$PWD
source_dir=../quicly-newcomer-startup-source
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

Run all 2,400 simulations and draw the SVG charts:

```sh
SIMULATOR="$source_dir/build/experiment/simulator" ruby run.rb
ruby draw.rb
```

`run.rb` accepts profile names as arguments when only part of the matrix is wanted, for example `ruby run.rb DSL LTE`. The number
of worker processes can be changed using `WORKERS`; the default is eight. Raw samples are written below `results/raw` and are not
committed. `draw.rb` writes the six committed charts below `results`.

## Recorded results

The committed SVG files are the output of the complete matrix described above:

* `results/newcomer-startup-dsl.svg`
* `results/newcomer-startup-half-dsl.svg`
* `results/newcomer-startup-quarter-dsl.svg`
* `results/newcomer-startup-eighth-dsl.svg`
* `results/newcomer-startup-lte.svg`
* `results/newcomer-startup-5g.svg`

Traditional startup and HEAD acquire bandwidth similarly on DSL, LTE, and 5G, while Wmax equal to the BDP estimate is slower on
the larger profiles. The distinction diminishes as DSL bandwidth is reduced and is immaterial at quarter and eighth DSL rates.
Suppressing the first congestion-avoidance Fast Convergence does not materially change the result.
