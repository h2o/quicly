# LTE newcomer ACK-clock ablation

This branch tests why the Cuback newcomer gains bandwidth faster than CUBIC in
`experiment/cuback-vs-cubic-newcomer`. It is a frozen experimental record, not maintained Quicly source.

The experiment uses pinned Quicly commit `14194a71610049f3ee31c5acee626cd0d2f51f0b`, the same LTE geometry, incumbent,
startup options, 100 paired phase/seed combinations, 200-second post-arrival duration, and trailing-five-RTT bottleneck
sampling as the parent experiment.

## Ablation

The benchmark adds one hybrid congestion controller:

| Newcomer | Cubic curve clock | Reno-friendly estimator |
|---|---|---|
| production `cubic` | wall time | CUBIC `W_est` |
| `cubic-ackclock` | acknowledged bytes | CUBIC `W_est` |
| production `cuback` | acknowledged bytes | Cuback estimator |

All three newcomers use `-i 30 -j 60 -p -R`. The incumbent remains production CUBIC with `-i 30 -p`.

The hybrid shares CUBIC's startup, recovery, Wmax, fast convergence, cubic target integration, and `W_est`. The only
algorithmic change is that the cubic curve's elapsed time is accumulated as:

```
ack_clock_time += bytes_acked / bandwidth_at_congestion
```

Thus production-CUBIC to hybrid isolates the clock-source effect. Hybrid to Cuback is the residual, principally the estimator
difference.

## LTE profile and throughput result

| RTT | Queue | Bandwidth | Chart duration |
|---:|---:|---:|---:|
| 60 ms | 120 ms | 30 Mbit/s | 50 s |

Every one of the 300 simulations completed successfully and emitted the expected sample count. The table reports mean per-run
newcomer bandwidth share over each horizon; deltas are means of paired differences.

| Horizon | CUBIC | ACK-clock hybrid | Cuback | Clock delta | Residual delta | Total delta |
|---:|---:|---:|---:|---:|---:|---:|
| 5 s | 0.2601 | 0.2802 | 0.2834 | +0.0201 | +0.0031 | +0.0232 |
| 10 s | 0.2889 | 0.3118 | 0.3128 | +0.0229 | +0.0010 | +0.0239 |
| 20 s | 0.3317 | 0.3532 | 0.3518 | +0.0214 | -0.0013 | +0.0201 |
| 50 s | 0.3970 | 0.4118 | 0.4091 | +0.0148 | -0.0027 | +0.0121 |

At 5 and 10 seconds the hybrid beat ordinary CUBIC in all 100 paired runs. The clock replacement accounts for 87% of Cuback's
total mean gain at 5 seconds and 96% at 10 seconds; the residual estimator effect is small.

## Direct recovery-entry test

The direct test observes the ACK-clock hybrid immediately before it enters recovery from each of its first ten
congestion-avoidance (CA) periods. Let `Wloss` be that pre-reduction CWND. For that period it reports:

```
X = K + cbrt((Wloss - Wmax) / (C * MSS))
Y = recovery_time - CA_epoch_start
```

`X` is the nominal wall-clock CUBIC time at which the period's cubic curve reaches the observed `Wloss`; `Y` is the wall time
actually elapsed. Therefore `X/Y > 1` means the ACK-clock hybrid reached that CWND faster than ordinary wall-clock CUBIC predicts.
The benchmark also checks whether the cubic curve or `W_est` selected the CWND at recovery entry.

The entries below are medians over all 100 runs with deterministic paired-bootstrap 95% confidence intervals (20,000
resamples). No run is excluded for failing to cross Wmax.

| CA period | X: nominal time (s) | Y: actual time (s) | X/Y | Fast convergence | Cubic dominant |
|---:|---:|---:|---:|---:|---:|
| 1 | 2.529 [2.455, 2.588] | 1.623 [1.541, 1.654] | 1.546 [1.514, 1.595] | 0/100 | 100/100 |
| 2 | 8.709 [8.682, 8.738] | 8.782 [8.750, 8.809] | 0.993 [0.992, 0.994] | 98/100 | 100/100 |
| 3 | 3.681 [3.626, 3.734] | 3.724 [3.694, 3.784] | 0.990 [0.986, 0.995] | 1/100 | 100/100 |
| 4 | 8.965 [8.888, 8.992] | 8.844 [8.804, 8.894] | 1.008 [1.005, 1.011] | 63/100 | 100/100 |
| 5 | 3.781 [3.574, 7.924] | 3.832 [3.663, 8.481] | 0.979 [0.975, 0.982] | 27/100 | 100/100 |
| 6 | 8.866 [6.712, 8.976] | 8.892 [7.242, 8.921] | 0.998 [0.985, 1.002] | 54/100 | 100/100 |
| 7 | 3.951 [3.619, 8.118] | 4.016 [3.701, 8.710] | 0.979 [0.977, 0.985] | 34/100 | 100/100 |
| 8 | 8.781 [6.594, 8.940] | 8.791 [7.270, 8.929] | 0.991 [0.982, 0.996] | 56/100 | 100/100 |
| 9 | 3.996 [3.677, 8.822] | 4.044 [3.761, 8.543] | 0.987 [0.981, 0.992] | 36/100 | 100/100 |
| 10 | 8.080 [4.070, 8.922] | 8.820 [4.142, 8.940] | 0.984 [0.979, 0.995] | 51/100 | 100/100 |

The first CA period has no fast convergence, the cubic curve dominates all 100 observations, and its median `X/Y` is 1.546.
Periods 2-10 are approximately wall-clock paced. Together with the throughput ablation, this directly identifies transient
ACK-clock acceleration in the first CA period as the mechanism behind most of Cuback's short-flow newcomer gain.

This recovery-entry method supersedes selecting only periods that cross Wmax, which would censor early recoveries and could make
the next recovery appear artificially early.

Committed results:

* `results/lte-newcomer-ackclock-ablation.svg`
* `results/lte-ca-recovery-summary.csv`

## Reproduction

Apply `benchmark.patch` to the pinned source and build the simulator:

```sh
experiment_dir=$PWD
source_dir=../quicly-cuback-ackclock-ablation-source
commit=14194a71610049f3ee31c5acee626cd0d2f51f0b

git worktree add --detach "$source_dir" "$commit"
git -C "$source_dir" submodule update --init --recursive
git -C "$source_dir" apply "$experiment_dir/benchmark.patch"
cmake -S "$source_dir" -B "$source_dir/build/experiment" -DCMAKE_BUILD_TYPE=Release
cmake --build "$source_dir/build/experiment" --target simulator -j
```

Run the 300 simulations, regenerate the throughput SVG, and regenerate the direct-test CSV and Markdown table:

```sh
SIMULATOR="$source_dir/build/experiment/simulator" ruby run.rb
ruby draw.rb
ruby summarize-recovery.rb
```

Raw throughput samples below `results/raw` and per-run recovery records below `results/recovery` are not committed.
