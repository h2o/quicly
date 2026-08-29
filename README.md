# LTE newcomer ACK-clock ablation

This branch tests why the CuBACK newcomer gains bandwidth faster than CUBIC in
`experiment/cuback-vs-cubic-newcomer`. It is a frozen experimental record, not maintained Quicly source.

The experiment uses the same pinned Quicly commit, LTE geometry, incumbent, startup options, 100 phase/seed pairs, 200-second
post-arrival duration, and trailing-five-RTT bottleneck sampling as the parent experiment.

## Ablation

The benchmark adds one hybrid congestion controller:

| Newcomer | Cubic curve clock | Reno-friendly estimator |
|---|---|---|
| `cubic` | wall time | CUBIC `W_est` |
| `cubic-ackclock` | acknowledged bytes | CUBIC `W_est` |
| `cuback` | acknowledged bytes | CuBACK standalone estimator |

All three newcomers use `-i 30 -j 60 -p -R`. The incumbent remains CUBIC with `-i 30 -p`.

The hybrid shares CUBIC's startup, recovery, `Wmax`, fast convergence, cubic target integration, and `W_est`. The only change is
that the cubic curve's elapsed time is accumulated as:

```
ack_clock_time += bytes_acked / bandwidth_at_congestion
```

This makes CUBIC-to-hybrid the isolated clock-source effect. Hybrid-to-CuBACK is the residual caused primarily by the different
Reno-friendly estimator.

## LTE profile

| RTT | Queue | Bandwidth | Chart duration |
|---:|---:|---:|---:|
| 60 ms | 120 ms | 30 Mbit/s | 50 s |

Seeds 1-100 and newcomer arrival phases are paired across policies exactly as in the parent experiment. Every one of the 300
simulations completed successfully and emitted the expected sample count.

## Result

The table reports mean per-run newcomer bandwidth share over each horizon. Deltas are means of paired differences.

| Horizon | CUBIC | ACK-clock hybrid | CuBACK | Clock delta | Residual delta | Total delta |
|---:|---:|---:|---:|---:|---:|---:|
| 5 s | 0.2601 | 0.2802 | 0.2834 | +0.0201 | +0.0031 | +0.0232 |
| 10 s | 0.2889 | 0.3118 | 0.3128 | +0.0229 | +0.0010 | +0.0239 |
| 20 s | 0.3317 | 0.3532 | 0.3518 | +0.0214 | -0.0013 | +0.0201 |
| 50 s | 0.3970 | 0.4118 | 0.4091 | +0.0148 | -0.0027 | +0.0121 |

At both 5 and 10 seconds, the ACK-clock hybrid beat ordinary CUBIC in all 100 paired runs. The clock change accounts for about 87%
of the total mean gain at 5 seconds and 96% at 10 seconds. The residual CuBACK estimator effect is small by comparison and
disappears over longer horizons.

The recorded SVG is `results/lte-newcomer-ackclock-ablation.svg`.

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

Run the 300 simulations and generate the SVG:

```sh
SIMULATOR="$source_dir/build/experiment/simulator" ruby run.rb
ruby draw.rb
```

Raw samples are written below `results/raw` and are not committed.
