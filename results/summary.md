# ABBA recalibration-suppression results

Every cell is calculated from ten repetitions. An incumbent is clearly harmed when the ABBA run's per-incumbent P90 is
below the matching stock/stock run's per-incumbent P10. This deliberately compares ABBA against the bandwidth that stock
actually left to an incumbent, rather than against an assumed equal share.

## Clear incumbent harm

| ABBA flags | CC | Before guards | With guards |
|---:|---|---:|---:|
| `0x2` | cubic | 1004 / 2576 | 8 / 2576 |
| `0x2` | cuback | 1035 / 2576 | 44 / 2576 |
| `0x6` | cubic | 1032 / 2576 | 9 / 2576 |
| `0x6` | cuback | 1066 / 2576 | 40 / 2576 |

## Distribution of median changes with the guards

Values are percentage-point changes relative to the matching stock/stock run. Positive incumbent loss means that the stock
incumbent received less bandwidth when its contender used ABBA.

| Flags | CC | Incumbent loss P50 | P90 | P99 | Contender gain P50 | Utilization change P50 |
|---:|---|---:|---:|---:|---:|---:|
| `0x2` | cubic | 0.0138 | 1.5159 | 4.6992 | 0.0253 | 0.0015 |
| `0x2` | cuback | 0.0225 | 1.7204 | 6.8316 | 0.0425 | 0.0004 |
| `0x6` | cubic | 0.0074 | 1.4200 | 5.0547 | 0.0163 | 0.0023 |
| `0x6` | cuback | 0.0158 | 1.7033 | 7.0083 | 0.0259 | 0.0005 |

## Reproduced regression

Cuback, 80 ms idle RTT, BDP 400 packets, 10 ms queue, two flows, and no random loss:

| Flags | Order | Revision | Incumbent median | Contender median | Utilization median |
|---:|---|---|---:|---:|---:|
| `0x2` | contender-first | baseline | 29.73% | 62.28% | 91.88% |
| `0x2` | contender-first | guarded | 47.59% | 47.76% | 95.33% |
| `0x2` | contender-last | baseline | 29.80% | 61.63% | 92.05% |
| `0x2` | contender-last | guarded | 46.73% | 48.63% | 95.27% |
| `0x6` | contender-first | baseline | 27.75% | 64.55% | 92.06% |
| `0x6` | contender-first | guarded | 48.01% | 47.35% | 95.27% |
| `0x6` | contender-last | baseline | 30.14% | 61.59% | 91.84% |
| `0x6` | contender-last | guarded | 45.75% | 49.73% | 95.20% |

## Largest residual incumbent losses with the guards

The table lists the ten scenarios with the greatest reduction in median per-incumbent throughput for each mode.

| Flags | CC | Flows | Order | Loss scope | PLR/RT | RTT | BDP | Queue | Stock incumbent | ABBA incumbent | ABBA contender | Utilization change |
|---:|---|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `0x2` | cuback | 1+1 | contender-first | all-flows | 0.1% | 40 ms | 400 | 10 ms | 49.06% | 36.95% | 60.47% | +0.48 pp |
| `0x2` | cuback | 1+1 | contender-last | contender-only | 1.0% | 40 ms | 400 | 12 ms | 58.53% | 47.68% | 49.87% | +0.33 pp |
| `0x2` | cuback | 1+1 | contender-last | contender-only | 0.1% | 5 ms | 4 | 5 ms | 62.32% | 51.47% | 60.29% | +0.30 pp |
| `0x2` | cuback | 1+1 | contender-first | all-flows | 10.0% | 10 ms | 400 | 20 ms | 36.85% | 26.30% | 71.57% | +22.02 pp |
| `0x2` | cuback | 1+1 | contender-first | all-flows | 1.0% | 40 ms | 400 | 10 ms | 46.68% | 36.13% | 61.16% | +1.54 pp |
| `0x2` | cuback | 1+1 | contender-last | all-flows | 1.0% | 80 ms | 400 | 20 ms | 47.52% | 36.99% | 60.00% | +0.88 pp |
| `0x2` | cubic | 1+1 | contender-first | all-flows | 10.0% | 10 ms | 400 | 20 ms | 38.65% | 28.30% | 69.54% | +20.71 pp |
| `0x2` | cuback | 1+1 | contender-first | contender-only | 1.0% | 40 ms | 400 | 10 ms | 56.14% | 45.91% | 51.34% | +0.63 pp |
| `0x2` | cuback | 1+1 | contender-first | contender-only | 1.0% | 80 ms | 400 | 20 ms | 59.16% | 48.95% | 48.21% | +0.22 pp |
| `0x2` | cuback | 1+1 | contender-last | all-flows | 10.0% | 10 ms | 400 | 20 ms | 36.94% | 26.83% | 71.08% | +23.53 pp |
| `0x6` | cuback | 1+1 | contender-last | contender-only | 0.1% | 80 ms | 400 | 20 ms | 52.97% | 40.49% | 56.75% | +0.11 pp |
| `0x6` | cuback | 1+1 | contender-last | contender-only | 1.0% | 40 ms | 400 | 12 ms | 59.57% | 48.84% | 48.69% | +0.29 pp |
| `0x6` | cuback | 1+1 | contender-last | all-flows | 1.0% | 40 ms | 400 | 12 ms | 49.00% | 38.42% | 59.08% | +1.11 pp |
| `0x6` | cuback | 1+1 | contender-last | all-flows | 0.1% | 5 ms | 4 | 5 ms | 58.88% | 48.53% | 62.07% | +0.12 pp |
| `0x6` | cuback | 1+1 | contender-first | contender-only | 1.0% | 80 ms | 400 | 20 ms | 57.62% | 47.33% | 49.87% | +0.12 pp |
| `0x6` | cuback | 1+1 | contender-last | all-flows | 10.0% | 10 ms | 400 | 20 ms | 38.08% | 28.22% | 69.64% | +19.83 pp |
| `0x6` | cubic | 1+1 | contender-last | all-flows | 10.0% | 10 ms | 400 | 20 ms | 37.32% | 27.49% | 70.34% | +21.54 pp |
| `0x6` | cuback | 1+1 | contender-first | all-flows | 10.0% | 10 ms | 400 | 20 ms | 38.53% | 28.75% | 69.16% | +19.86 pp |
| `0x6` | cuback | 1+1 | contender-first | all-flows | 0.1% | 80 ms | 400 | 20 ms | 49.60% | 39.90% | 57.30% | +0.06 pp |
| `0x6` | cubic | 1+1 | contender-first | all-flows | 10.0% | 10 ms | 400 | 20 ms | 38.88% | 29.25% | 68.65% | +19.46 pp |
