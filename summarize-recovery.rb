require 'csv'

root = File.expand_path(__dir__)
logdir = File.join(root, 'results', 'recovery')
output = File.join(root, 'results', 'lte-ca-recovery-summary.csv')

median = lambda do |values|
  sorted = values.sort
  size = sorted.length
  size.odd? ? sorted[size / 2] : (sorted[size / 2 - 1] + sorted[size / 2]) / 2
end

percentile = lambda do |values, probability|
  sorted = values.sort
  sorted[(probability * (sorted.length - 1)).round]
end

periods = (1..10).map do |period|
  samples = Dir.glob(File.join(logdir, 'cubic-ackclock-LTE-*.txt')).sort.map do |path|
    line = File.foreach(path).find { |candidate| candidate.match?(/^BENCH_RECOVERY ack #{period} /) }
    raise "missing recovery record for CA period #{period} in #{path}" unless line
    fields = line.split
    {
      expected: Float(fields[4]),
      actual: Float(fields[5]),
      dominant: fields[11],
      fast_convergence: Integer(fields[12])
    }
  end
  raise "expected 100 samples for CA period #{period}, got #{samples.length}" unless samples.length == 100

  rng = Random.new(30_000 + period)
  bootstrap = {expected: [], actual: [], ratio: []}
  20_000.times do
    resample = Array.new(samples.length) { samples[rng.rand(samples.length)] }
    bootstrap[:expected] << median.call(resample.map { |sample| sample[:expected] })
    bootstrap[:actual] << median.call(resample.map { |sample| sample[:actual] })
    bootstrap[:ratio] << median.call(resample.map { |sample| sample[:expected] / sample[:actual] })
  end

  result = {
    period: period,
    fast_convergence: samples.count { |sample| sample[:fast_convergence] == 1 },
    cubic_dominant: samples.count { |sample| sample[:dominant] == 'cubic' }
  }
  [:expected, :actual].each do |key|
    result[key] = median.call(samples.map { |sample| sample[key] })
    result[:"#{key}_low"] = percentile.call(bootstrap[key], 0.025)
    result[:"#{key}_high"] = percentile.call(bootstrap[key], 0.975)
  end
  result[:ratio] = median.call(samples.map { |sample| sample[:expected] / sample[:actual] })
  result[:ratio_low] = percentile.call(bootstrap[:ratio], 0.025)
  result[:ratio_high] = percentile.call(bootstrap[:ratio], 0.975)
  result
end

columns = {
  period: :period,
  nominal_x_seconds: :expected,
  nominal_x_ci_low: :expected_low,
  nominal_x_ci_high: :expected_high,
  actual_y_seconds: :actual,
  actual_y_ci_low: :actual_low,
  actual_y_ci_high: :actual_high,
  x_over_y: :ratio,
  x_over_y_ci_low: :ratio_low,
  x_over_y_ci_high: :ratio_high,
  fast_convergence_runs: :fast_convergence,
  cubic_dominant_runs: :cubic_dominant
}
CSV.open(output, 'w') do |csv|
  csv << columns.keys
  periods.each { |period| csv << columns.values.map { |column| period[column] } }
end

puts '| CA period | X: nominal time (s) | Y: actual time (s) | X/Y | Fast convergence | Cubic dominant |'
puts '|---:|---:|---:|---:|---:|---:|'
periods.each do |period|
  puts format('| %d | %.3f [%.3f, %.3f] | %.3f [%.3f, %.3f] | %.3f [%.3f, %.3f] | %d/100 | %d/100 |',
              period[:period], period[:expected], period[:expected_low], period[:expected_high], period[:actual],
              period[:actual_low], period[:actual_high], period[:ratio], period[:ratio_low], period[:ratio_high],
              period[:fast_convergence], period[:cubic_dominant])
end
warn output
