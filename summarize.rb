require "json"
require "zlib"

KEY_FIELDS = %w[cc rtt_ms bdp_packets bandwidth_mbps queue_spec queue_ms queue_packets plr_per_rt loss_scope incumbents order].freeze
METRIC_FIELDS = %w[incumbent contender utilization contender_share].freeze

DATASETS = {
  ["baseline", 2] => Dir[File.join(__dir__, "results/raw/baseline-0x2-*.ldjson.gz")].sort,
  ["baseline", 6] => [File.join(__dir__, "results/raw/baseline-0x6.ldjson.gz")],
  ["guarded", 2] => [File.join(__dir__, "results/raw/guarded-0x2.ldjson.gz")],
  ["guarded", 6] => [File.join(__dir__, "results/raw/guarded-0x6.ldjson.gz")]
}.freeze

def percentile(values, fraction)
  sorted = values.sort
  position = (sorted.length - 1) * fraction
  lower = position.floor
  upper = position.ceil
  sorted.fetch(lower) + (sorted.fetch(upper) - sorted.fetch(lower)) * (position - lower)
end

def load_dataset(paths, flags)
  grouped = Hash.new { |hash, key| hash[key] = [] }
  paths.each do |path|
    Zlib::GzipReader.open(path) do |input|
      input.each_line do |line|
        record = JSON.parse(line)
        key = record.fetch("key")
        variant = key.fetch(11)
        next unless variant == "stock" || variant == "abba-0x#{flags.to_s(16)}"
        grouped[key].concat(record.fetch("samples"))
      end
    end
  end

  scenarios = Hash.new { |hash, key| hash[key] = {} }
  grouped.each do |key, samples|
    variant = key.fetch(11)
    scenario_key = key.first(11)
    by_repetition = samples.to_h { |sample| [Integer(sample.fetch(0)), sample] }
    raise "#{scenario_key.inspect}/#{variant}: expected 10 repetitions, got #{by_repetition.length}" unless by_repetition.length == 10
    scenarios[scenario_key][variant] = by_repetition.values.sort_by(&:first)
  end

  expected_variants = ["stock", "abba-0x#{flags.to_s(16)}"]
  scenarios.each do |key, variants|
    missing = expected_variants - variants.keys
    raise "#{key.inspect}: missing #{missing.join(', ')}" unless missing.empty?
  end
  scenarios
end

def metric(samples, index)
  samples.map { |sample| Float(sample.fetch(index)) }
end

def scenario_values(key, variants, flags)
  incumbents = Integer(key.fetch(9))
  stock = variants.fetch("stock")
  abba = variants.fetch("abba-0x#{flags.to_s(16)}")
  stock_incumbent = metric(stock, 1).map { |value| value / incumbents }
  abba_incumbent = metric(abba, 1).map { |value| value / incumbents }
  stock_contender = metric(stock, 2)
  abba_contender = metric(abba, 2)
  stock_utilization = metric(stock, 3)
  abba_utilization = metric(abba, 3)
  {
    stock_incumbent: stock_incumbent,
    abba_incumbent: abba_incumbent,
    stock_contender: stock_contender,
    abba_contender: abba_contender,
    stock_utilization: stock_utilization,
    abba_utilization: abba_utilization,
    incumbent_loss: percentile(stock_incumbent, 0.5) - percentile(abba_incumbent, 0.5),
    contender_gain: percentile(abba_contender, 0.5) - percentile(stock_contender, 0.5),
    utilization_change: percentile(abba_utilization, 0.5) - percentile(stock_utilization, 0.5),
    clear_harm: percentile(abba_incumbent, 0.9) < percentile(stock_incumbent, 0.1)
  }
end

loaded = DATASETS.to_h { |name, paths| [name, load_dataset(paths, name.fetch(1))] }
counts = {}
distributions = {}
loaded.each do |(revision, flags), scenarios|
  %w[cubic cuback].each do |cc|
    rows = scenarios.each_with_object([]) do |(key, variants), selected|
      selected << scenario_values(key, variants, flags) if key.fetch(0) == cc
    end
    counts[[revision, flags, cc]] = [rows.count { |row| row.fetch(:clear_harm) }, rows.length]
    distributions[[revision, flags, cc]] = rows
  end
end

lines = []
lines << "# ABBA recalibration-suppression results"
lines << ""
lines << "Every cell is calculated from ten repetitions. An incumbent is clearly harmed when the ABBA run's per-incumbent P90 is"
lines << "below the matching stock/stock run's per-incumbent P10. This deliberately compares ABBA against the bandwidth that stock"
lines << "actually left to an incumbent, rather than against an assumed equal share."
lines << ""
lines << "## Clear incumbent harm"
lines << ""
lines << "| ABBA flags | CC | Before guards | With guards |"
lines << "|---:|---|---:|---:|"
[2, 6].each do |flags|
  %w[cubic cuback].each do |cc|
    before = counts.fetch(["baseline", flags, cc])
    after = counts.fetch(["guarded", flags, cc])
    lines << "| `0x#{flags.to_s(16)}` | #{cc} | #{before[0]} / #{before[1]} | #{after[0]} / #{after[1]} |"
  end
end

lines << ""
lines << "## Distribution of median changes with the guards"
lines << ""
lines << "Values are percentage-point changes relative to the matching stock/stock run. Positive incumbent loss means that the stock"
lines << "incumbent received less bandwidth when its contender used ABBA."
lines << ""
lines << "| Flags | CC | Incumbent loss P50 | P90 | P99 | Contender gain P50 | Utilization change P50 |"
lines << "|---:|---|---:|---:|---:|---:|---:|"
[2, 6].each do |flags|
  %w[cubic cuback].each do |cc|
    rows = distributions.fetch(["guarded", flags, cc])
    loss = rows.map { |row| row.fetch(:incumbent_loss) }
    gain = rows.map { |row| row.fetch(:contender_gain) }
    utilization = rows.map { |row| row.fetch(:utilization_change) }
    lines << format("| `0x%x` | %s | %.4f | %.4f | %.4f | %.4f | %.4f |", flags, cc,
                    percentile(loss, 0.5), percentile(loss, 0.9), percentile(loss, 0.99), percentile(gain, 0.5),
                    percentile(utilization, 0.5))
  end
end

lines << ""
lines << "## Reproduced regression"
lines << ""
lines << "Cuback, 80 ms idle RTT, BDP 400 packets, 10 ms queue, two flows, and no random loss:"
lines << ""
lines << "| Flags | Order | Revision | Incumbent median | Contender median | Utilization median |"
lines << "|---:|---|---|---:|---:|---:|"
[2, 6].each do |flags|
  ["contender-first", "contender-last"].each do |order|
    ["baseline", "guarded"].each do |revision|
      scenarios = loaded.fetch([revision, flags])
      key, variants = scenarios.find do |candidate, _|
        candidate.fetch(0) == "cuback" && Float(candidate.fetch(1)) == 80 && Integer(candidate.fetch(2)) == 400 &&
          Float(candidate.fetch(5)) == 10 && Float(candidate.fetch(7)) == 0 && candidate.fetch(8) == "clean" &&
          Integer(candidate.fetch(9)) == 1 && candidate.fetch(10) == order
      end
      raise "target scenario missing" if key.nil?
      values = scenario_values(key, variants, flags)
      lines << format("| `0x%x` | %s | %s | %.2f%% | %.2f%% | %.2f%% |", flags, order, revision,
                      percentile(values.fetch(:abba_incumbent), 0.5), percentile(values.fetch(:abba_contender), 0.5),
                      percentile(values.fetch(:abba_utilization), 0.5))
    end
  end
end

lines << ""
lines << "## Largest residual incumbent losses with the guards"
lines << ""
lines << "The table lists the ten scenarios with the greatest reduction in median per-incumbent throughput for each mode."
lines << ""
lines << "| Flags | CC | Flows | Order | Loss scope | PLR/RT | RTT | BDP | Queue | Stock incumbent | ABBA incumbent | ABBA contender | Utilization change |"
lines << "|---:|---|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|"
[2, 6].each do |flags|
  rows = loaded.fetch(["guarded", flags]).map do |key, variants|
    [key, scenario_values(key, variants, flags)]
  end.sort_by { |_key, values| -values.fetch(:incumbent_loss) }.first(10)
  rows.each do |key, values|
    lines << format("| `0x%x` | %s | %d+1 | %s | %s | %.1f%% | %.0f ms | %d | %.0f ms | %.2f%% | %.2f%% | %.2f%% | %+.2f pp |",
                    flags, key.fetch(0), Integer(key.fetch(9)), key.fetch(10), key.fetch(8), Float(key.fetch(7)) * 100,
                    Float(key.fetch(1)), Integer(key.fetch(2)), Float(key.fetch(5)),
                    percentile(values.fetch(:stock_incumbent), 0.5), percentile(values.fetch(:abba_incumbent), 0.5),
                    percentile(values.fetch(:abba_contender), 0.5), values.fetch(:utilization_change))
  end
end

output = ARGV.fetch(0, File.join(__dir__, "results/summary.md"))
File.write(output, lines.join("\n") + "\n")
warn "wrote #{output}"
