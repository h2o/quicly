require 'fileutils'
require 'open3'
require 'thread'

SIMULATOR = ENV.fetch('SIMULATOR', './build/default/simulator')
WORKERS = Integer(ENV.fetch('WORKERS', '8'))
DURATION = 200

NETWORKS = {
  'DSL' => {rtt: 0.03, queue: 0.05, bandwidth: 30_000_000.0 / 8},
  'Half_DSL' => {rtt: 0.03, queue: 0.05, bandwidth: 15_000_000.0 / 8},
  'Quarter_DSL' => {rtt: 0.03, queue: 0.05, bandwidth: 7_500_000.0 / 8},
  'Eighth_DSL' => {rtt: 0.03, queue: 0.05, bandwidth: 3_750_000.0 / 8},
  'LTE' => {rtt: 0.06, queue: 0.12, bandwidth: 30_000_000.0 / 8},
  '5G' => {rtt: 0.04, queue: 0.08, bandwidth: 100_000_000.0 / 8}
}.freeze

POLICIES = {
  'traditional' => ['-c', 'cubic-traditional', '-i', '30', '-p'],
  'bdp' => ['-c', 'cubic-bdp', '-i', '30', '-j', '60', '-p', '-R'],
  'bdp-nofc' => ['-c', 'cubic-bdp-nofc', '-i', '30', '-j', '60', '-p', '-R'],
  'head' => ['-c', 'cubic', '-i', '30', '-j', '60', '-p', '-R']
}.freeze

selected = ARGV.empty? ? NETWORKS.keys : ARGV
unknown = selected - NETWORKS.keys
abort "unknown network profile(s): #{unknown.join(', ')}" unless unknown.empty?

outdir = File.join(__dir__, 'results', 'raw')
FileUtils.mkdir_p(outdir)
jobs = Queue.new
selected.each do |network|
  geometry = NETWORKS.fetch(network)
  POLICIES.each do |policy, options|
    100.times do |index|
      seed = index + 1
      start = 20 + index / 20 * 5
      jobs << [network, geometry, policy, options, seed, start]
    end
  end
end

errors = []
lock = Mutex.new
completed = 0
total = jobs.length
workers = WORKERS.times.map do
  Thread.new do
    loop do
      begin
        network, geometry, policy, options, seed, start = jobs.pop(true)
      rescue ThreadError
        break
      end
      begin
        step = geometry[:rtt] * 5
        env = {
          'BENCH_SEED' => seed.to_s,
          'BENCH_SHARE_ANCHOR' => start.to_s,
          'BENCH_SHARE_STEP' => step.to_s,
          'BENCH_SHARE_WINDOW_BINS' => '1',
          'BENCH_SHARE_DURATION' => DURATION.to_s,
          'BENCH_SHARE_SRC' => '3'
        }
        command = [SIMULATOR,
                   '-d', geometry[:rtt].to_s, '-q', geometry[:queue].to_s, '-b', geometry[:bandwidth].to_s,
                   '-l', (start + DURATION).to_s,
                   '--', '-c', 'cubic', '-i', '30', '-p',
                   '--', *options, '-s', start.to_s]
        stdout, stderr, status = Open3.capture3(env, *command)
        raise "#{network}/#{policy}/#{seed}: simulator failed: #{stderr}" unless status.success?

        rows = []
        stdout.each_line do |line|
          match = /^BENCH_SHARE ([0-9.]+) ([0-9.]+)/.match(line)
          rows << "#{match[1]},#{match[2]}\n" if match
        end
        expected = (DURATION / step).floor
        raise "#{network}/#{policy}/#{seed}: #{rows.length} samples, expected #{expected}" unless rows.length == expected
        File.write(File.join(outdir, "#{policy}-#{network}-#{start}-#{seed}.csv"), rows.join)
      rescue => e
        lock.synchronize { errors << e.full_message }
      ensure
        lock.synchronize do
          completed += 1
          warn "completed #{completed}/#{total}" if completed % 20 == 0 || completed == total
        end
      end
    end
  end
end
workers.each(&:join)
abort errors.join("\n") unless errors.empty?
puts outdir
