require 'fileutils'
require 'open3'
require 'thread'

SIMULATOR = ENV.fetch('SIMULATOR', './build/default/simulator')
WORKERS = Integer(ENV.fetch('WORKERS', '8'))
DURATION = 200

NETWORKS = {
  'LTE' => {rtt: 0.06, queue: 0.12, bandwidth: 30_000_000.0 / 8}
}.freeze

POLICIES = {
  'cubic' => ['-c', 'cubic', '-i', '30', '-j', '60', '-p', '-R'],
  'cubic-ackclock' => ['-c', 'cubic-ackclock', '-i', '30', '-j', '60', '-p', '-R'],
  'cuback' => ['-c', 'cuback', '-i', '30', '-j', '60', '-p', '-R']
}.freeze

selected = ARGV.empty? ? NETWORKS.keys : ARGV
unknown = selected - NETWORKS.keys
abort "unknown network profile(s): #{unknown.join(', ')}" unless unknown.empty?

outdir = File.join(__dir__, 'results', 'raw')
FileUtils.mkdir_p(outdir)
recovery_outdir = File.join(__dir__, 'results', 'recovery')
FileUtils.mkdir_p(recovery_outdir)
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
        recovery_rows = []
        stdout.each_line do |line|
          match = /^BENCH_SHARE ([0-9.]+) ([0-9.]+)/.match(line)
          rows << "#{match[1]},#{match[2]}\n" if match
          recovery_rows << line if line.start_with?('BENCH_RECOVERY')
        end
        expected = (DURATION / step).floor
        raise "#{network}/#{policy}/#{seed}: #{rows.length} samples, expected #{expected}" unless rows.length == expected
        if policy == 'cubic-ackclock'
          1.upto(10) do |episode|
            count = recovery_rows.count { |line| line.match?(/^BENCH_RECOVERY ack #{episode} /) }
            raise "#{network}/#{policy}/#{seed}: #{count} recovery records for CA period #{episode}, expected 1" unless count == 1
          end
        end
        File.write(File.join(outdir, "#{policy}-#{network}-#{start}-#{seed}.csv"), rows.join)
        if policy == 'cubic-ackclock'
          File.write(File.join(recovery_outdir, "#{policy}-#{network}-#{start}-#{seed}.txt"), recovery_rows.join)
        end
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
