require "json"
require "open3"
require "thread"

SIMULATOR = ENV.fetch("SIMULATOR")
OUTPUT = ENV.fetch("OUTPUT")
THREADS = Integer(ENV.fetch("THREADS"))
TOTAL_SLOTS = Integer(ENV.fetch("TOTAL_SLOTS"))
SLOT_BEGIN = Integer(ENV.fetch("SLOT_BEGIN"))
SLOT_END = Integer(ENV.fetch("SLOT_END"))
PACKET_SIZE = 1280.0
ABBA_FLAGS = Integer(ENV.fetch("ABBA_FLAGS", "2"))

RTTS = [0.005, 0.01, 0.02, 0.04, 0.08].freeze
BDPS = [4, 25, 100, 400].freeze
QUEUE_SPECS = [
  ["2ms", ->(_rtt) { 0.002 }],
  ["5ms", ->(_rtt) { 0.005 }],
  ["10ms", ->(_rtt) { 0.010 }],
  ["20ms", ->(_rtt) { 0.020 }],
  ["0.3rt", ->(rtt) { rtt * 0.3 }],
  ["1rt", ->(rtt) { rtt }],
  ["2rt", ->(rtt) { rtt * 2 }]
].freeze
LOSS_TARGETS = [0.0, 0.001, 0.01, 0.10].freeze
CCS = %w[cubic cuback].freeze
INCUMBENT_COUNTS = [1, 4].freeze
ORDERS = %w[contender-first contender-last].freeze
VARIANTS = [["stock", 0], ["abba-0x#{ABBA_FLAGS.to_s(16)}", ABBA_FLAGS]].freeze
REPETITIONS = 10
TARGET_PERIODS = 50.0
MIN_MEASUREMENT_RTTS = 200.0
HEADER = %w[job_id repetition cc rtt_ms bdp_packets bandwidth_mbps queue_spec queue_ms queue_packets loss_per_full_flight
            per_packet_loss loss_scope incumbents order variant incumbent_throughput_pct contender_throughput_pct
            utilization_pct contender_share_pct incumbent_loss_episodes contender_loss_episodes duration_seconds elapsed_seconds
            expected_periods measurement_rtts status error].join("\t")

def networks
  values = []
  RTTS.each do |rtt|
    BDPS.each do |bdp|
      bytes_per_second = bdp * PACKET_SIZE / rtt
      bits_per_second = bytes_per_second * 8
      next if bits_per_second < 100_000 || bits_per_second > 1_000_000_000

      seen_depths = {}
      QUEUE_SPECS.each do |label, calculate|
        queue = calculate.call(rtt)
        relative = [rtt * 0.3, rtt, rtt * 2].any? { |candidate| (queue - candidate).abs < 1e-9 }
        fixed = [0.002, 0.005, 0.010, 0.020].any? { |candidate| (queue - candidate).abs < 1e-9 } &&
                queue <= [rtt * 0.3, 0.002].max
        next if queue < 0.002 || !(relative || fixed)
        queue_packets = bytes_per_second * queue / PACKET_SIZE
        next if queue_packets < 1
        depth_key = (queue * 1_000_000).round
        next if seen_depths.key?(depth_key)
        seen_depths[depth_key] = true
        values << {rtt: rtt, bdp: bdp, bytes_per_second: bytes_per_second, queue: queue,
                   queue_packets: queue_packets, queue_spec: label}
      end
    end
  end
  values
end

def packet_loss_probability(network, target)
  return 0.0 if target == 0
  full_flight_packets = network.fetch(:bdp) + network.fetch(:queue_packets)
  1 - (1 - target)**(1.0 / full_flight_packets)
end

def jobs
  values = []
  networks.each do |network|
    LOSS_TARGETS.each do |target|
      scopes = target == 0 ? ["clean"] : %w[contender-only all-flows]
      scopes.each do |scope|
        VARIANTS.each do |variant, flags|
          CCS.each do |cc|
            INCUMBENT_COUNTS.each do |incumbents|
              ORDERS.each do |order|
                REPETITIONS.times do |repetition|
                  values << {network: network, target: target, scope: scope, variant: variant, flags: flags,
                             cc: cc, incumbents: incumbents, order: order, repetition: repetition}
                end
              end
            end
          end
        end
      end
    end
  end
  values
end

def run(job)
    network = job.fetch(:network)
  probability = packet_loss_probability(network, job.fetch(:target))
  num_flows = job.fetch(:incumbents) + 1
  fair_window = network.fetch(:bdp).to_f / num_flows
  fair_window = 1 if fair_window < 1
  capacity_loss_reno = [3.0 / (2 * fair_window**2), 1.0].min
  capacity_loss_cubic = [network.fetch(:rtt) * (1.054 / fair_window)**(4.0 / 3), 1.0].min
  flow_probabilities = [probability]
  flow_probabilities << (job.fetch(:scope) == "all-flows" ? probability : 0)
  measurement_rtts = flow_probabilities.map do |random_loss|
    effective_loss = [random_loss, capacity_loss_reno, capacity_loss_cubic].max
    w_reno = Math.sqrt(3.0 / (2 * effective_loss))
    w_cubic = 1.054 * (network.fetch(:rtt) / effective_loss)**0.75
    window = [[w_reno, w_cubic].max, fair_window].min
    TARGET_PERIODS / (effective_loss * window)
  end.max
  measurement_rtts = MIN_MEASUREMENT_RTTS if measurement_rtts < MIN_MEASUREMENT_RTTS
  duration = 2 * measurement_rtts * network.fetch(:rtt)
  contender = ["-r", probability.to_s]
  contender.concat(["-X", job.fetch(:flags).to_s]) if job.fetch(:flags) != 0
  incumbent_loss = job.fetch(:scope) == "all-flows" ? probability : 0
  incumbent = ["-r", incumbent_loss.to_s]
  flows = Array.new(job.fetch(:incumbents)) { incumbent.dup }
  contender_index = job.fetch(:order) == "contender-first" ? 0 : flows.length
  flows.insert(contender_index, contender)

  command = [SIMULATOR, "-C", "-d", network.fetch(:rtt).to_s, "-q", network.fetch(:queue).to_s,
             "-b", network.fetch(:bytes_per_second).to_s, "-l", duration.to_s, "-c", job.fetch(:cc), "-p"]
  flows.each { |flow| command.concat(["--", *flow]) }

  started_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  output, error, status = Open3.capture3(*command)
  raise "simulator failed: #{command.join(" ")}: #{error}" unless status.success?

  summary = output.each_line.map { |line| JSON.parse(line) }.to_h do |event|
    [[event.fetch("cc-stats"), event.fetch("packet-src").to_s], event]
  end
  rates = flows.each_index.map do |index|
    src = (index + 2).to_s
    base = summary.fetch(["measurement-start", src]).fetch("data-off")
    final = summary.fetch(["measurement-end", src]).fetch("data-off")
    (final - base) / (duration / 2) / network.fetch(:bytes_per_second) * 100
  end
  episodes = flows.each_index.map do |index|
    src = (index + 2).to_s
    summary.fetch(["measurement-end", src]).fetch("num-loss-episodes") -
      summary.fetch(["measurement-start", src]).fetch("num-loss-episodes")
  end
  contender_rate = rates.fetch(contender_index)
  incumbent_rate = rates.sum - contender_rate
  contender_episodes = episodes.fetch(contender_index)
  incumbent_episodes = episodes.sum - contender_episodes
  utilization = rates.sum
  elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started_at
  [incumbent_rate, contender_rate, utilization, utilization != 0 ? contender_rate / utilization * 100 : 0,
   incumbent_episodes, contender_episodes, duration, elapsed, probability, measurement_rtts]
end

all_jobs = jobs
if ENV["COUNT_ONLY"]
  puts "networks=#{networks.length} jobs=#{all_jobs.length}"
  exit
end
selected = all_jobs.each_with_index.select do |_job, index|
  slot = index % TOTAL_SLOTS
  SLOT_BEGIN <= slot && slot < SLOT_END
end
completed = if File.exist?(OUTPUT)
              File.foreach(OUTPUT).filter_map do |line|
                next if line.start_with?("job_id\t")
                fields = line.chomp.split("\t", -1)
                fields.first if fields[-2] == "ok"
              end
                                  .to_h { |id| [id, true] }
            else
              {}
            end
selected.reject! { |_job, index| completed.key?(index.to_s) }
selected.shuffle!(random: Random.new(1))
selected = selected.drop(Integer(ENV.fetch("SKIP_SELECTED", "0")))

output_exists = File.exist?(OUTPUT) && File.size(OUTPUT) != 0
File.open(OUTPUT, output_exists ? "a" : "w") do |file|
  file.puts HEADER unless output_exists
  file.flush
  queue = Queue.new
  selected.each { |entry| queue << entry }
  lock = Mutex.new
  count = 0
  started_at = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  workers = [THREADS, selected.length].min.times.map do
    Thread.new do
      loop do
        begin
            job, index = queue.pop(true)
        rescue ThreadError
          break
        end
        error = nil
        begin
          result = run(job)
        rescue => exception
          result = Array.new(10, Float::NAN)
          result[8] = packet_loss_probability(job.fetch(:network), job.fetch(:target))
          error = exception.message
        end
        network = job.fetch(:network)
        row = [index, job.fetch(:repetition), job.fetch(:cc), network.fetch(:rtt) * 1000, network.fetch(:bdp),
               network.fetch(:bytes_per_second) * 8 / 1_000_000, network.fetch(:queue_spec), network.fetch(:queue) * 1000,
               network.fetch(:queue_packets), job.fetch(:target), result.fetch(8), job.fetch(:scope), job.fetch(:incumbents),
               job.fetch(:order), job.fetch(:variant), *result.first(8), TARGET_PERIODS, result.fetch(9),
               error == nil ? "ok" : "error", error]
        lock.synchronize do
          file.puts row.map { |value| value.is_a?(Float) ? format("%.9g", value) : value }.join("\t")
          file.flush
          count += 1
          if count % 10 == 0 || count == selected.length
            elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started_at
            warn format("completed %d/%d shard jobs in %.1fs (%.2f jobs/s)", count, selected.length, elapsed, count / elapsed)
          end
        end
      end
    end
  end
  workers.each(&:join)
end

warn "finished #{selected.length} of #{all_jobs.length} total jobs"
