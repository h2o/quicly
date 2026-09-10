require "json"
require "zlib"

path = ARGV.fetch(0)
header = nil
rows = {}
input = path.end_with?(".gz") ? Zlib::GzipReader.open(path) : File.open(path)
input.each_line do |line|
  fields = line.chomp.split("\t", -1)
  if fields.first == "job_id"
    header ||= fields
    next
  end
  row = header.zip(fields).to_h
  rows[row.fetch("job_id")] = row if row.fetch("status") == "ok"
end
input.close

key_fields = %w[cc rtt_ms bdp_packets bandwidth_mbps queue_spec queue_ms queue_packets loss_per_full_flight loss_scope incumbents order
                variant]
metric_fields = %w[incumbent_throughput_pct contender_throughput_pct utilization_pct contender_share_pct]
rows.values.group_by { |row| key_fields.map { |field| row.fetch(field) } }.sort.each do |key, group|
  samples = group.sort_by { |row| Integer(row.fetch("repetition")) }.map do |row|
    [Integer(row.fetch("repetition")), *metric_fields.map { |field| Float(row.fetch(field)) }]
  end
  puts JSON.generate({key: key, samples: samples})
end
