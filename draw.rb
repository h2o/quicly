root = File.expand_path(__dir__)
rundir = File.join(root, 'results', 'raw')
outdir = File.join(root, 'results')
Dir.mkdir(outdir) unless Dir.exist?(outdir)

profiles = {
  'LTE' => {label: 'LTE', bandwidth: 30.0, horizon: 50.0, rundir: rundir}
}
policies = {
  'cubic' => {label: 'CUBIC: wall clock + CUBIC estimator', color: '#0072B2'},
  'cubic-ackclock' => {label: 'hybrid: ACK clock + CUBIC estimator', color: '#009E73'},
  'cuback' => {label: 'Cuback: ACK clock + Cuback estimator', color: '#D55E00'}
}

profiles.each do |network, profile|
  ymax = profile[:bandwidth]
  xmax = profile[:horizon]

  series = policies.to_h do |policy, style|
    paths = Dir.glob(File.join(profile[:rundir], "#{policy}-#{network}-*.csv")).sort.map do |path|
      File.foreach(path).map do |line|
        time, share = line.split(',').map(&:to_f)
        [time, share * ymax]
      end
    end
    raise "expected 100 runs for #{network}/#{policy}, got #{paths.length}" unless paths.length == 100
    [policy, {style: style, paths: paths}]
  end

  width = 1800
  height = 950
  margin = {left: 105, right: 35, top: 95, bottom: 85}
  plot_width = width - margin[:left] - margin[:right]
  plot_height = height - margin[:top] - margin[:bottom]
  sx = ->(x) { margin[:left] + x / xmax * plot_width }
  sy = ->(y) { margin[:top] + (1 - [[y, 0].max, ymax].min / ymax) * plot_height }
  escape = ->(text) { text.gsub('&', '&amp;').gsub('<', '&lt;').gsub('>', '&gt;') }
  fmt_seconds = lambda do |value|
    if xmax >= 20
      format('%.0f', value)
    elsif xmax >= 4
      format('%.1f', value)
    else
      format('%.3f', value).sub(/0+$/, '').sub(/\.$/, '')
    end
  end

  basename = "lte-newcomer-ackclock-ablation"
  output = File.join(outdir, "#{basename}.svg")
  svg = +%(<?xml version="1.0" encoding="UTF-8"?>\n)
  svg << %(<svg xmlns="http://www.w3.org/2000/svg" width="#{width}" height="#{height}" viewBox="0 0 #{width} #{height}">\n)
  svg << %(<rect width="100%" height="100%" fill="white"/>\n)
  svg << %(<style>text { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; fill: #222; }</style>\n)
  svg << %(<text x="#{margin[:left]}" y="38" font-size="25" font-weight="600">#{profile[:label]} newcomer ACK-clock ablation across 300 runs</text>\n)
  svg << %(<text x="#{margin[:left]}" y="68" font-size="16" fill="#555">Horizontal span = #{fmt_seconds.call(xmax)} s; 100 paired phase/seed combinations per policy</text>\n)

  y_step = ymax / 3
  (0..3).each do |index|
    value = index * y_step
    y = sy.call(value)
    label = value == value.round ? value.round.to_s : format('%.2f', value).sub(/0+$/, '').sub(/\.$/, '')
    svg << %(<line x1="#{margin[:left]}" y1="#{y.round(2)}" x2="#{width - margin[:right]}" y2="#{y.round(2)}" stroke="#ddd"/>\n)
    svg << %(<text x="#{margin[:left] - 12}" y="#{(y + 5).round(2)}" text-anchor="end" font-size="14">#{label}</text>\n)
  end
  (0..5).each do |index|
    value = xmax * index / 5
    x = sx.call(value)
    svg << %(<line x1="#{x.round(2)}" y1="#{margin[:top]}" x2="#{x.round(2)}" y2="#{height - margin[:bottom]}" stroke="#eee"/>\n)
    svg << %(<text x="#{x.round(2)}" y="#{height - margin[:bottom] + 27}" text-anchor="middle" font-size="14">#{fmt_seconds.call(value)}</text>\n)
  end
  svg << %(<line x1="#{margin[:left]}" y1="#{height - margin[:bottom]}" x2="#{width - margin[:right]}" y2="#{height - margin[:bottom]}" stroke="#333"/>\n)
  svg << %(<line x1="#{margin[:left]}" y1="#{margin[:top]}" x2="#{margin[:left]}" y2="#{height - margin[:bottom]}" stroke="#333"/>\n)
  svg << %(<text x="#{margin[:left] + plot_width / 2}" y="#{height - 25}" text-anchor="middle" font-size="17">time since newcomer start (seconds)</text>\n)
  svg << %(<text x="25" y="#{margin[:top] + plot_height / 2}" text-anchor="middle" font-size="17" transform="rotate(-90 25 #{margin[:top] + plot_height / 2})">newcomer bandwidth (Mbit/s, trailing 5 RTT)</text>\n)
  svg << %(<defs><clipPath id="plot"><rect x="#{margin[:left]}" y="#{margin[:top]}" width="#{plot_width}" height="#{plot_height}"/></clipPath></defs>\n)
  svg << %(<g clip-path="url(#plot)">\n)

  100.times do |run|
    series.each_value do |entry|
      points = entry[:paths][run].take_while { |time, _| time <= xmax }
                                 .map { |time, bw| "#{sx.call(time).round(1)},#{sy.call(bw).round(1)}" }.join(' ')
      svg << %(<polyline points="#{points}" fill="none" stroke="#{entry[:style][:color]}" stroke-width="0.65" stroke-opacity="0.045"/>\n)
    end
  end

  series.each_value do |entry|
    count = entry[:paths][0].count { |time, _| time <= xmax }
    distributions = (0...count).map do |index|
      values = entry[:paths].map { |path| path[index][1] }.sort
      [entry[:paths][0][index][0], values[9], (values[49] + values[50]) / 2, values[89]]
    end
    [[1, 1.8, '8 6'], [2, 3, nil], [3, 1.8, '8 6']].each do |column, stroke_width, dash|
      points = distributions.map { |row| "#{sx.call(row[0]).round(1)},#{sy.call(row[column]).round(1)}" }.join(' ')
      dash_attr = dash ? %( stroke-dasharray="#{dash}") : ''
      svg << %(<polyline points="#{points}" fill="none" stroke="#{entry[:style][:color]}" stroke-width="#{stroke_width}"#{dash_attr} stroke-opacity="0.95"/>\n)
    end
  end
  svg << %(</g>\n)

  legend_x = margin[:left] + 18
  legend_y = margin[:top] + 20
  svg << %(<rect x="#{legend_x - 12}" y="#{legend_y - 18}" width="410" height="98" rx="5" fill="white" fill-opacity="0.9" stroke="#ccc"/>\n)
  series.each_value.with_index do |entry, index|
    y = legend_y + index * 28
    svg << %(<line x1="#{legend_x}" y1="#{y}" x2="#{legend_x + 38}" y2="#{y}" stroke="#{entry[:style][:color]}" stroke-width="4"/>\n)
    svg << %(<text x="#{legend_x + 50}" y="#{y + 5}" font-size="15">#{escape.call(entry[:style][:label])}</text>\n)
  end
  svg << %(</svg>\n)

  File.write(output, svg)
  puts "#{output} xmax=#{xmax}"
end
