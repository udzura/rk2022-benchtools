require 'benchmark'
require 'ruston'

if ENV['C']
    puts $$
      $stdin.gets
end

# N = 100000
# M = 10
N = ENV['N']&.to_i || 10000

Benchmark.bm do |x|
  SIMPLE = %q({"Hello": "world", "lireral": true, "numeric": 1})
  r = Ruston.new
  x.report("ruston obj") { N.times { r.parse(SIMPLE) } }
end
