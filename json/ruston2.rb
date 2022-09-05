require 'benchmark'
require 'ruston'

SIMPLE = '[' + (1..50).to_a.map{|v|v%2==0}.join(",") + ']'

if ENV['C']
    puts $$
      $stdin.gets
end

# N = 100000
# M = 10
N = ENV['N']&.to_i || 10000

Benchmark.bm do |x|
  r = Ruston.new
  x.report("ruston obj") { N.times { r.parse(SIMPLE) } }
end
