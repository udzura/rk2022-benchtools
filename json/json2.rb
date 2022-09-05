require 'benchmark'
require 'json'

SIMPLE = '[' + (1..50).to_a.map{|v|v%2==0}.join(",") + ']'

if ENV['C']
  puts $$
  $stdin.gets
end

N = ENV['N']&.to_i || 10000
Benchmark.bm do |x|
  x.report("json obj") { N.times { JSON.parse(SIMPLE) } }
end

