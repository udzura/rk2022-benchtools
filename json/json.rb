require 'benchmark'
require 'json'

if ENV['C']
  puts $$
  $stdin.gets
end

N = ENV['N']&.to_i || 10000
Benchmark.bm do |x|
  SIMPLE = %q({"Hello": "world", "lireral": true, "numeric": 1})
  x.report("json obj") { N.times { JSON.parse(SIMPLE) } }
end

