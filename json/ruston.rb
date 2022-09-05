require 'benchmark'
require 'ruston'

# N = 100000
# M = 10
N = 10000

Benchmark.bm do |x|
  SIMPLE = %q({"Hello": "world", "lireral": true, "numeric": 1})
  r = Ruston.new
  x.report("ruston obj") { N.times { r.parse(SIMPLE) } }
end
