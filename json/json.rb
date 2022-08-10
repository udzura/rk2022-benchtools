require 'benchmark'
require 'json'

N = 100000 * 10
# M = 10

Benchmark.bmbm do |x|
  SIMPLE = %q({"Hello": "world", "lireral": true, "numeric": 1})
  x.report("ruston obj") { N.times { JSON.parse(SIMPLE) } }
end
