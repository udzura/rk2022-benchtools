require 'benchmark'
require 'json'

N = 10000
# M = 10

Benchmark.bmbm do |x|
  SIMPLE = %q({"Hello": "world", "lireral": true, "numeric": 1})
  x.report("json obj") { N.times { JSON.parse(SIMPLE) } }
end
