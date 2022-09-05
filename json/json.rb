require 'benchmark'
require 'json'

N = 10000
Benchmark.bm do |x|
  SIMPLE = %q({"Hello": "world", "lireral": true, "numeric": 1})
  x.report("json obj") { N.times { JSON.parse(SIMPLE) } }
end

