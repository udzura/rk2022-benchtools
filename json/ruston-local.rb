require 'benchmark'
require_relative './ruston.so'

# N = 100000
# M = 10
N = 100000

Benchmark.bmbm do |x|
  SIMPLE = %q({"Hello": "world", "lireral": true, "numeric": 1})
  r = Ruston.new
  x.report("ruston obj") { N.times { r.parse(SIMPLE) } }
end
