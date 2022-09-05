require 'benchmark'
require 'json'
require 'ruston'

N = 50000
R = Ruston.new

SIMPLE = %q({"Hello": "world", "lireral": true, "numeric": 1})

BIG = Hash.new.tap{|ha|
  (1..100).each {|i|
    ha["key#{i}"] = i
  }

  # (101..110).each {|i|
  #   ha["key#{i}"] = Hash.new
  #   (1..10).each {|j|
  #     ha["key#{i}"]["key2#{j}"] = i * j
  #   }
  # }
}.to_json
# M = 10

Benchmark.bmbm do |x|
  x.report("json obj") { N.times { JSON.parse(SIMPLE) } }
  x.report("ruston obj") { N.times { R.parse(SIMPLE) } }
end
