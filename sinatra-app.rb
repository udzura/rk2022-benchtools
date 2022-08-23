require 'sinatra'

$count = 0
$leak = []
$next = 100

puts "LEAK MODE: #{! ENV["LEAKY"].nil?}"

get '/' do
  $count += 1
  $leak << (1..100).map { Object.new }
  
  if !ENV["LEAKY"] && $count >= $next
    puts "Release objects!"
    $leak = []
    $next += 100
  end
  "OK"
end
