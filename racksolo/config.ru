run lambda {|_env|
  return [200,
          {"Content-Type" => "text/plain"},
          ["OK Rack"]]
}
