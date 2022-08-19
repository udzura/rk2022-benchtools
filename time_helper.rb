def stars(val, val_max, width)
  i = 0
  text = ""
  while true
    break if (i > (width * val.to_f / val_max) - 1) || (i > width - 1)
    text += "*"
    i += 1
  end
  if val > val_max
    text = text[0...-1] + "+"
  end
  return text
end

def to_time(dur)
  case dur
  when (10**0)...(10**3)
    "%dns" % dur
  when (10**3)...(10**6)
    "%dμs" % (dur / 1000)
  when (10**6)...(10**9)
    "%dms" % (dur / 1000 / 1000)
  when (10**9)...(10**24)
    "%ds"  % (dur / 1000 / 1000 / 1000)
  end
end

def print_etime_hist(vals)
  idx_max = 0
  val_max = 0

  vals.each_with_index do |v, i|
    idx_max = i if v > 0
    val_max = v if v > val_max
  end

  header = "   %-16s : count     distribution"
  body =   "   %-16s : %-8d |%-*s|"
  stars_max = 48

  if idx_max >= 0
    puts(header % "time range");
  end

  (0...(idx_max + 1)).each do |i|
    val = vals[i]
    val = val[0, 8].unpack("I")[0]

    range = "%5s ... %5s" % [
      to_time(10**i),
      to_time(10**(i+1))
    ]
    
    puts(body % [range, val, stars_max,
                 stars(val, val_max, stars_max)])
  end
end
