require 'rbbcc'
include RbBCC

prog = <<PROG
BPF_HISTOGRAM(dist);
BPF_HASH(start, u32);

static u32 log10(u64 value) {
  if (u64 == 0) { return 0; }
  u32 log = 0;
  for (int i = 0; i < 32; i++) {
    value = value / 10;
    if (value == 0)
      return log;
    log += 1;
  }
  return log;
}

int rb_str_new_begin(void *ctx) {
  u64 ts = bpf_ktime_get_ns();
  u32 tid = bpf_get_current_pid_tgid();

  start.update(&tid, &ts);
  return 0;
}

int rb_str_new_return(void *ctx) {
  u64 *tsp, delta;
  u32 tid = bpf_get_current_pid_tgid();

  tsp = start.lookup(&tid);
  if (tsp != 0) {
    delta = bpf_ktime_get_ns() - *tsp;
    start.delete(&tid);

    dist.increment(log10(delta));
  }
  return 0;
}
PROG

def usage
  puts("USAGE: #{$0} [RUBY_PATH] [PID]")
  exit()
end

def stars(val, val_max, width)
  DisplayHelper.stars(val, val_max, width)
end

def to_time(dur)
  case dur
  when (10**0)..(10**3)
    "%dns" % dur
  when (10**3)..(10**6)
    "%dμs" % (dur / 1000)
  when (10**6)..(10**9)
    "%dms" % (dur / 1000 / 1000)
  when (10**9)..(10**24)
    "%ds"  % (dur / 1000 / 1000 / 1000)
  end
end

def print_etime_hist(vals)
      idx_max = 0
      val_max = 0

      vals.each do |i, v|
        idx_max = i if i > idx_max
        val_max = v if v > val_max
      end

      header = "     %-13s : count     distribution"
      body = "        %-10d : %-8d |%-*s|"
      stars = stars_max

      if idx_max >= 0
        puts(header % val_type);
      end

      (0...(idx_max + 1)).each do |i|
        val = vals[i]
        range = "%s .. %s" % [
          to_time(10**i),
          to_time(10**(i+1))
        ]
        
        puts(body % [range, val, stars,
                     stars(val, val_max, stars)])
      end
    end

usage if ARGV.size != 1 && ARGV.size != 2

path = ARGV[0]
pid = ARGV[1]&.to_i || -1

b = BCC.new(text: prog)
b.attach_uprobe(name: path, sym: "rb_str_new", fn_name: "rb_str_new_begin", pid: pid)
b.attach_uretprobe(name: path, sym: "rb_str_new", fn_name: "rb_str_new_return", pid: pid)

puts("collectiong data...")

loop do
  begin
    sleep 1
  rescue Interrupt
    puts
    break # pass
  end
end

puts "elapsed time histogram"
puts "~~~~~~~~~~~~~~"
# print_etime_hist(b["dist"])

b["dist"].print_linear_hist
