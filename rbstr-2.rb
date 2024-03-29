require 'rbbcc'
include RbBCC

prog = <<PROG
#include <uapi/linux/ptrace.h>

BPF_HISTOGRAM(dist);
BPF_HISTOGRAM(size);
BPF_HASH(start, u32);
BPF_HASH(is_long, u32, u8);

struct ruby_value_t {
  u64 flags;
  u64 klass;
  u64 len;
  u64 ptr;
};

struct ruby_string_t {
  char str[32];
};

BPF_HASH(longlen, u64, u64);
BPF_HASH(longstr, u64, struct ruby_string_t);

static u32 log10(u64 value) {
  if (value == 0) { return 0; }
  u32 log = 0;
  for (int i = 0; i < 32; i++) {
    value = value / 10;
    if (value == 0)
      return log;
    log += 1;
  }
  return log;
}

int rb_str_new_begin(struct pt_regs *ctx) {
  u64 ts = bpf_ktime_get_ns();
  u32 tid = bpf_get_current_pid_tgid();

  start.update(&tid, &ts);

  u64 len = (u64)PT_REGS_PARM2(ctx);
  size.increment(bpf_log2l(len));

  if (len > 64) {
    u8 is = 1;
    is_long.update(&tid, &is);
  }

  return 0;
}

int rb_str_new_return(struct pt_regs *ctx) {
  u64 *tsp, delta;
  u8 *is;
  u32 tid = bpf_get_current_pid_tgid();

  tsp = start.lookup(&tid);
  if (tsp != 0) {
    delta = bpf_ktime_get_ns() - *tsp;
    start.delete(&tid);

    dist.increment(log10(delta));

    is = is_long.lookup(&tid);
    if (is != 0) {
      is_long.delete(&tid);
      struct ruby_value_t value = {0};
      struct ruby_string_t buf = {0};
      bpf_probe_read_user(&value, sizeof(buf), (struct ruby_value_t *)PT_REGS_RC(ctx));
      bpf_probe_read_user(&buf.str, 31, (char *)value.ptr);
      u64 key = bpf_ktime_get_ns();
      longlen.update(&key, &value.len);
      longstr.update(&key, &buf);
    }
  }
  return 0;
}
PROG

def usage
  puts("USAGE: #{$0} [RUBY_PATH] [PID]")
  exit()
end

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

      header = "   %-15s : count     distribution"
      body =   "   %-15s : %-8d |%-*s|"
      stars_max = 64

      if idx_max >= 0
        puts(header % "time range");
      end

      (0...(idx_max + 1)).each do |i|
        val = vals[i]
        val = val[0, 8].unpack("I")[0]

        range = "%s .. %s" % [
          to_time(10**i),
          to_time(10**(i+1))
        ]
        
        puts(body % [range, val, stars_max,
                     stars(val, val_max, stars_max)])
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
print_etime_hist(b["dist"])

puts
puts "created string size histogram"
puts "~~~~~~~~~~~~~~"
b["size"].print_log2_hist("bytes")

puts
puts "detected long strings:"
puts "~~~~~~~~~~~~~~"

b["longstr"].each {|k, v| p "#{k[0, 8].unpack("L")[0]}: #{v[0, 32]}..." }
