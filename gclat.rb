require 'rbbcc'
require_relative 'time_helper'
include RbBCC

def usage
  puts("USAGE: #{$0} mark|sweep PID [RUBY_PATH]")
  exit()
end

type = ARGV[0]
pid = ARGV[1]&.to_i
binpath = ARGV[2]
if !type or !pid
  usage
end

prog = <<PROG
BPF_HISTOGRAM(dist);
BPF_HISTOGRAM(dist2);
BPF_HASH(start, u32);

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
int gc_event_begin(void *ctx) {
  u64 ts = bpf_ktime_get_ns();
  u32 tid = bpf_get_current_pid_tgid();

  start.update(&tid, &ts);
  return 0;
}

int gc_event_end(void *ctx) {
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

int gc_event_begin2(void *ctx) {
  u64 ts = bpf_ktime_get_ns();
  u32 tid = bpf_get_current_pid_tgid();

  start.update(&tid, &ts);
  return 0;
}

int gc_event_end2(void *ctx) {
  u64 *tsp, delta;
  u32 tid = bpf_get_current_pid_tgid();

  tsp = start.lookup(&tid);
  if (tsp != 0) {
    delta = bpf_ktime_get_ns() - *tsp;
    start.delete(&tid);

    dist2.increment(log10(delta));
  }
  return 0;
}
PROG

# $ sudo bpftrace -e '
#   usdt:./bin/ruby:ruby:gc__mark__begin {
#      @call[tid] = nsecs }
#   usdt:./bin/ruby:ruby:gc__mark__end /@call[tid]/ {
#     @lat = hist(nsecs - @call[tid]) }
#   usdt:./bin/ruby:ruby:gc__sweep__begin {
#     @call2[tid] = nsecs }
#   usdt:./bin/ruby:ruby:gc__sweep__end /@call[tid]/ {
#     @lat2 = hist(nsecs - @call2[tid]) }
#   END {clear(@call);clear(@call2)}' --usdt-file-activation

u = USDT.new(pid: pid, path: binpath)
if type == "all"
  u.enable_probe(probe: "gc__mark__begin", fn_name: "gc_event_begin")
  u.enable_probe(probe: "gc__mark__end", fn_name: "gc_event_end")
  u.enable_probe(probe: "gc__sweep__begin", fn_name: "gc_event_begin2")
  u.enable_probe(probe: "gc__sweep__end", fn_name: "gc_event_end2")
elsif type == "mark"
  u.enable_probe(probe: "gc__mark__begin", fn_name: "gc_event_begin")
  u.enable_probe(probe: "gc__mark__end", fn_name: "gc_event_end")
else
  u.enable_probe(probe: "gc__sweep__begin", fn_name: "gc_event_begin")
  u.enable_probe(probe: "gc__sweep__end", fn_name: "gc_event_end")
end

# initialize BPF
b = BCC.new(text: prog, usdt_contexts: [u])

puts("collectiong data...")

loop do
  begin
    sleep 1
  rescue Interrupt
    puts
    break # pass
  end
end

if type == "all"
  puts "elapsed time of gc mark"
  puts "~~~~~~~~~~~~~~"
  print_etime_hist(b["dist"])

  puts
  puts "elapsed time of gc sweep"
  puts "~~~~~~~~~~~~~~"
  print_etime_hist(b["dist2"])
else  
  puts "elapsed time of gc #{type}"
  puts "~~~~~~~~~~~~~~"
  print_etime_hist(b["dist"])
end
