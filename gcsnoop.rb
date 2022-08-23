require 'rbbcc'
include RbBCC

def usage
  puts("USAGE: #{$0} mark|sweep PID [RUBY_PATH]")
  exit()
end

pid = ARGV[0]&.to_i
binpath = ARGV[1]
if !pid
  usage
end

prog = <<PROG
#include <uapi/linux/ptrace.h>

// key = 1: mark 2: sweep
BPF_ARRAY(dist, u64, 3);
BPF_ARRAY(count, u64, 3);
BPF_HASH(start, u32);
BPF_HASH(start2, u32);

int gc_event_begin(void *ctx) {
  u64 ts = bpf_ktime_get_ns();
  u32 tid = bpf_get_current_pid_tgid();

  start.update(&tid, &ts);
  return 0;
}

int gc_event_end(void *ctx) {
  u64 *tsp, delta;
  u32 tid = bpf_get_current_pid_tgid();
  u32 key = 1;

  tsp = start.lookup(&tid);
  if (tsp != 0) {
    delta = bpf_ktime_get_ns() - *tsp;
    start.delete(&tid);
    u64 *value = dist.lookup(&key);
    if (value) *value += delta;
    u64 *value2 = count.lookup(&key);
    if (value2) *value2 += 1;
  }
  return 0;
}

int gc_event_begin2(void *ctx) {
  u64 ts = bpf_ktime_get_ns();
  u32 tid = bpf_get_current_pid_tgid();

  start2.update(&tid, &ts);
  return 0;
}

int gc_event_end2(void *ctx) {
  u64 *tsp, delta;
  u32 tid = bpf_get_current_pid_tgid();
  u32 key = 2;

  tsp = start2.lookup(&tid);
  if (tsp != 0) {
    delta = bpf_ktime_get_ns() - *tsp;
    start2.delete(&tid);
    u64 *value = dist.lookup(&key);
    if (value) *value += delta;
    u64 *value2 = count.lookup(&key);
    if (value2) *value2 += 1;
  }
  return 0;
}
PROG

u = USDT.new(pid: pid, path: binpath)
u.enable_probe(probe: "gc__mark__begin", fn_name: "gc_event_begin")
u.enable_probe(probe: "gc__mark__end", fn_name: "gc_event_end")
u.enable_probe(probe: "gc__sweep__begin", fn_name: "gc_event_begin2")
u.enable_probe(probe: "gc__sweep__end", fn_name: "gc_event_end2")
b = BCC.new(text: prog, usdt_contexts: [u])

puts "Start tracing"

puts "%-26s %8s %10s %s" % %w(TIME EVENT RSS(KB) ELAPSED(ms/event))

loop do
  begin
    begin
      rss = `cat /proc/#{pid}/smaps | grep Private`.lines.map{_1.split[1].to_i}.sum
      puts "%26s %8s %10d" % [Time.now.strftime("%Y-%m-%d %H:%M:%S.%6N"), "RSS", rss]
    rescue
      puts "[!] Failed to get RSS, skip. #{$!}"
    end

    sleep 1

    count, dist = *[b["count"][1], b["dist"][1]].map{ _1[0, 8].unpack("L")[0] }
    count2, dist2 = *[b["count"][2], b["dist"][2]].map{ _1[0, 8].unpack("L")[0] }
    elap1 = count.zero? : '-' : "%7.3f" % (dist.to_f/count/1000/1000)
    elap2 = count2.zero? : '-' : "%7.3f" % (dist2.to_f/count2/1000/1000)
    
    puts "%-26s %8s %10s %s" % [Time.now.strftime("%Y-%m-%d %H:%M:%S.%6N"), "MARK", "", elap1, count]
    puts "%-26s %8s %10s %s" % [Time.now.strftime("%Y-%m-%d %H:%M:%S.%6N"), "SWEEP", "", elap2, count2]

    b["count"][1] = 0
    b["count"][2] = 0
    b["dist"][1] = 0
    b["dist"][2] = 0
  rescue Interrupt
    exit()
  end
end

