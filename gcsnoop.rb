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

// define key
struct data_t {
  u32 type; // 1: mark 2: sweep
  u64 elapsed;
};
BPF_PERF_OUTPUT(events);
BPF_ARRAY(sweeps, struct data_t);
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

  tsp = start.lookup(&tid);
  if (tsp != 0) {
    struct data_t data = {0};
    delta = bpf_ktime_get_ns() - *tsp;
    data.type = 1;
    data.elapsed = delta;
    start.delete(&tid);
    events.perf_submit(ctx, &data, sizeof(data));
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

  tsp = start2.lookup(&tid);
  if (tsp != 0) {
    struct data_t data = {0};
    delta = bpf_ktime_get_ns() - *tsp;
    data.type = 2;
    data.elapsed = delta;
    start2.delete(&tid);
    events.perf_submit(ctx, &data, sizeof(data));
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

puts "%-26s %10s %11s %8s" % %w(TIME RSS(KB) ELAPSED(ms) EVENT)

do_loop = true
t = Thread.new do
  while do_loop
    begin
      rss = `cat /proc/#{pid}/smaps | grep Private`.lines.map{_1.split[1].to_i}.sum
      puts "%26s %10d %11s %8s" % [Time.now.strftime("%Y-%m-%d %H:%M:%S.%6N"), rss, "", ""]
    rescue
      puts "[!] Failed to get RSS, skip. #{$!}"
    end

    sleep 1

    b["sweeps"].to_a
  end
end

b["events"].open_perf_buffer do |_cpu, data, _size|
  event = b["events"].event(data)
  elapsed = event.elapsed.to_f / (1000*1000)
  type = [nil, "mark", "sweep"][event.type]
  puts "%26s %10s %11.2f %8s" % [Time.now.strftime("%Y-%m-%d %H:%M:%S.%6N"), "", elapsed, type]
end

loop do
  begin
    b.perf_buffer_poll()
  rescue Interrupt
    do_loop = false
    t.join
    exit()
  end
end

