require 'rbbcc'
include RbBCC

def usage
  puts("USAGE: #{$0} PID [RUBY_PATH]")
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
struct key_t {
  u32 tid;
  char klass [16];
  char symbol[16];
};
// define output data structure in C
struct data_t {
  char klass [16];
  char symbol[16];
};
BPF_PERF_OUTPUT(events);
BPF_HASH(start, struct key_t);

int cmethod_entry(struct pt_regs *ctx) {
  u64 ts = bpf_ktime_get_ns();
  struct key_t key = {0};
  u32 tid = bpf_get_current_pid_tgid();
  bpf_usdt_readarg_p(1, ctx, &key.klass,  16);
  bpf_usdt_readarg_p(2, ctx, &key.symbol, 16);

  start.update(&key, &ts);
  return 0;
}

int cmethod_return(struct pt_regs *ctx) {
  struct key_t key = {0};
  u32 tid = bpf_get_current_pid_tgid();
  bpf_usdt_readarg_p(1, ctx, &key.klass,  16);
  bpf_usdt_readarg_p(2, ctx, &key.symbol, 16);

  u64 *tsp, delta;

  tsp = start.lookup(&key);
  if (tsp != 0) {
    delta = bpf_ktime_get_ns() - *tsp;
    start.delete(&key);

    if (delta > 1000*1000) {
      struct data_t data = {0};
      bpf_usdt_readarg_p(1, ctx, &data.klass,  16);
      bpf_usdt_readarg_p(2, ctx, &data.symbol, 16);
      
      events.perf_submit(ctx, &data, sizeof(data));
    }
  }
  return 0;
}
PROG

u = USDT.new(pid: pid, path: binpath)
u.enable_probe(probe: "cmethod__entry",  fn_name: "cmethod_entry")
u.enable_probe(probe: "cmethod__return", fn_name: "cmethod_return")

b = BCC.new(text: prog, usdt_contexts: [u])

puts "Start tracing"

b["events"].open_perf_buffer do |_cpu, data, _size|
  event = b["events"].event(data)
  binding.irb
end

loop do
  begin
    b.perf_buffer_poll()
  rescue Interrupt
    exit()
  end
end

