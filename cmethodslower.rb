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
BPF_HASH(start, u32);

int cmethod_entry(void *ctx) {
  u64 ts = bpf_ktime_get_ns();
  u64 kaddr, symaddr;
  struct key_t key = {0};
  u32 tid = bpf_get_current_pid_tgid();
  bpf_usdt_readarg(1, ctx, &kaddr);
  bpf_probe_read_user_str(&key.klass,  16, (char *)kaddr);
  bpf_usdt_readarg(2, ctx, &symaddr);
  bpf_probe_read_user_str(&key.symbol, 16, (char *)symaddr);

  start.update(&key, &ts);
  return 0;
}

int cmethod_return(void *ctx) {
  u64 kaddr, symaddr;
  struct key_t key = {0};
  u32 tid = bpf_get_current_pid_tgid();
  bpf_usdt_readarg(1, ctx, &kaddr);
  bpf_probe_read_user_str(&key.klass,  16, (char *)kaddr);
  bpf_usdt_readarg(2, ctx, &symaddr);
  bpf_probe_read_user_str(&key.symbol, 16, (char *)symaddr);

  u64 *tsp, delta;

  tsp = start.lookup(&key);
  if (tsp != 0) {
    delta = bpf_ktime_get_ns() - *tsp;
    start.delete(&tid);

    if (delta > 1000*1000) {
      struct data_t data = {0};
      bpf_probe_read_user_str(&data.klass,  16, (char *)kaddr);
      bpf_probe_read_user_str(&data.symbol, 16, (char *)symaddr);
      
      events.perf_submit(ctx, &data, sizeof(data));
    }
  }
  return 0;
}
PROG

u = USDT.new(pid: pid, path: path)
u.enable_probe(probe: "cmethod__entry",  fn_name: "cmethod_entry")
u.enable_probe(probe: "cmethod__return", fn_name: "cmethod_return")

b = BCC.new(text: prog, usdt_contexts: [u])

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

