require 'rbbcc'
include RbBCC

prog = <<PROG
BPF_HISTOGRAM(dist);
BPF_HASH(start, u32);

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

    dist.increment(bpf_log2l(delta));
  }
  return 0;
}
PROG

def usage
  puts("USAGE: #{$0} [RUBY_PATH] [PID]")
  exit()
end

usage if ARGV.size != 1 && ARGV.size != 2

path = ARGV[0]
pid = ARGV[1]&.to_i || -1

b = BCC.new(text: prog)
b.attach_uprobe(name: path, sym: "rb_str_new", fn_name: "rb_str_new_begin", pid: pid)
b.attach_uretprobe(name: path, sym: "rb_str_new", fn_name: "rb_str_new_return", pid: pid)

loop do
  begin
    sleep 1
  rescue Interrupt
    break # pass
  end
end

puts "elapsed time histogram"
puts "~~~~~~~~~~~~~~"
# print_etime_hist(b["dist"])

b["dist"].print_log2_hist
