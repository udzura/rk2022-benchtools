require 'rbbcc'
include RbBCC

header = <<PROG
#include <uapi/linux/ptrace.h>

struct key_t {
  u32 tid;
  u32 idx;
};

BPF_ARRAY(calls, u64, 4);
BPF_ARRAY(elap,  u64, 4);
BPF_HASH(start, struct key_t);
PROG

funcs = lambda {|i|
  %Q@
int on_begin#{i}(void *ctx) {
  int idx = #{i};
  u64 ts = bpf_ktime_get_ns();
  u32 tid = bpf_get_current_pid_tgid();
  struct key_t key = {0};
  key.tid = tid;
  key.idx = #{i};
  start.update(&key, &ts);
  return 0;
}

int on_return#{i}(void *ctx) {
  int idx = #{i};
  u64 *tsp, delta;
  u32 tid = bpf_get_current_pid_tgid();
  struct key_t key = {0};
  key.tid = tid;
  key.idx = #{i};

  tsp = start.lookup(&key);
  if (tsp != 0) {
    delta = bpf_ktime_get_ns() - *tsp;
    start.delete(&key);
    u64 zero = 0, *val;

    val = calls.lookup_or_init(&idx, &zero);
    if (val)
      (*val) += 1;

    val = elap.lookup_or_init(&idx, &zero);
    if (val)
      (*val) += delta;
  }
  return 0;
}
@
}

prog = [
  header,
  funcs[0],
  funcs[1],
  funcs[2],
].join("\n")

puts prog

def usage
  puts("USAGE: #{$0} [GEM_SO_PATH] [PID]")
  exit()
end

usage if ARGV.size != 1 && ARGV.size != 2

path = ARGV[0]
pid = ARGV[1]&.to_i || -1

b = BCC.new(text: prog)
syms = []
if sym = ENV['SYMNAME0']
  b.attach_uprobe(name: path, sym: sym, fn_name: "on_begin0", pid: pid)
  b.attach_uretprobe(name: path, sym: sym, fn_name: "on_return0", pid: pid)
  syms[0] = sym
end
if sym = ENV['SYMNAME1']
  b.attach_uprobe(name: path, sym: sym, fn_name: "on_begin1", pid: pid)
  b.attach_uretprobe(name: path, sym: sym, fn_name: "on_return1", pid: pid)
  syms[1] = sym
end
if sym = ENV['SYMNAME2']
  b.attach_uprobe(name: path, sym: sym, fn_name: "on_begin2", pid: pid)
  b.attach_uretprobe(name: path, sym: sym, fn_name: "on_return2", pid: pid)
  syms[2] = sym
end

puts("collectiong data...")

loop do
  begin
    sleep 1
  rescue Interrupt
    puts
    break # pass
  end
end

puts "Call stats:"
calls = b.get_table("calls").to_a
elap  = b.get_table("elap").to_a

puts "%8s %8s %10s %10s" % %w(SYM COUNT ALL(ms) ELAP(ms/i))
calls.each_with_index do |v, i|
  elapav = elap[i].to_f / v / 1000 / 1000
  puts "%8s %8d %10.4f %10.4f" % [syms[i], v, elap[i].to_f / 1000 / 1000 ,elapav]
end
