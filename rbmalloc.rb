require 'rbbcc'
include RbBCC

if ARGV.size == 0
  $stderr.puts("USAGE: $0 PID")
  exit
end
pid = ARGV[0].to_i

b = BCC.new(text: <<CLANG)
#include <uapi/linux/ptrace.h>
BPF_ARRAY(calls, u64, 4);

int malloc_enter(struct pt_regs *ctx, size_t size) {
    int imalloc = 0;
    u64 zero = 0, *val;
    val = calls.lookup_or_init(&imalloc, &zero);
    if (val)
      (*val) += 1;
    return 0;
};

int calloc_enter(struct pt_regs *ctx, size_t size) {
    int icalloc = 1;
    u64 zero = 0, *val;
    val = calls.lookup_or_init(&icalloc, &zero);
    if (val)
      (*val) += 1;
    return 0;
};

int free_enter(struct pt_regs *ctx, size_t size) {
    int ifree   = 2;
    u64 zero = 0, *val;
    val = calls.lookup_or_init(&ifree, &zero);
    if (val)
      (*val) += 1;
    return 0;
};
CLANG

b.attach_uprobe(name: "c", sym: "malloc", fn_name: "malloc_enter", pid: pid)
b.attach_uprobe(name: "c", sym: "calloc", fn_name: "calloc_enter", pid: pid)
b.attach_uprobe(name: "c", sym: "free", fn_name: "free_enter", pid: pid)
puts("Attaching to pid %d, Ctrl+C to quit." % pid)

loop do
  begin
    sleep 1
  rescue Interrupt
    break # pass
  end
end

calls = b.get_table("calls")
callee = %w(malloc calloc free unknown)

puts "Call stats:"
calls.each_with_index do |v, i|
  puts "%8s %d" % [callee[i], v]
end
