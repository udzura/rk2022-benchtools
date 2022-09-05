require 'rbbcc'
include RbBCC

if ARGV.size == 0
  $stderr.puts("USAGE: $0 PID")
  exit
end
pid = ARGV[0]&.to_i || -1

b = BCC.new(text: <<CLANG)
#include <uapi/linux/ptrace.h>
BPF_ARRAY(calls, u64, 1);

int enter(struct pt_regs *ctx, size_t size) {
    int idx = 0;
    u64 zero = 0, *val;
    val = calls.lookup_or_init(&idx, &zero);
    if (val)
      (*val) += 1;
    return 0;
};
CLANG

b.attach_uprobe(name: "c", sym: "realloc", fn_name: "enter", pid: pid)
puts("Attaching to pid %d, Ctrl+C to quit." % pid)

loop do
  begin
    sleep 1
  rescue Interrupt
    break # pass
  end
end

calls = b.get_table("calls")
callee = %w(realloc)

puts "Call stats:"
calls.each_with_index do |v, i|
  puts "%8s %d" % [callee[i], v]
end
