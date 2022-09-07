require 'rbbcc'; include RbBCC

code = <<CLANG
#include <uapi/linux/ptrace.h>
BPF_ARRAY(dist, u32, 1)
int func(struct pt_regs *ctx) {
  u32 key = 0;
  u32 *count = dist.lookup(&key);
  if (count) *count++;
  return 0;
}
CLANG

b = BCC.new(text: code)
b.attach_kprobe(event: b.get_syscall_fnname("execve"), fn_name: "func")
loop do
  sleep 10;
  puts "execve count in 10s: #{b['dist'][0]}"
  b['dist'][0] = 0
end
