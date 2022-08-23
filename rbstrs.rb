require 'rbbcc'
include RbBCC

prog = <<PROG
#include <uapi/linux/ptrace.h>

BPF_PERF_OUTPUT(events);

struct data_t {
  u32 len;
  char str[32];
};

int rb_str_new_begin(struct pt_regs *ctx) {

  char *ptr = (char *)PT_REGS_PARM1(ctx);
  u32 len = (u32)PT_REGS_PARM2(ctx);

  //if (len > 64) {
  struct data_t data = {0};
  data.len = len;
  bpf_probe_read_user(data.str, 32, ptr);
  events.perf_submit(ctx, &data, sizeof(data));

  //}

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

b["events"].open_perf_buffer do |_cpu, data, _size|
  event = b["events"].event(data)
  binding.irb
  puts "String created:: #{event.str.inspect} (len=#{event.len})"
end

loop do
  begin
    b.perf_buffer_poll()
  rescue Interrupt
    exit()
  end
end
