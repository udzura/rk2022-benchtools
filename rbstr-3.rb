require 'rbbcc'
include RbBCC

prog = <<PROG
#include <uapi/linux/ptrace.h>

struct ruby_string_t {
  char str[64];
};

struct ruby_value_t {
  u64 flags;
  u64 klass;
  u64 len;
  u64 ptr;
};

BPF_HASH(long, u32, u8);
BPF_HASH(long1, u32, struct ruby_string_t);
BPF_HASH(long2, u32, struct ruby_string_t);
BPF_HASH(long3, u32, struct ruby_string_t);
BPF_HASH(long4, u32, struct ruby_string_t);

int rb_str_new_begin(struct pt_regs *ctx) {
  u32 tid = bpf_get_current_pid_tgid();
  u64 len = (u64)PT_REGS_PARM2(ctx);
  if (len > 1000) {
    u8 is = 4;
    is_long.update(&tid, &is);
    return 0;
  }
  if (len > 500) {
    u8 is = 3;
    is_long.update(&tid, &is);
    return 0;
  }
  if (len > 200) {
    u8 is = 2;
    is_long.update(&tid, &is);
    return 0;
  }
  if (len > 50) {
    u8 is = 1;
    is_long.update(&tid, &is);
    return 0;
  }
  return 0;
}

int rb_str_new_return(struct pt_regs *ctx) {
  u8 *is;
  u32 tid = bpf_get_current_pid_tgid();
  is = is_long.lookup(&tid);
  if (is != 0) {
    u64 key = bpf_ktime_get_ns();
    struct ruby_value_t value = {0};
    struct ruby_string_t buf = {0};
    bpf_probe_read_user(&value, sizeof(buf), (struct ruby_value_t *)PT_REGS_RC(ctx));
    if (*is == 1) {
      bpf_probe_read_user(&buf.str, 50, (char *)value.ptr);
      long1.update(&key, &buf);
    }
    if (*is == 2) {
      bpf_probe_read_user(&buf.str, sizeof(buf.str), (char *)value.ptr);
      long1.update(&key, &buf);
    }
    if (*is == 3) {
      bpf_probe_read_user(&buf.str, sizeof(buf.str), (char *)value.ptr);
      long1.update(&key, &buf);
    }
    if (*is == 4) {
      bpf_probe_read_user(&buf.str, sizeof(buf.str), (char *)value.ptr);
      long1.update(&key, &buf);
    }
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

puts("collectiong data...")

loop do
  begin
    sleep 1
  rescue Interrupt
    puts
    break # pass
  end
end

puts "Sample strings 50 <= len < 200"
b["long1"].each {|k, v| p v[0, 64].inspect }

puts "Sample strings 200 <= len < 500"
b["long1"].each {|k, v| p v[0, 64].inspect }

puts "Sample strings 500 <= len < 1000"
b["long1"].each {|k, v| p v[0, 64].inspect }

puts "Sample strings len >= 1000"
b["long1"].each {|k, v| p v[0, 64].inspect }
