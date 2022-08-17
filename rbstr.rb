require 'rbbcc'
include RbBCC

prog = <<PROG
int hola(void *ctx) {
  bpf_trace_printk("Hello, World!\\n");
  return 0;
}

int hola2(void *ctx) {
  bpf_trace_printk("Return, World!\\n");
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
b.attach_uprobe(name: path, sym: "rb_str_new", fn_name: "hola", pid: pid)
b.attach_uretprobe(name: path, sym: "rb_str_new", fn_name: "hola2", pid: pid)

loop do
  begin
    b.trace_print
    sleep 1
  rescue Interrupt
    break # pass
  end
end

puts "elapsed time histogram"
puts "~~~~~~~~~~~~~~"
# print_etime_hist(b["dist"])
