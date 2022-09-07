require 'rbbcc'; include RbBCC

code = <<CLANG
BPF_ARRAY(dist, u64, 1);
int func(void *ctx) {
  u32 key = 0;
  u64 *count = dist.lookup(&key);
  if (count) (*count)++;
  return 0;
}
CLANG

b = BCC.new(text: code)
b.attach_kprobe(event: "__arm64_sys_execve", fn_name: "func")
loop do
  sleep 3;
  puts "#{Time.now} execve count in 3s: #{b['dist'].to_a[0]}"
  b['dist'].clear
end
