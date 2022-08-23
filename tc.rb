require 'rbbcc'
include RbBCC

require 'ipaddr'

begin
  require 'pycall/import'
rescue LoadError => e
  puts "#{e.inspect}: needs pycall installed. run: gem install pycall"
  exit 127
end

unless iface = ARGV[0]
  puts("USAGE: #{$0} [IFACE]")
  exit 1
end

private_begin = IPAddr.new("192.168.0.0/32").to_i
private_end   = IPAddr.new("192.168.255.255/32").to_i

code = <<CODE
// SPDX-License-Identifier: GPL-2.0+
#define BPF_LICENSE GPL

#include <linux/pkt_cls.h>
#include <uapi/linux/bpf.h>
#include <bcc/proto.h>

struct data_t {
  u32 dest;
};

BPF_PERF_OUTPUT(events);

int on_egress(struct __sk_buff *skb) {
  u8 *cursor = 0;
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  if (ethernet->type != 0x0800) goto ret;

  struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
  u32 dest = ip->dst;
  if (dest == 0) goto ret;
  if (#{private_begin} <= dest && dest <= #{private_end})
    goto ret;

  struct data_t data = {0};
  data.dest = dest;
  events.perf_submit(skb, &data, sizeof(data));
ret:
  return TC_ACT_OK;
}
CODE

module Py
  extend PyCall::Import
  pyimport :pyroute2
end
PyRoute2 = Py.pyroute2

b = BCC.new(text: code)
func = b.load_func("on_egress", BPF::SCHED_CLS)

ip = PyRoute2.IPRoute.new
ipdb = PyRoute2.IPDB.new
idx = ipdb.interfaces[iface].index
ip.tc("add", "clsact", idx)

ip.tc("add-filter", "bpf", idx, ":1", fd: func[:fd], name: func[:name],
      parent: "ffff:fff3", classid: 1, direct_action: true)

at_exit {
  ip.tc("del", "clsact", idx)
  ipdb.release
}

b["events"].open_perf_buffer do |_cpu, data, _size|
  event = b["events"].event(data)
  got = IPAddr.new event.dest, Socket::AF_INET
  puts "EGRESS IP: #{got}"
end

loop do
  begin
    b.perf_buffer_poll()
  rescue Interrupt
    exit()
  end
end
