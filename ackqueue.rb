#!/usr/bin/env ruby

require 'rbbcc'
include RbBCC

prog = """
#include <linux/sched.h>
#include <net/sock.h>

// define output data structure in C
struct data_t {
    u32 backlog_len;
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);

int kprobe__tcp_v4_conn_request(struct pt_regs *ctx, struct sock * arg0) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();

    if(data.ts % 999997 != 0) {
        return 0;
    }

    data.backlog_len = arg0->sk_ack_backlog;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

b = BCC.new(text: prog)
# b.attach_kprobe(event: "tcp_v4_conn_request", fn_name: "hello")

# header
puts("%-18s %-16s %-6s %s" % ["TIME(s)", "COMM", "PID", "BACKLOG_LEN"])

# process event
start = 0
print_event = lambda { |cpu, data, size|
  event = b["events"].event(data)
  if start == 0
    start = event.ts
  end

  time_s = ((event.ts - start).to_f) / 1000000000
  # event.comm.pack("c*").sprit
  puts("%-18.9f %-16s %-6d %d" % [time_s, event.comm, event.pid,
                                  event.backlog_len])
}

# loop with callback to print_event
b["events"].open_perf_buffer(&print_event)

loop do
  begin
    b.perf_buffer_poll()
  rescue Interrupt
    exit()
  end
end
