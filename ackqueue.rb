#!/usr/bin/env ruby
require 'rbbcc'
include RbBCC

disp_interval = ARGV[0]&.to_i
b = BCC.new(src_file: "ackqueue.bpf.c")

# header
puts("%-18s %-16s %-6s %s" % ["TIME(s)", "COMM", "PID", "BACKLOG_LEN"])

# loop with callback to print_event
start = 0; last_disp = nil
b["events"].open_perf_buffer do |cpu, data, size|
  event = b["events"].event(data)
  start = event.ts if start == 0

  time_s = ((event.ts - start).to_f) / 1000000000
  # event.comm.pack("c*").sprit
  if last_disp && (Time.now - last_disp) < disp_interval
    return
  end
  puts("%-18.9f %-16s %-6d %d/%d" % [time_s, event.comm, event.pid,
                                     event.backlog_len, event.max_backlog_len])
  last_disp = Time.now if disp_interval
end

b.perf_buffer_poll while true
