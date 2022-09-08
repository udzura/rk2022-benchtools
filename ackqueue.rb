#!/usr/bin/env ruby

require 'rbbcc'
include RbBCC

disp_interval = ARGV[0]&.to_i

prog = "ackqueue.bpf.c"
b = BCC.new(src_file: prog)

# header
puts("%-18s %-16s %-6s %s" % ["TIME(s)", "COMM", "PID", "BACKLOG_LEN"])

# process event
start = 0
last_disp = nil
print_event = lambda { |cpu, data, size|
  event = b["events"].event(data)
  if start == 0
    start = event.ts
  end

  time_s = ((event.ts - start).to_f) / 1000000000
  # event.comm.pack("c*").sprit
  if last_disp && (Time.now - last_disp) < disp_interval
    return
  end

  puts("%-18.9f %-16s %-6d %d/%d" % [time_s, event.comm, event.pid,
                                  event.backlog_len, event.max_backlog_len])

  if disp_interval
    last_disp = Time.now
  end
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
