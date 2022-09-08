#include <linux/sched.h>
#include <net/sock.h>

// define output data structure in C
struct data_t {
    u32 backlog_len;
    u32 max_backlog_len;
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);

int kprobe__tcp_v4_conn_request(struct pt_regs *ctx, struct sock * arg0) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();

    //if(data.ts % 999997 != 0) {
    //    return 0;
    //}

    data.backlog_len = arg0->sk_ack_backlog;
    data.max_backlog_len = arg0->sk_max_ack_backlog;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
