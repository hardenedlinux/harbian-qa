package ebpf

const EbpfSingle string =`
#include <net/sock.h>
#include <linux/net.h>

int kprobe__tcp_v6_init_sock(struct pt_regs *ctx, struct sock *sk)
{
    uint64_t state = 0x1;
    state = state | (*(sk->__sk_flags_offset) << 4);
    bpf_trace_printk("%lx\n", state);
    return 0;
}
int kprobe__tcp_v6_connect(struct pt_regs *ctx, struct sock *sk)
{
    uint64_t state = 0x2;
    state = state | (*(sk->__sk_flags_offset) << 4);
    bpf_trace_printk("%lx\n", state);
    return 0;
}
int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk)
{
    uint64_t state = 0x3;
    state = state | (*(sk->__sk_flags_offset) << 4);
    bpf_trace_printk("%lx\n", state);
    return 0;
}
int kprobe__tcp_recvmsg(struct pt_regs *ctx, struct sock *sk)
{
    uint64_t state = 0x4;
    state = state | (*(sk->__sk_flags_offset) << 4);
    bpf_trace_printk("%lx\n", state);
    return 0;
}
int kprobe__tcp_close(struct pt_regs *ctx, struct sock *sk)
{
    uint64_t state = 0x5;
    state = state | (*(sk->__sk_flags_offset) << 4);
    bpf_trace_printk("%lx\n", state);
    return 0;
}
int kprobe__tcp_shutdown(struct pt_regs *ctx, struct sock *sk)
{
    uint64_t state = 0x6;
    state = state | (*(sk->__sk_flags_offset) << 4);
    bpf_trace_printk("%lx\n", state);
    return 0;
}
int kprobe__tcp_setsockopt(struct pt_regs *ctx, struct sock *sk)
{
    uint64_t state = 0x7;
    state = state | (*(sk->__sk_flags_offset) << 4);
    bpf_trace_printk("%lx\n", state);
    return 0;
}
int kprobe__tcp_getsockopt(struct pt_regs *ctx, struct sock *sk)
{
    uint64_t state = 0x8;
    state = state | (*(sk->__sk_flags_offset) << 4);
    bpf_trace_printk("%lx\n", state);
    return 0;
}
int kprobe__inet_accept(struct pt_regs *ctx, struct socket *sock, struct socket* newsock)
{
    uint64_t state = 0x9;
    state = state | (*(sock->sk->__sk_flags_offset) << 4);
    bpf_trace_printk("%lx\n", state);
    state = 0x9;
    state = state | (*(newsock->sk->__sk_flags_offset) << 4);
    bpf_trace_printk("%lx\n", state);
    return 0;
}
int kprobe__inet_listen(struct pt_regs *ctx, struct socket *sock)
{
    uint64_t state = 0xa;
    state = state | (*(sock->sk->__sk_flags_offset) << 4);
    bpf_trace_printk("%lx\n", state);
    return 0;
}
`

var ProbePoint []string = []string{"tcp_v6_init_sock","tcp_v6_connect","tcp_sendmsg","tcp_recvmsg","tcp_close","tcp_shutdown","tcp_setsockopt","tcp_getsockopt","inet_accept","inet_listen"}
