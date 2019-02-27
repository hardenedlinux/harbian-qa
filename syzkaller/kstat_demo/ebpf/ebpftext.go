package ebpf

const EbpfSingle string =`
#include <net/sock.h>
#include <linux/net.h>

int kprobe__tcp_v6_init_sock(struct pt_regs *ctx, struct sock *sk)
{
    uint64_t state = 0x1;
    state = state | ((sk->sk_socket->state&0xf) << 4);
    state = state | ((sk->sk_socket->type&0xf) << 8);
    state = state | ((sk->sk_socket->flags&0xf) << 12);
    state = state | (sk->__sk_flags_offset[0] << 16);
    bpf_trace_printk("%lx\n", state);
    return 0;
}
int kprobe__tcp_v6_connect(struct pt_regs *ctx, struct sock *sk)
{
    uint64_t state = 0x2;
    state = state | ((sk->sk_socket->state&0xf) << 4);
    state = state | ((sk->sk_socket->type&0xf) << 8);
    state = state | ((sk->sk_socket->flags&0xf) << 12);
    state = state | (sk->__sk_flags_offset[0] << 16);
    bpf_trace_printk("%lx\n", state);
    return 0;
}
int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg)
{
    uint64_t state = 0x3, tmp;
    state = state | ((sk->sk_socket->state&0xf) << 4);
    state = state | ((sk->sk_socket->type&0xf) << 8);
    state = state | ((sk->sk_socket->flags&0xf) << 12);
    state = state | (sk->__sk_flags_offset[0] << 16);
    tmp =  msg->msg_flags;
    state = state | ((tmp&0xffff) << 32);
    bpf_trace_printk("%lx\n", state);
    return 0;
}
int kprobe__tcp_recvmsg(struct pt_regs *ctx, struct sock *sk, int flags)
{
    uint64_t state = 0x4, tmp = 0;
    state = state | ((sk->sk_socket->state&0xf) << 4);
    state = state | ((sk->sk_socket->type&0xf) << 8);
    state = state | ((sk->sk_socket->flags&0xf) << 12);
    state = state | (sk->__sk_flags_offset[0] << 16);
    tmp = flags;
    state = state | ((tmp&0xffff) << 32);
    bpf_trace_printk("%lx\n", state);
    return 0;
}
int kprobe__tcp_close(struct pt_regs *ctx, struct sock *sk)
{
    uint64_t state = 0x5;
    state = state | ((sk->sk_socket->state&0xf) << 4);
    state = state | ((sk->sk_socket->type&0xf) << 8);
    state = state | ((sk->sk_socket->flags&0xf) << 12);
    state = state | (sk->__sk_flags_offset[0] << 16);
    bpf_trace_printk("%lx\n", state);
    return 0;
}
int kprobe__tcp_shutdown(struct pt_regs *ctx, struct sock *sk, int how)
{
    uint64_t state = 0x6, tmp = 0x0;
    state = state | ((sk->sk_socket->state&0xf) << 4);
    state = state | ((sk->sk_socket->type&0xf) << 8);
    state = state | ((sk->sk_socket->flags&0xf) << 12);
    state = state | (sk->__sk_flags_offset[0] << 16);
    tmp = how;
    state = state | (tmp << 32);
    bpf_trace_printk("%lx\n", state);
    return 0;
}
int kprobe__tcp_setsockopt(struct pt_regs *ctx, struct sock *sk, int level, int optname)
{
    uint64_t state = 0xe, tmp = 0;
    state = state | ((sk->sk_socket->state&0xf) << 4);
    state = state | ((sk->sk_socket->type&0xf) << 8);
    state = state | ((sk->sk_socket->flags&0xf) << 12);
    state = state | (sk->__sk_flags_offset[0] << 16);
    tmp = optname;
    if(tmp < 36) {
        state = state | ((tmp%0x36) << 32);
    }
    bpf_trace_printk("%lx\n", state);
    return 0;
}
int kprobe__tcp_getsockopt(struct pt_regs *ctx, struct sock *sk, int level, int optname)
{
    uint64_t state = 0x8, tmp = 0;
    state = state | ((sk->sk_socket->state&0xf) << 4);
    state = state | ((sk->sk_socket->type&0xf) << 8);
    state = state | ((sk->sk_socket->flags&0xf) << 12);
    state = state | (sk->__sk_flags_offset[0] << 16);
    tmp = optname;
    if(tmp < 36) {
        state = state | ((tmp%0x36) << 32);
    }
    bpf_trace_printk("%lx\n", state);
    return 0;
}
int kprobe__inet_accept(struct pt_regs *ctx, struct socket *sock, struct socket* newsock, int flags, bool kern)
{
    uint64_t state = 0x9, tmp = 0;
    state = state | ((sock->state&0xf) << 4);
    state = state | ((sock->type&0xf) << 8);
    state = state | ((sock->flags&0xf) << 12);
    state = state | (sock->sk->__sk_flags_offset[0] << 16);
    tmp = flags;
    state = state | ((tmp&0xffff) << 32);
    if(kern)
        tmp = 0x1;
    state = state | ((tmp&0x1) << 36);
    bpf_trace_printk("%lx\n", state);
    state = 0xa;
    state = state | ((sock->state&0xf) << 4);
    state = state | ((sock->type&0xf) << 8);
    state = state | ((sock->flags&0xf) << 12);
    state = state | (sock->sk->__sk_flags_offset[0] << 16);
    tmp = flags;
    state = state | ((tmp&0xffff) << 32);
    if(kern)
        tmp = 0x1;
    state = state | ((tmp&0x1) << 36);
    bpf_trace_printk("%lx\n", state);
    return 0;
}
int kprobe__inet_listen(struct pt_regs *ctx, struct socket *sock)
{
    uint64_t state = 0xb;
    state = state | ((sock->state&0xf) << 4);
    state = state | ((sock->type&0xf) << 8);
    state = state | ((sock->flags&0xf) << 12);
    state = state | (sock->sk->__sk_flags_offset[0] << 16);
    bpf_trace_printk("%lx\n", state);
    return 0;
}
int kprobe__tcp_ioctl(struct pt_regs *ctx, struct sock *sk, int cmd)
{
    uint64_t state = 0x7, tmp = 0;
    state = state | ((sk->sk_socket->state&0xf) << 4);
    state = state | ((sk->sk_socket->type&0xf) << 8);
    state = state | ((sk->sk_socket->flags&0xf) << 12);
    tmp = cmd;
    if(cmd == 0x541B || cmd == 0x8905 || cmd == 0x894b || cmd == 0x5411)
    state = state | ((tmp&0xffff) << 16);
    bpf_trace_printk("%lx\n", state);
    return 0;
}
`

var ProbePoint []string = []string{"tcp_v6_init_sock","tcp_v6_connect","tcp_sendmsg","tcp_recvmsg","tcp_close","tcp_shutdown","tcp_setsockopt","tcp_getsockopt","inet_accept","inet_listen", "tcp_ioctl"}
