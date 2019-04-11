package ebpf

/* High-32-bit: |-----|-sk_state-|-flags-|-sk_shutdown--|--state--|
 *              |-----|---4bit---|--4bit-|-----2bit-----|--4bit---|
 * Low-32-bit:  |------branch-related-argument----------|-func-id-|
 *              |-----------------n-bit-----------------|--4bit---|
 * The highest n-bit was empty. You can fill it as your will.
 * Collect data for a specified function will generate too much useless 
 * signals. Hight-32-bit is only for general purpos.
 * In a monitored function, do not care too much about arguments 
 * passed to called function. Just write another probe for it.
 */ 

const EbpfSingle string =`
#include <net/sock.h>
#include <linux/net.h>
#define KBUILD_MODNAME "foo"
#include <linux/tcp.h>
#include <net/inet_sock.h>
#include <linux/ipv6.h>
#include <uapi/linux/sockios.h>
#include <uapi/asm-generic/ioctls.h>

#define SOCK_STATE_OPT  0x1
#define SK_SHUTDOWN_OPT 0x20
#define SOCK_FLAGS_OPT  0x40
#define SK_STATE_OPT    0x80


static uint64_t set_func_id(uint32_t id)
{
    uint64_t state = 0;
    state |= ((id&0xf) << 0);
    return state &= 0xf; 
}

static uint64_t set_state(struct sock *sk, int opt)
{
    uint64_t state = 0, tmp;
    u8 bitfield;

    if (opt&SOCK_STATE_OPT) {
        tmp = sk->sk_socket->state&0xf;
        state |= (tmp << 32);
    }
    // SHUTDOWN_MASK
    if (opt&SK_SHUTDOWN_OPT) {
        tmp = sk->sk_shutdown&0x3;
        state |= (tmp << 36);
    }
    if (opt&SOCK_FLAGS_OPT) {
        tmp = sk->sk_socket->flags&0xf;
        state |= (tmp << 40);
    }
    //TCP_STATE_MASK
    if (opt&SK_STATE_OPT) {
        tmp = sk->sk_state&0xf;
        state |= (tmp << 44);
    }

    return state;
}

static uint64_t set_mask(uint64_t state)
{
    return state&0xffffffffffffffff;
}

int kprobe__tcp_v6_init_sock(struct pt_regs *ctx, struct sock *sk)
{
    uint64_t state = set_func_id(0);
    state |= set_state(sk, 0x0);
    state = set_mask(state);
    bpf_trace_printk("%lx\n", state);
    return 0;
}

int kprobe__tcp_v6_connect(struct pt_regs *ctx, struct sock *sk)
{
    uint64_t state = set_func_id(1);
    state |= set_state(sk, SK_STATE_OPT);
    state = set_mask(state);
    bpf_trace_printk("%lx\n", state);
    return 0;
}

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg)
{
    uint64_t state = set_func_id(2), tmp = 0;
    u8 bitfield;
    state |= set_state(sk, SK_STATE_OPT|SK_SHUTDOWN_OPT);

    tmp = 1;
    bpf_probe_read(&bitfield, sizeof(bitfield), (void*)((long)&tcp_sk(sk)->repair_queue)-1);
    if (bitfield&0x2) 
        state = state | (tmp << 8);
    // defer_connect
    bpf_probe_read(&bitfield, sizeof(bitfield), (void*)((long)&inet_sk(sk)->rcv_tos)-1);
    if (bitfield) {
        tmp = bitfield&0xf;
        state = state | (tmp << 10);
    }
    // TCP_NO_QUEUE,TCP_RECV_QUEUE,TCP_SEND_QUEUE,TCP_QUEUES_NR
    tmp = tcp_sk(sk)->repair_queue & 0x3;
    state |= (tmp << 14);
    //MSG_ZEROCOPY,MSG_DONTWAIT,MSG_FASTOPEN,MSG_OOB, MSG_EOR, MSG_MORE...
    tmp = msg->msg_flags;
    if (tmp&0x1)
        state |= ((tmp&0x1) << 16);
    if (tmp&(0x80|0x40))
        state |= (((tmp&(0x80|0x40))>>6) << 17);
    if (tmp&0x8000)
        state |= (((tmp&0x8000)>>19) << 19);
    if (tmp&0x20000000)
        state |= (((tmp&0x20000000)>>29) << 20);
    tmp = 0x1;
    if (msg->msg_controllen)
        state |= (tmp << 24);

    state = set_mask(state);
    bpf_trace_printk("%lx\n", state);
    return 0;
}

int kprobe__tcp_recvmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, int flags)
{
    uint64_t state = set_func_id(3), tmp = 0;
    state |= set_state(sk, SK_STATE_OPT|SK_SHUTDOWN_OPT);
    u8 bitfield;

    //MSG_OOB, MSG_ERRQUEUE, MSG_PEEK, MSG_TRUNC, MSG_WAITALL
    tmp = flags;
    state = state | ((tmp&0x2123) << 4);

    // TCP_NO_QUEUE,TCP_RECV_QUEUE,TCP_SEND_QUEUE,TCP_QUEUES_NR
    tmp = tcp_sk(sk)->repair_queue&0x3;
    state |= (tmp&0x3 << 20);

    tmp = 1;
    bpf_probe_read(&bitfield, sizeof(bitfield), (void*)((long)&tcp_sk(sk)->repair_queue)-1);
    if (bitfield&0x2) 
        state = state | (tmp << 24);

    state = set_mask(state);
    bpf_trace_printk("%lx\n", state);
    return 0;
}

int kprobe__tcp_close(struct pt_regs *ctx, struct sock *sk)
{
    uint64_t state = set_func_id(4), tmp = 0;
    u8 bitfield;
    state |= set_state(sk, SK_STATE_OPT|SOCK_FLAGS_OPT);

    tmp = 1;
    bpf_probe_read(&bitfield, sizeof(bitfield), (void*)((long)&tcp_sk(sk)->repair_queue)-1);
    if (bitfield&0x2) 
        state |= (tmp << 8);

    tmp = 1;
    if (tcp_sk(sk)->linger2)
        state |= (tmp << 12);

    state = set_mask(state);
    bpf_trace_printk("%lx\n", state);
    return 0;
}

int kprobe__tcp_shutdown(struct pt_regs *ctx, struct sock *sk, int how)
{
    uint64_t state = set_func_id(5), tmp = 0;
    state |= set_state(sk, SK_STATE_OPT);
    tmp = how;
    state = state | (tmp&0xff << 4);
    state =  set_mask(state);
    bpf_trace_printk("%lx\n", state);
    return 0;
}

int kprobe__tcp_setsockopt(struct pt_regs *ctx, struct sock *sk, int level, int optname)
{
    uint64_t state = set_func_id(6), tmp = 0;
    u8 bitfield;
    state |= set_state(sk, SK_STATE_OPT);

    // Don't monitor optname, It's easy to be covered by syz's descript
    // TCP_NO_QUEUE,TCP_RECV_QUEUE,TCP_SEND_QUEUE,TCP_QUEUES_NR
    tmp = tcp_sk(sk)->repair_queue & 0x3;
    state |= (tmp << 16);

    // tp->repair, tp->nonagle
    tmp = 1;
    bpf_probe_read(&bitfield, sizeof(bitfield), (void*)((long)&tcp_sk(sk)->repair_queue)-1);
    if (bitfield&0x2)
        state = state | (tmp << 20);
    if (bitfield&0x70) {
        tmp = bitfield;
        state = state | ((tmp&0x70 >> 4) << 24);
    }

    state = set_mask(state);
    bpf_trace_printk("%lx\n", state);
    return 0;
}

int kprobe__tcp_getsockopt(struct pt_regs *ctx, struct sock *sk, int level, int optname)
{
    uint64_t state = set_func_id(7), tmp = 0;
    u8 bitfield;
    state |= set_state(sk, SK_STATE_OPT);

    // TCP_NO_QUEUE,TCP_RECV_QUEUE,TCP_SEND_QUEUE,TCP_QUEUES_NR
    tmp = tcp_sk(sk)->repair_queue & 0x3;
    state |= (tmp << 16);

    tmp = 1;
    bpf_probe_read(&bitfield, sizeof(bitfield), (void*)((long)&tcp_sk(sk)->repair_queue)-1);
    if (bitfield&0x2)
        state |= (tmp << 20);

    state = set_mask(state);
    bpf_trace_printk("%lx\n", state);
    return 0;
}

int kprobe__inet_accept(struct pt_regs *ctx, struct socket *sock, struct socket* newsock, int flags, bool kern)
{
    uint64_t state = set_func_id(8);
    state |= set_state(sock->sk, 0x0);
    if(kern)
        state = state | (0x1 << 4);
    state = set_mask(state);
    bpf_trace_printk("%lx\n", state);

    state = set_func_id(9);
    state |= set_state(sock->sk, 0x0);
    if(kern)
        state = state | (0x1 << 4);
    state = set_mask(state);
    bpf_trace_printk("%lx\n", state);
    return 0;
}

int kprobe__inet_listen(struct pt_regs *ctx, struct socket *sock)
{
    uint64_t state = set_func_id(0xa);
    state |= set_state(sock->sk, SK_STATE_OPT);
    state = set_mask(state);
    bpf_trace_printk("%lx\n", state);
    return 0;
}

int kprobe__tcp_ioctl(struct pt_regs *ctx, struct sock *sk, int cmd)
{
    uint64_t state = set_func_id(0xb), tmp, mask;
    state |= set_state(sk, 0x0);
    tmp = cmd;
    mask = SIOCINQ|SIOCATMARK|SIOCOUTQ|SIOCOUTQNSD;
    if (tmp&mask)
            state |= ((cmd&mask) << 4);
    state = set_mask(state);
    bpf_trace_printk("%lx\n", state);
    return 0;
}

int kprobe__inet6_bind(struct pt_regs *ctx, struct sock *sk, struct sockaddr *uaddr, bool with_lock)
{
    uint64_t state = set_func_id(0xc);
    state |= set_state(sk, SK_STATE_OPT);
    state = set_mask(state);
    bpf_trace_printk("%lx\n", state);
    return 0;
}

int kprobe__inet6_ioctl(struct pt_regs *ctx, struct sock *sk, int cmd)
{
    uint64_t state = set_func_id(0xd), tmp;
    state |= set_state(sk, 0x0);
    tmp = cmd;
    if(cmd&(0x541B|0x8905|0x894b|0x5411))
        state |= ((cmd&(0x541B|0x8905|0x894b|0x5411)) << 4);
    state = set_mask(state);
    bpf_trace_printk("%lx\n", state);
    return 0;
}

int kprobe__inet6_getname(struct pt_regs *ctx, struct sock *sk, int cmd, int peer)
{
    uint64_t state = set_func_id(0xe), tmp;
    state |= set_state(sk, 0x0);

    tmp = 0x1;
    if (peer == 1)
        state |= (tmp << 4);

    state = set_mask(state);
    bpf_trace_printk("%lx\n", state);
    return 0;
}
`
/* Kernel probe point, kprobe__do_mmap for syzkaller's machine check */
var ProbePoint []string = []string{"tcp_v6_init_sock","tcp_v6_connect","tcp_sendmsg","tcp_recvmsg","tcp_close","tcp_shutdown","tcp_setsockopt","tcp_getsockopt","inet_accept","inet_listen", "tcp_ioctl", "inet6_bind", "inet6_getname","inet6_ioctl"}
