package ebpf

/* High-32-bit: |-----|-sk_state-|-flags-|-sk_shutdown--|--state--|
 *              |-----|---4bit---|--4bit-|-----2bit-----|--4bit---|
 * Low-32-bit:  |-func-id-|---branch-related-argument---|--weight-|
 *              |--4-bit--|-------n-bit-----------------|--4bit---|
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
#include <net/net_namespace.h>
#include <linux/skbuff.h>

#define SOCK_STATE_OPT  0x1
#define SK_SHUTDOWN_OPT 0x2
#define SOCK_FLAGS_OPT  0x4
#define SK_STATE_OPT    0x8
#define SK_FLAGS_OPT    0x10
#define SK_ERR_OPT      0x20

#define STATE_MASK      0xe000000000000000
#define RETSTATE_MASK   0xf000000000000000

static uint64_t set_func_id(uint32_t id)
{
    uint64_t state = 0;
    state |= ((id&0xf) << 28);
    return state &= 0xf0000000;
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
    // SOL_SOCKET
    if (opt&SK_FLAGS_OPT) {
        tmp = sk->sk_flags&0xff;
        state |= (tmp << 48);
    }
    if (opt&SK_ERR_OPT) {
        if (sk->sk_err > 0) {
            tmp = 1;
            state |= (tmp << 49);
        }
    }
    return state;
}

static uint64_t set_mask(uint64_t state)
{
    uint64_t tmp = STATE_MASK;
    return state|tmp;
}

// Don't case about which function give the state
static uint64_t getretstate(struct sock *sk, int id)
{
    uint64_t state = 0, tmp = 0;
    u8 bitfield;

    state |= set_state(sk, SOCK_STATE_OPT|SK_SHUTDOWN_OPT|SOCK_FLAGS_OPT|SK_STATE_OPT|SK_FLAGS_OPT|SK_ERR_OPT);
    // nonagle, repair
    bpf_probe_read(&bitfield, sizeof(bitfield), (void*)((long)&tcp_sk(sk)->repair_queue)-1);
    if (bitfield&0xf0) {
        tmp = bitfield&0xf0;
        state |= ((tmp>>4) << 48);
    }
    tmp = 0x1;
    if (bitfield&0x2) 
        state |= tmp << 52;

    // defer_connect
    bpf_probe_read(&bitfield, sizeof(bitfield), (void*)((long)&inet_sk(sk)->rcv_tos)-1);
    if (bitfield&0xf0) {
        tmp = bitfield&0xf0;
        state = state | ((tmp>>4) << 53);
    }

    // TCP_NO_QUEUE,TCP_RECV_QUEUE,TCP_SEND_QUEUE,TCP_QUEUES_NR
    tmp = tcp_sk(sk)->repair_queue & 0x3;
    state |= (tmp << 57);


    // tp->fastopen_req
    if (tcp_sk(sk)->fastopen_req)
        state |= (0x1 << 16);
    if (tcp_sk(sk)->fastopen_rsk != NULL)
        state |= (0x1 << 17);

    tmp = RETSTATE_MASK;
    return state|tmp;
}

int kretprobe__tcp_v6_init_sock(struct pt_regs *ctx, struct sock *sk)
{
    bpf_trace_printk("%llx\n", getretstate(sk,0));
    return 0;
}

int kretprobe__tcp_v6_connect(struct pt_regs *ctx, struct sock *sk)
{
    bpf_trace_printk("%llx\n", getretstate(sk, 1));
    return 0;
}

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size)
{
    uint64_t state = set_func_id(0x2), tmp = 0;
    u8 bitfield;

    tmp = sk->sk_state&0xf;
    if(tmp == TCP_ESTABLISHED || tmp == TCP_CLOSE || tmp == TCP_CLOSE_WAIT || tmp == TCP_SYN_SENT)
        state |= ((tmp&0xf) << 32);

    tmp = sk->sk_shutdown&0x3;
    if(tmp == SEND_SHUTDOWN)
        state |= ((tmp&0x3) << 36);

    tmp = sk->sk_flags&0xff;
    if(tmp == SOCK_ZEROCOPY)
        state |= ((tmp&0xff) << 40);

    // nonagle, repair
    bpf_probe_read(&bitfield, sizeof(bitfield), (void*)((long)&tcp_sk(sk)->repair_queue)-1);
    if (bitfield&0xf0) {
        tmp = bitfield&0xf0;
        state |= ((tmp>>4) << 48);
    }
    tmp = 0x1;
    if (bitfield&0x2) 
        state |= tmp << 52;

    // defer_connect
    bpf_probe_read(&bitfield, sizeof(bitfield), (void*)((long)&inet_sk(sk)->rcv_tos)-1);
    if (bitfield&0xf0) {
        tmp = bitfield&0xf0;
        state = state | ((tmp>>4) << 53);
    }

    // TCP_NO_QUEUE,TCP_RECV_QUEUE,TCP_SEND_QUEUE,TCP_QUEUES_NR
    tmp = tcp_sk(sk)->repair_queue & 0x3;
    state |= (tmp << 57);


    // tp->fastopen_req
    if (tcp_sk(sk)->fastopen_req)
        state |= (0x1 << 16);
    if (tcp_sk(sk)->fastopen_rsk != NULL)
        state |= (0x1 << 17);

    // From syscalls argument
    // msg->msg_controllen
    /*if (msg->msg_controllen)
        state |= (0x1 << 20);
    // msg->msg_flags
    if (msg->msg_flags&MSG_OOB)
        state |= (0x1 << 21);
    // msg->msg_flags
    if (msg->msg_flags&MSG_MORE)
        state |= (0x1 << 22);
    // msg->msg_flags
    if (msg->msg_flags&MSG_EOR)
        state |= (0x1 << 23);
    // msg->msg_flags
    if (msg->msg_flags&MSG_ZEROCOPY)
        state |= (0x1 << 24);
    // msg_data_left
    if (msg->msg_iter.count)
        state |= (0x1 << 27);*/

    state = set_mask(state);
    bpf_trace_printk("%llx\n", state);
    return 0;
}

int kretprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk)
{
    bpf_trace_printk("%llx\n", getretstate(sk, 2));
    return 0;
}

int kretprobe__tcp_recvmsg(struct pt_regs *ctx, struct sock *sk)
{
    bpf_trace_printk("%llx\n", getretstate(sk, 3));
    return 0;
}

int kretprobe__tcp_close(struct pt_regs *ctx, struct sock *sk)
{
    bpf_trace_printk("%llx\n", getretstate(sk, 4));
    return 0;
}

int kretprobe__tcp_shutdown(struct pt_regs *ctx, struct sock *sk)
{
    bpf_trace_printk("%llx\n", getretstate(sk, 5));
    return 0;
}

int kretprobe__tcp_setsockopt(struct pt_regs *ctx, struct sock *sk)
{
    bpf_trace_printk("%llx\n", getretstate(sk, 6));
    return 0;
}

int kretprobe__tcp_getsockopt(struct pt_regs *ctx, struct sock *sk)
{
    bpf_trace_printk("%llx\n", getretstate(sk, 7));
    return 0;
}

int kretprobe__inet_accept(struct pt_regs *ctx, struct socket *sock, struct socket* newsock)
{
    bpf_trace_printk("%llx\n", getretstate(sock->sk, 8));
    bpf_trace_printk("%llx\n", getretstate(newsock->sk, 9));
    return 0;
}

int kretprobe__inet_listen(struct pt_regs *ctx, struct socket *sock)
{
    bpf_trace_printk("%llx\n", getretstate(sock->sk, 0xa));
    return 0;
}

int kretprobe__tcp_ioctl(struct pt_regs *ctx, struct sock *sk)
{
    bpf_trace_printk("%llx\n", getretstate(sk, 0xb));
    return 0;
}

int kretprobe__inet6_bind(struct pt_regs *ctx, struct sock *sk)
{
    bpf_trace_printk("%llx\n", getretstate(sk, 0xc));
    return 0;
}

int kretprobe__inet6_ioctl(struct pt_regs *ctx, struct sock *sk)
{
    bpf_trace_printk("%llx\n", getretstate(sk, 0xd));
    return 0;
}

int kretprobe__inet6_getname(struct pt_regs *ctx, struct sock *sk)
{
    bpf_trace_printk("%llx\n", getretstate(sk, 0xe));
    return 0;
}

`
/* Kernel probe/retprobe point */
var ProbePoint []string = []string{"tcp_sendmsg"}

var RetProbePoint []string = []string{"tcp_v6_init_sock","tcp_v6_connect","tcp_sendmsg","tcp_recvmsg","tcp_close","tcp_shutdown","tcp_setsockopt","tcp_getsockopt","inet_accept","inet_listen", "tcp_ioctl", "inet6_bind", "inet6_getname","inet6_ioctl"}
