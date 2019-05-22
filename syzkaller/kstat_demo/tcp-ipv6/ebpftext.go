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

#define SOCK_STATE_OPT  0x1
#define SK_SHUTDOWN_OPT 0x20
#define SOCK_FLAGS_OPT  0x40
#define SK_STATE_OPT    0x80


static uint64_t set_func_id(uint32_t id)
{
    uint64_t state = 0;
    state |= ((id&0xf) << 28);
    return state &= 0xf0000000;
}

static uint64_t set_weight(uint32_t weight)
{
    uint64_t state = 0;
    state |= ((weight&0xf) << 0);
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

// Don't case which function give the state
static uint64_t getretstate(struct sock *sk, int id)
{
    uint64_t state = set_func_id(0xf), tmp = 0;
    u8 bitfield;
    uint32_t weight = 0x1;

    state |= set_state(sk, SK_SHUTDOWN_OPT|SK_STATE_OPT);

    bpf_probe_read(&bitfield, sizeof(bitfield), (void*)((long)&tcp_sk(sk)->repair_queue)-1);
    if (bitfield&0xf0) {
        tmp = bitfield&0xf0;
        state |= ((tmp>>4) << 4);
    }
    if (bitfield&0x2)
        state |= 0x1 << 8;

    // TCP_NO_QUEUE,TCP_RECV_QUEUE,TCP_SEND_QUEUE,TCP_QUEUES_NR
    tmp = tcp_sk(sk)->repair_queue & 0x3;
    state |= (tmp << 16);

    if (sk->sk_route_caps&NETIF_F_SG)
        state |= (0x1 << 20);

    if (tcp_sk(sk)->fastopen_rsk != NULL)
        state |= (0x1 << 21);

    state |= set_weight(weight);
    state = set_mask(state);
    return state;
}

int kprobe__tcp_v6_init_sock(struct pt_regs *ctx, struct sock *sk)
{
    uint64_t state = set_func_id(0);
    uint32_t weight = 0x1;

    state = set_mask(state);
    state |= set_weight(weight);
    bpf_trace_printk("%lx\n", state);
    return 0;
}

int kretprobe__tcp_v6_init_sock(struct pt_regs *ctx, struct sock *sk)
{
    bpf_trace_printk("%lx\n", getretstate(sk,0));
    return 0;
}

int kprobe__tcp_v6_connect(struct pt_regs *ctx, struct sock *sk)
{
    uint64_t state = set_func_id(0x1);
    uint32_t weight = 0x1;

    state |= set_weight(weight);
    state = set_mask(state);
    bpf_trace_printk("%lx\n", state);
    return 0;
}

int kretprobe__tcp_v6_connect(struct pt_regs *ctx, struct sock *sk)
{
    bpf_trace_printk("%lx\n", getretstate(sk, 1));
    return 0;
}

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg)
{
    uint64_t state = set_func_id(0x2), tmp = 0;
    u8 bitfield;
    uint32_t weight = 0x1;

    tmp = sk->sk_state&0xf;
    if(tmp == TCP_ESTABLISHED || tmp == TCP_CLOSE || tmp == TCP_CLOSE_WAIT || tmp == TCP_SYN_SENT)
        state |= ((tmp&0xf) << 32);

    tmp = sk->sk_shutdown&0x3;
    if(tmp == SEND_SHUTDOWN)
        state |= ((tmp&0x3) << 36);

    // nonagle, repair
    bpf_probe_read(&bitfield, sizeof(bitfield), (void*)((long)&tcp_sk(sk)->repair_queue)-1);
    if (bitfield&0xf0) {
        tmp = bitfield&0xf0;
        state |= ((tmp>>4) << 4);
    }
    if (bitfield&0x2) 
        state |= 0x1 << 8;

    // defer_connect
    bpf_probe_read(&bitfield, sizeof(bitfield), (void*)((long)&inet_sk(sk)->rcv_tos)-1);
    if (bitfield&0xf0) {
        tmp = bitfield&0xf0;
        state = state | ((tmp>>4) << 10);
    }

    // TCP_NO_QUEUE,TCP_RECV_QUEUE,TCP_SEND_QUEUE,TCP_QUEUES_NR
    tmp = tcp_sk(sk)->repair_queue & 0x3;
    state |= (tmp << 14);

    // Input
    // MSG_ZEROCOPY,MSG_DONTWAIT,MSG_FASTOPEN,MSG_OOB, MSG_EOR, MSG_MORE...
    /*tmp = msg->msg_flags;
    if (tmp&MSG_OOB)
        state |= (0x1 << 18);
    if (tmp&MSG_DONTWAIT)
        state |= (0x1 << 19);
    if (tmp&MSG_EOR)
        state |= (0x1 << 20);
    if (tmp&MSG_MORE)
        state |= (0x1 << 21);
    if (tmp&MSG_ZEROCOPY)
        state |= (0x1 << 22);
    if (tmp&MSG_FASTOPEN)
        state |= (0x1 << 23);
    if (msg->msg_controllen)
        state |= (0x1 << 24);*/

    if (sk->sk_route_caps&NETIF_F_SG)
        state |= (0x1 << 25);

    if (tcp_sk(sk)->fastopen_rsk != NULL)
        state |= (0x1 << 26);

    // msg_data_left
    if (msg->msg_iter.count)
        state |= (0x1 << 27);

    state |= set_weight(weight);
    state = set_mask(state);
    bpf_trace_printk("%lx\n", state);
    return 0;
}

int kretprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk)
{
    bpf_trace_printk("%lx\n", getretstate(sk, 2));
    return 0;
}

int kprobe__tcp_recvmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, int flags)
{
    uint64_t state = set_func_id(0x3), tmp = 0;
    uint32_t weight = 0x1;
    u8 bitfield;

    tmp = sk->sk_state&0xf;
    if(tmp == TCP_ESTABLISHED || tmp == TCP_CLOSE || tmp == TCP_CLOSE_WAIT || tmp == TCP_LISTEN)
        state |= ((tmp&0xf) << 32);

    tmp = sk->sk_shutdown&0x3;
    if(tmp == RCV_SHUTDOWN)
        state |= ((tmp&0x3) << 36);


    //MSG_OOB, MSG_ERRQUEUE, MSG_PEEK, MSG_TRUNC, MSG_WAITALL
   /* tmp = flags;
    if (tmp&MSG_PEEK)
        state |= (0x1 << 4);
    if (tmp&MSG_ERRQUEUE)
        state |= (0x1 << 5);
    if (tmp&MSG_OOB)
        state |= (0x1 << 6);
    if (tmp&MSG_TRUNC)
        state |= (0x1 << 7);
    if (tmp&MSG_WAITALL)
        state |= (0x1 << 8);*/

    // TCP_NO_QUEUE,TCP_RECV_QUEUE,TCP_SEND_QUEUE,TCP_QUEUES_NR
    tmp = tcp_sk(sk)->repair_queue&0x3;
    state |= (tmp&0x3 << 20);

    tmp = 1;
    bpf_probe_read(&bitfield, sizeof(bitfield), (void*)((long)&tcp_sk(sk)->repair_queue)-1);
    if (bitfield&0x2) 
        state = state | (tmp << 24);

    state |= set_weight(weight);
    state = set_mask(state);
    bpf_trace_printk("%lx\n", state);
    return 0;
}

int kretprobe__tcp_recvmsg(struct pt_regs *ctx, struct sock *sk)
{
    bpf_trace_printk("%lx\n", getretstate(sk, 3));
    return 0;
}

int kprobe__tcp_close(struct pt_regs *ctx, struct sock *sk)
{
    uint64_t state = set_func_id(0x4), tmp = 0;
    u8 bitfield;
    uint32_t weight = 0x1;

    tmp = sk->sk_state&0xf;
    if(tmp == TCP_LISTEN)
        state |= ((tmp&0xf) << 32);

    tmp = 1;
    bpf_probe_read(&bitfield, sizeof(bitfield), (void*)((long)&tcp_sk(sk)->repair_queue)-1);
    if (bitfield&0x2) 
        state |= (tmp << 8);

    tmp = 1;
    if (tcp_sk(sk)->linger2)
        state |= (tmp << 12);

    state |= set_weight(weight);
    state = set_mask(state);
    bpf_trace_printk("%lx\n", state);
    return 0;
}

int kretprobe__tcp_close(struct pt_regs *ctx, struct sock *sk)
{
    bpf_trace_printk("%lx\n", getretstate(sk, 4));
    return 0;
}

int kprobe__tcp_shutdown(struct pt_regs *ctx, struct sock *sk, int how)
{
    uint64_t state = set_func_id(0x5), tmp = 0;
    uint32_t weight = 0x1;

    tmp = how;
    state |= (tmp&0xff << 4);

    if ((1 << sk->sk_state)&(TCPF_ESTABLISHED | TCPF_SYN_SENT | TCPF_SYN_RECV | TCPF_CLOSE_WAIT))
        state |= (0x1 << 12);

    state |= set_weight(weight);
    state =  set_mask(state);
    bpf_trace_printk("%lx\n", state);
    return 0;
}

int kretprobe__tcp_shutdown(struct pt_regs *ctx, struct sock *sk)
{
    bpf_trace_printk("%lx\n", getretstate(sk, 5));
    return 0;
}

int kprobe__tcp_setsockopt(struct pt_regs *ctx, struct sock *sk, int level, int optname)
{
    uint64_t state = set_func_id(0x6), tmp = 0;
    u8 bitfield;
    uint32_t weight = 0x1;

    tmp = sk->sk_state&0xf;
    if(tmp == TCP_ESTABLISHED || tmp == TCP_CLOSE || tmp == TCP_CLOSE_WAIT || tmp == TCP_LISTEN)
        state |= ((tmp&0xf) << 32);

    // TCP_NO_QUEUE,TCP_RECV_QUEUE,TCP_SEND_QUEUE,TCP_QUEUES_NR
    tmp = tcp_sk(sk)->repair_queue & 0x3;
    state |= (tmp << 16);

    // tp->repair, tp->nonagle
    tmp = 1;
    bpf_probe_read(&bitfield, sizeof(bitfield), (void*)((long)&tcp_sk(sk)->repair_queue)-1);
    if (bitfield&0x2)
        state = state | (tmp << 20);
    if (bitfield&0xf0) {
        tmp = bitfield;
        state |= ((tmp&0xf0 >> 4) << 24);
    }

    state |= set_weight(weight);
    state = set_mask(state);
    bpf_trace_printk("%lx\n", state);
    return 0;
}

int kretprobe__tcp_setsockopt(struct pt_regs *ctx, struct sock *sk)
{
    bpf_trace_printk("%lx\n", getretstate(sk, 6));
    return 0;
}

int kprobe__tcp_getsockopt(struct pt_regs *ctx, struct sock *sk, int level, int optname)
{
    uint64_t state = set_func_id(0x7), tmp = 0;
    uint32_t weight = 0x1;
    u8 bitfield;

    tmp = sk->sk_state&0xf;
    if(tmp == TCP_CLOSE || tmp == TCP_LISTEN)
        state |= ((tmp&0xf) << 32);

    // TCP_NO_QUEUE,TCP_RECV_QUEUE,TCP_SEND_QUEUE,TCP_QUEUES_NR
    tmp = tcp_sk(sk)->repair_queue & 0x3;
    state |= (tmp << 16);

    tmp = 1;
    bpf_probe_read(&bitfield, sizeof(bitfield), (void*)((long)&tcp_sk(sk)->repair_queue)-1);
    if (bitfield&0x2)
        state |= (tmp << 20);

    state |= set_weight(weight);
    state = set_mask(state);
    bpf_trace_printk("%lx\n", state);
    return 0;
}

int kretprobe__tcp_getsockopt(struct pt_regs *ctx, struct sock *sk)
{
    bpf_trace_printk("%lx\n", getretstate(sk, 7));
    return 0;
}

int kprobe__inet_accept(struct pt_regs *ctx, struct socket *sock, struct socket* newsock, int flags, bool kern)
{
    uint64_t state = set_func_id(0x8);
    uint32_t weight = 0x1;

    if(kern)
        state = state | (0x1 << 4);
    state = set_mask(state);
    bpf_trace_printk("%lx\n", state);

    state = set_func_id(9);
    if(kern)
        state = state | (0x1 << 4);

    state |= set_weight(weight);
    state = set_mask(state);
    bpf_trace_printk("%lx\n", state);
    return 0;
}

int kretprobe__inet_accept(struct pt_regs *ctx, struct socket *sock, struct socket* newsock)
{
    bpf_trace_printk("%lx\n", getretstate(sock->sk, 8));
    bpf_trace_printk("%lx\n", getretstate(newsock->sk, 9));
    return 0;
}

int kprobe__inet_listen(struct pt_regs *ctx, struct socket *sock)
{
    uint64_t state = set_func_id(0xa), tmp;
    uint32_t weight = 0x1;

    tmp = sock->sk->sk_state&0xf;
    if(tmp == TCP_LISTEN || tmp == TCP_CLOSE)
        state |= ((tmp&0xf) << 32);

    state |= set_weight(weight);
    state = set_mask(state);
    bpf_trace_printk("%lx\n", state);
    return 0;
}

int kretprobe__inet_listen(struct pt_regs *ctx, struct socket *sock)
{
    bpf_trace_printk("%lx\n", getretstate(sock->sk, 0xa));
    return 0;
}

int kprobe__tcp_ioctl(struct pt_regs *ctx, struct sock *sk, int cmd)
{
    uint64_t state = set_func_id(0xb), tmp, mask;
    uint32_t weight = 0x1;

    tmp = cmd;
    mask = SIOCINQ|SIOCATMARK|SIOCOUTQ|SIOCOUTQNSD;
    if (tmp==SIOCINQ || tmp==SIOCATMARK || tmp==SIOCOUTQ || tmp==SIOCOUTQNSD)
            state |= ((cmd&mask) << 4);
    state |= set_weight(weight);
    state = set_mask(state);
    bpf_trace_printk("%lx\n", state);
    return 0;
}

int kretprobe__tcp_ioctl(struct pt_regs *ctx, struct sock *sk)
{
    bpf_trace_printk("%lx\n", getretstate(sk, 0xb));
    return 0;
}

int kprobe__inet6_bind(struct pt_regs *ctx, struct sock *sk, struct sockaddr *uaddr, bool with_lock)
{
    uint64_t state = set_func_id(0xc);
    uint32_t weight = 0x1;

    state |= set_weight(weight);
    state = set_mask(state);
    bpf_trace_printk("%lx\n", state);
    return 0;
}

int kretprobe__inet6_bind(struct pt_regs *ctx, struct sock *sk)
{
    bpf_trace_printk("%lx\n", getretstate(sk, 0xc));
    return 0;
}

int kprobe__inet6_ioctl(struct pt_regs *ctx, struct sock *sk, int cmd)
{
    uint64_t state = set_func_id(0xd), tmp, mask;
    uint32_t weight = 0x1;

    tmp = cmd;
    mask = SIOCINQ|SIOCATMARK|SIOCOUTQ|SIOCOUTQNSD;
    if (tmp==SIOCINQ || tmp==SIOCATMARK || tmp==SIOCOUTQ || tmp==SIOCOUTQNSD)
        state |= ((cmd&(0x541B|0x8905|0x894b|0x5411)) << 4);
    state |= set_weight(weight);
    state = set_mask(state);
    bpf_trace_printk("%lx\n", state);
    return 0;
}

int kretprobe__inet6_ioctl(struct pt_regs *ctx, struct sock *sk)
{
    bpf_trace_printk("%lx\n", getretstate(sk, 0xd));
    return 0;
}

int kprobe__inet6_getname(struct pt_regs *ctx, struct sock *sk, int cmd, int peer)
{
    uint64_t state = set_func_id(0xe), tmp;
    uint32_t weight = 0x1;

    tmp = 0x1;
    if (peer == 1)
        state |= (tmp << 4);

    state |= set_weight(weight);
    state = set_mask(state);
    bpf_trace_printk("%lx\n", state);
    return 0;
}

int kretprobe__inet6_getname(struct pt_regs *ctx, struct sock *sk)
{
    bpf_trace_printk("%lx\n", getretstate(sk, 0xe));
    return 0;
}

`
/* Kernel probe/retprobe point */
var ProbePoint []string = []string{"tcp_v6_init_sock","tcp_v6_connect","tcp_sendmsg","tcp_recvmsg","tcp_close","tcp_shutdown","tcp_setsockopt","tcp_getsockopt","inet_accept","inet_listen", "tcp_ioctl", "inet6_bind", "inet6_getname","inet6_ioctl"}

var RetProbePoint []string = []string{/*"tcp_v6_init_sock","tcp_v6_connect","tcp_sendmsg","tcp_recvmsg","tcp_close","tcp_shutdown","tcp_setsockopt","tcp_getsockopt","inet_accept","inet_listen", "tcp_ioctl", "inet6_bind", "inet6_getname","inet6_ioctl"*/}
