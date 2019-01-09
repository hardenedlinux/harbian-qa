package ebpf

import (
	"fmt"
	"os"
	//"strconv"
	//"log"

	"github.com/iovisor/gobpf/bcc"
	"github.com/iovisor/gobpf/pkg/tracepipe"
)

/*
 * As an example, we monitor the state, type, flags in socket structure.
 * Use ebpf map is a better way to monitor kernel data state.
 * But that isn't feasible under syzkaller frame because prog's( syscalls) running shouldn't be broken down.
 * Breaking every syscall for checking the ebpf map will cause other problems.
 * So, we print the state in every hook and handle them after prog complete 
 */

const ebpftext string =`
#include <net/sock.h>
#include <linux/net.h>
#define KPP "[KPROBE_P]:"
#define SOCK_ID "[SOCKET_ID]:"

static void tcp_print_sock(struct socket *sock)
{
    unsigned int state = 0;
    bpf_trace_printk(SOCK_ID"%p\n", sock);
    if(sock)
        state =  state|(1 << 16);
    state = state | ((sock->flags & 0x7) << 0);
    state = state | ((sock->type & 0xf) << 4);
    state = state | ((sock->state & 0x7) << 8);
    bpf_trace_printk("socket_state:%d\n", state);
}

static void print_sk(struct sock *sk)
{
    tcp_print_sock(sk->sk_socket);
}
`
const initp string =`
int kprobe__tcp_v6_init_sock(struct pt_regs *ctx, struct sock *sk)
{
    bpf_trace_printk(KPP"tcp_v6_init_sock\n");
    print_sk(sk);
    return 0;
}
`
const connectp string =`
int kprobe__tcp_v6_connect(struct pt_regs *ctx, struct sock *sk)
{
    bpf_trace_printk(KPP"tcp_v6_connect\n");
    print_sk(sk);
    return 0;
}
`
const sendmsgp string =`
int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk)
{
    bpf_trace_printk(KPP"tcp_sendmsg\n");
    print_sk(sk);
    return 0;
}
int kprobe__tcp_recvmsg(struct pt_regs *ctx, struct sock *sk)
{
    bpf_trace_printk(KPP"tcp_recvmsg\n");
    print_sk(sk);
    return 0;
}
int kprobe__tcp_close(struct pt_regs *ctx, struct sock *sk)
{
    bpf_trace_printk(KPP"tcp_close\n");
    print_sk(sk);
    return 0;
}
int kprobe__tcp_shutdown(struct pt_regs *ctx, struct sock *sk)
{
    bpf_trace_printk(KPP"tcp_shutdown\n");
    print_sk(sk);
    return 0;
}
int kprobe__tcp_setsockopt(struct pt_regs *ctx, struct sock *sk)
{
    bpf_trace_printk(KPP"tcp_setsockopt\n");
    print_sk(sk);
    return 0;
}
int kprobe__tcp_getsockopt(struct pt_regs *ctx, struct sock *sk)
{
    bpf_trace_printk(KPP"tcp_getsockopt\n");
    print_sk(sk);
    return 0;
}
int kprobe__inet_accept(struct pt_regs *ctx, struct socket *sock, struct socket* newsock)
{
    bpf_trace_printk(KPP"inet_accept\n");
    tcp_print_sock(sock);
    tcp_print_sock(newsock);
    return 0;
}
int kprobe__inet_listen(struct pt_regs *ctx, struct socket *sock)
{
    bpf_trace_printk(KPP"inet_listen\n");
    tcp_print_sock(sock);
    return 0;
}
`

func EbpfInit() string {
	ebpf := ebpftext + initp + connectp + sendmsgp
	return ebpf
}

func Attachs(m *bcc.Module) {
	attach("tcp_v6_init_sock", m)
	attach("tcp_v6_connect", m)
	attach("tcp_sendmsg", m)
	attach("tcp_recvmsg", m)
	attach("tcp_close", m)
	attach("tcp_shutdown", m)
	attach("tcp_setsockopt", m)
	attach("tcp_getsockopt", m)
	attach("inet_accept", m)
	attach("inet_listen", m)
}

func ReadLine(tp *tracepipe.TracePipe, pid uint64) string {
	return readline(tp, pid)
}

func attach(kprobepoint string, m *bcc.Module) {
	funcName := "kprobe__" + kprobepoint
	tmpKprobe, err := m.LoadKprobe(funcName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load %s: %s\n", kprobepoint, err);
		os.Exit(1)
	}

	err = m.AttachKprobe(kprobepoint, tmpKprobe)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach %s: %s\n", kprobepoint, err);
		os.Exit(1)
	}
}

/* read a single line from ebpf, strip useless information */
func readline(tp *tracepipe.TracePipe, pid uint64) string {
	ret := ""
	te, err := tp.ReadLine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to ReadLine\n", err);
		return ret
	}
	if (te.Message) != "" {
		ret = te.Message
	}
	return ret
}
