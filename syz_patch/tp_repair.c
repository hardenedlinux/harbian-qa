/* The code modify from https://raw.githubusercontent.com/ilammy/ftrace-hook/master/ftrace_hook.c */
#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/types.h>

/* For process id */
#include <linux/thread_info.h>
#include <asm/current.h>

/* For tcp function/structure */
#include <linux/tcp.h>

#define HOOK_KF_NAME "tcp_setsockopt"

static unsigned long ft_address;
static struct ftrace_ops ft_ops;
static int obj_ppid;
static int (*real_tcp_setsockopt)(struct sock *sk, int level, int optname, char __user *optval, unsigned int optlen);

module_param(obj_ppid, int, 0);

static notrace int fh_tcp_setsockopt(struct sock *sk, int level, int optname, char __user *optval, unsigned int optlen)
{
  int ret;
  static unsigned int rand;
  struct tcp_sock* tp = tcp_sk(sk);
  pid_t pid;

  get_random_bytes(&rand, sizeof(unsigned int));
  if(rand%10 <= 5){
    tp->repair = true;
    printk("Hijack tcp_setsockopt\n");
  }

  real_tcp_setsockopt = (void*)(ft_address + MCOUNT_INSN_SIZE);
  pid = current->pid;
  printk("[PID:%d]:Hello tcp_setsockopt, my parent is %d\n", pid, obj_ppid);
  ret = real_tcp_setsockopt(sk, level, optname, optval, optlen);
  return ret;
}

static notrace noinline void fh_callback(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct pt_regs *regs)
{
  if (current->real_parent->pid == obj_ppid)
    regs->ip = (unsigned long)fh_tcp_setsockopt;
  else
    regs->ip = (unsigned long)regs->ip;
}

static int __init fh_init(void)
{
  int err;

  ft_address = kallsyms_lookup_name(HOOK_KF_NAME);
  if (!ft_address) {
    pr_debug("Symbol is not exit!\n");
    return -ENOENT;
  }

  ft_ops.func = fh_callback;
  ft_ops.flags = FTRACE_OPS_FL_SAVE_REGS
    | FTRACE_OPS_FL_RECURSION_SAFE
    | FTRACE_OPS_FL_PID
    | FTRACE_OPS_FL_IPMODIFY;

  err = ftrace_set_filter_ip(&ft_ops, ft_address, 0, 0);
  if (err) {
    pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
    return err;
  }

  err = register_ftrace_function(&ft_ops);
  if (err) {
    pr_debug("register_ftrace_function() failed: %d\n", err);
    ftrace_set_filter_ip(&ft_ops, ft_address, 1, 0);
    return err;
  }
  printk("ftrace load, ppid is %d\n", obj_ppid);
  return 0;
}

static void fh_exit(void)
{
  int err;
  err = unregister_ftrace_function(&ft_ops);
  if (err) {
    pr_debug("unregister_ftrace_function() failed: %d\n", err);
  }

  err = ftrace_set_filter_ip(&ft_ops, ft_address, 1, 0);
  if (err) {
    pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
  }
  printk("ftrace remove\n");
}

module_init(fh_init);
module_exit(fh_exit);
MODULE_DESCRIPTION("Ftrace kernel function hook");
MODULE_LICENSE("GPL");

