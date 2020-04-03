# Make syzkaller a state-based guided fuzzer

## Goal
Make the syzkaller as a kernel-state-awareness fuzzer or state-based guided fuzzer. The fuzzer should collect the progs which cover the same code but with different kernel data state. Currently syzkaller only collect coverage information. I wonder if it's effective that make syzkaller more kernel-state-awareness. I'd finish collecting some socket state as syzkaller feedback currently. Using the coverage signal interface in syzkaller. And I will show you how to combine these features in a specified purpose fuzzing.

## Foundation of theory

### Why should we collect the state
For example, assume the prog "socket--setsockopt$1--setsockopt$2--sendmsg(EXPECT_FLAG)" is a desired prog, if only coverage is collected, a pseudocode can be write down as:  
```
// Cov(prog) is the coverage of a prog
// We assume that only both setsockopt$1 and setsockopt$2 was used
// before sendmsg, new coverage will appear in sendmsg(EXPECT_FLAG).
// EXPECT_FLAG: The flag restrist sendmsg to a new branch
Cov(socket+setsockopt$1)+Cov(socket+setsockopt$2)+Cov(socket+sendmsg(NOEXPECT_FLAG))
= Cov(socket+setsockopt1+setsockopt2)
= Cov(socket+setsockopt$1+setsocketopt$2+sendmsg(NOEXPECT_FLAG))
!= Cov(socket+setsockopt$1+setsocketopt$2+sendmsg(EXPECT_FLAG))
```
The prog can't be put into corpus until a new coverage signal was detected. Without any gradient between subprog and desired prog. After adding state-based feedback, 
```  
// some State(prog) may be miss by syzkaller
// Both of these combinations of syscall may help the coverage discovering 
State_or_Cov(socket+setsockopt$1)+State(socket+setsockopt$2)
!= State_or_Cov(socket+setsockopt1+setsockopt$2)
!= State_or_Cov(socket+setsockopt$1+setsocketopt$2+sendmsg(ANY))
!= State_or_Cov(socket+setsockopt$1+setsocketopt$2+sendmsg(EXPECT_FLAG))
```
Some prog with new state can be collected to corpus and used to generate and mutate. All of them is the gradient that help syzkaller to generate the desired prog. In recent syzkaller, a "resource centric" was introduce and it's quite similar to "state" what we need, although syzkaller use the whole corpus as "resource". The difference is, we mark a prog as resource when it can only build a special kernel state without a new coverage.

### Types of branch  
From another perspective, coverage is the same as how many branchs the fuzzer has solved. In practice, degree of diffculty in covering different type of branch are different. Kernel state can be restraint of branch. In a kernel function, there are some type of branch:
1. A condition directly determined by kernel function parameters. Without any impact from other syscalls. In other words, it can be easily covered by mutating a single syscall.
In this [example](https://elixir.bootlin.com/linux/v4.20/source/net/ipv4/tcp.c#L1188), msg_flags is a branch-relative parameters which specified by the input of syscall 'sendmsg'.

2. A condition determined by kernel function parameters' historical state.
In first [example](https://elixir.bootlin.com/linux/v4.20/source/net/ipv4/tcp.c#L1189), sk_state is a historical state which can be changed after calling listen/connect... In second [one](https://elixir.bootlin.com/linux/v4.20/source/net/ipv4/tcp.c#L1231), repair_queue is changed after calling setsockopt.

3. A condition determined by a local variable that can be changed in the kernel function.
In this [example](https://elixir.bootlin.com/linux/v4.20/source/net/ipv4/tcp.c#L1346), local variable merge is changed by this [line](https://elixir.bootlin.com/linux/v4.20/source/net/ipv4/tcp.c#L1330).  

#### Which is not easy to be covered

First one can be easily covered by syzkaller if powerful syscalls scriptions have been written. Collect function's input as feedbacl helps little coverage. Even though there are several paramters.

The second one, need time to explore, especial nested condition. For example, in tcp-ipv6 testing, we should not assume that setsockopt/getsockopt/close/shutdown... have no impact on calling sendmsg. Enable too much syscalls will waste much time on exploring their coverage( Original syzkaller do this). Actually, it has no impact on sendmsg unless it trigger a special state for sendmsg( A new State(prog) was discovered). Collecting useful state before calling sendmsg, without collecting any coverage signal of other kernel functions could be more effective. It's actually what i done in state-base fuzzer. And it get a great improvement in some special purpos fuzzer.

The third one need time to explore too. But it can't be solved by using ebpf feedback. ebpf know nothing about the internal of kernel function. I think fault-injection is a way that can help it. Kernel have a general framework to do function-ret-fault-injection. But it can't attach to inline function. ebpf use this framework also. It has much work to do with supporting a specified fault-injection in syzkaller.

### Result
It got a great improvement in the second type of branch. [Here](tcp-ipv6/test.md) is a example for tcp-ipv6. It can easily cover some branch with restraint like "tp->repair", "tp->repair_queue == TCP_*_QUEUE", "sk->sk_state == TCP_CLOSE". All of these branch need more time to explore in original syzkaller.

## Usage  
### Patch syzkaller  
First, you need to patch original syzkaller. 
```  
git checkout a34e2c33
git apply *.patch
```
### Gobpf as syzkaller feedback  
To build a ebpf as syzkaller feedback, run:  
```  
go build pipe_monitor.go
```

### Run state-base syzkaller
Just run syz-manager as original syzkaller.

### What can you customize  

#### Code and features  
1. Add ebpf feedback and display in webui: run a ebpf monitor before execute_one, read pipe memory to get kernel socket state as syzkaller feedback.
2. Add coverage filter: filter coverage by address. I use syz-func2addr to get a function address from ELF.
3. pipe_monitor.go: load a ebpf text, monitor the socket state, feedback to syzkaller by using pipe memory. But it can't trace the historical state of a specific socket.
4. Add ret ebpfsig as resource: only prog with a special kernel state can be resource.

* These patch base on upstream syzkaller: a34e2c33  
More detail refer to the code comments. 

#### ebpf, kernel data type

ebpf text in ebpf/ebpftext.go is the only one file can be modified as your will. You can get any data you want by writing ebpf by yourself. Notice:
1. A hook function before kernel function should be named as kprobe_KFUNC_NAME and append to the list ProbePoint.
2. Similarly, a kernel function return hook should be named as kretprobe_KFUNC_NAME and append to the RetProbePoint.
3. The state send to syzkaller by using ebpf function "bpf_trace_printk". Currently, I use a uint64_t state. If you need state with other type, there are a lot work in syzkaller should be done to coordinary with ebpf's output.

* kernel socket state: parse/parse.go is only for making the socket state readable. Modify it refer to you ebpf text as your will. Only for execprog. Now it's discarded.

## Some example  
pipe_monitor can run well with patched syzkaller. Without any different compare to original syzkaller's using. But you need write your ebpf to collect state you want.

We had already used these featrue to do some fuzz:
### tcp-ipv6 subsystem fuzzer
According to [this](#Which is not easy to be covered), to fuzz the tcp-ipv6 subsystem, I use the follow feature:
1. Use ebpf to collect the expected input of kernel function.
2. Kernel function coverage filtering. Only collect the coverage of _ops function
3. Filtering the all kernel function coverage except subsystem you need to fuzz.	

### Arbitrary kernel function fuzzer
1. Use ebpf to collect socket state before return from syscalls. Mark this type of prog as resource.
2. Use ebpf to collect the expected input of a kernel function.
3. Filtering the all kernel function coverage except the one you need to fuzz.  
[Here](tcp-ipv6/test.md) are some comparisons of performance of different feedback fuzzer.

### Multi-policy fuzzer
We also try to combine this different policy fuzzer by using syz-hub. [Here](../multi_policy/README.md) is a documentation.