# Make syzkaller a state-based guided fuzzer

## Code

1. syz-executor patch: run a ebpf monitor before execute_one, read pipe/shared memory to get kernel socket state
2. pipe_monitor/shm_monitor: load a ebpf text, monitor the socket state, feedback to syzkaller by using pipe/shared memory. pipe_monitor is more simple and efficient. But it can't track the socket.

* Patches named as:
FEATURE\_NAME1-FEATURE\_NAME2-FEATURE\_NAMEn-commit_COMMITNUM.patch

## Goal

Make the syzkaller as a kernel-state-awareness fuzzer or state-based guided fuzzer. The fuzzer should collect the progs which hit the same code coverage but with different kernel data state. Currently syzkaller only collect coverage information.

I wonder if it's effective that make syzkaller more kernel-state-awareness.
I finish collecting the some socket state and feedback to syzkaller currently. Use the coverage signal interface.


## Customize
### ebpf, kernel data type
ebpf text in ebpf/ebpftext.go can be modify as your will. You can get any data you want by writing ebpf by yourself.  In my case, the socket state i want is a uint64, fill with kprobe point(a specify num) and sk->__sk_flags ...  
The state is maintained by state/state.go.

### kernel socket state

parse/parse.go is only for making the socket state readable. Modify it refer to you ebpf text as your will.

## Example
pipe_monitor can run well with patched syzkaller( patch_executor_pipe.patch). Without any different compared to original syzkaller's using. But you need write your ebpf to collect state.
This is a example run patched execproc( patch_for_syz_executor.patch) with shm_monitor.
```  
# bin/linux_amd64/syz-execprog -executor=./bin/linux_amd64/syz-executor -cover=1 -threaded=0 -procs=1 --debug 06def8c2645148cb881aff26e222a886db9e1d72 
2019/01/09 04:34:14 parsed 1 programs
2019/01/09 04:34:14 executed programs: 0
spawned loop pid 7530
...
shm_monitor start ...
...
spawned worker pid 7799
...
2019/01/09 04:34:23 Monitoring the process 7799
2019/01/09 04:34:23 Waiting for signal
#0 [8476ms] -> socket$inet6_tcp(0xa, 0x1, 0x0)
#0 [8482ms] -> bind$inet6(0x3, 0x20000100, 0x1c)
#0 [8483ms] -> recvfrom$inet6(0x3, 0x20000280, 0x67, 0x20, 0x20000080, 0x1c)
#0 [8483ms] -> sendto$inet6(0x3, 0x200001c0, 0x0, 0x20000000, 0x200000c0, 0x1c)
#0 [8485ms] -> setsockopt$inet6_tcp_TCP_CONGESTION(0x3, 0x6, 0xd, 0x20000140, 0x3)
#0 [8486ms] -> sendto$inet6(0x3, 0x20000340, 0x982b5b491b7ad2c5, 0x41, 0x20000040, 0x16)
#0 [8492ms] -> recvfrom$inet6(0x3, 0x20000180, 0xfc, 0x100, 0x20000000, 0x1c)
Before send SIGUSR1 signal
...
2019/01/09 04:34:23 Socket state handle start ...
2019/01/09 04:34:23 7 signals in statelist
2019/01/09 04:34:23 8 rawSignals got!
2019/01/09 04:34:23 :8 covered
2019/01/09 04:34:23 :0 covered
2019/01/09 04:34:23 :8 covered
2019/01/09 04:34:23 Write signal:65808, byteX
...
...
2019/01/09 04:34:23 :8 covered
2019/01/09 04:34:23 :0 covered
2019/01/09 04:34:23 :8 covered
2019/01/09 04:34:23 Write signal:65808, byteX
2019/01/09 04:34:23 :0 covered
2019/01/09 04:34:23 SOCK_STREAM:2 covered
2019/01/09 04:34:23 SS_CONNECTED:3 covered
2019/01/09 04:34:23 Write signal:66320, byte: c
2019/01/09 04:34:23 :0 covered
2019/01/09 04:34:23 SOCK_STREAM:2 covered
2019/01/09 04:34:23 SS_CONNECTED:3 covered
2019/01/09 04:34:23 Write signal:66320, byte: c
2019/01/09 04:34:23 :0 covered
2019/01/09 04:34:23 SOCK_STREAM:2 covered
2019/01/09 04:34:23 SS_CONNECTED:3 covered
2019/01/09 04:34:23 Write signal:66320, byte: c
2019/01/09 04:34:23 Write signal:ffffffff, byte:����
...
2019/01/09 04:34:24 result: failed=false hanged=false err=<nil>

2019/01/09 04:34:24 executed programs: 1
...
```  
