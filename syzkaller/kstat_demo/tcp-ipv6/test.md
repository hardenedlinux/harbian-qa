# A sample of tcp-ipv6 fuzz

## Feature of customize syzkaller
1. Socket state( historical state) feedback.
2. Coverage filter

I implement runtime state( sk->sk_state, tp->repair ...) feedback by using ebpf. ebpf collect a 64-bit state send to executor, executor separate to two 32-bit state. Then calculate low-32-bit ^ hash(high-32-bit). The result of it will look like original syzkaller coverage signal. Send these signals to fuzzer. Coverage filter implement in executor. You can get kernel function address region use the [fun2addr](https://github.com/hardenedlinux/harbian-qa/blob/master/syz_patch/fun2addr.go).

## Usage  
Command for build ebpf monitor:
```  
cd harbian-qa/syzkaller/kstat_demo
mv kstat_demo/tcp-ipv6/ebpftext.go kstat_demo/ebpf/ebpftext.go
go build pipe_monitor
```  
Command for patching syzkaller:
```  
cd /path/to/your/syzkaller/source
git checkout 12365b99
git apply /path/to/harbian-qa/syzkaller/kstat_demo/tcp-ipv6.patch
```
After patching syzkaller, to filter coverage, address in executor/cov_filter.h should fit to you kernel. Use fun2addr as:
```  
bin/syz-func2addr -v PATH_to_YOUR_VMLINUX -f FUNC_NAME -s
```
Get address of all functions you want to test. And write them to cov_filter.h. Then run make as original syzkaller to build it.

## Testcase
I run six times both original and customize syzkaller. Two hours per time. The enable syscalls is extract from socket_inet6.txt and socket_inet_tcp.txt using this [tool](https://github.com/hardenedlinux/harbian-qa/blob/master/syz_patch/extract_syscall_names_from_prog.py). There is also some syscalls for ipv4_tcp have to be removed by hand.
This is some coverage( customize vs. original in the table) of functions which monitored by my ebpf:  

|kern_func | 1 | 2 | 3 | 4 | 5 | 6 |  
| -------- | - | - | - | - | - | - |  
| tcp_v6_connect | 44/45 | 44/44 | 45/45 | 45/46 | 46/44 | 45/45 |  
| tcp_sendmsg_locked | 73/71 | 19/18 | 77/48 | 73/20 | 73/17 | 72/20 |  
| tcp_recvmsg | 54/33 | 35/33 | 35/33 | 54/36 | 36/33 | 48/36 |  
| tcp_setsockopt | 83/80 | 80/81 | 84/79 | 84/82 | 82/81 | 84/83 |  
| tcp_getsockopt | 61/59 | 57/59 | 56/57 | 61/60 | 58/58 | 60/58 |  
| inet_accept | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 | 2/2 |  
| tcp_ioctl | 9/9 | 9/9 | 9/9 | 9/9 | 9/9 | 9/9 |

Other example, I run six times both original and customize syzkaller. Two hours per time. These lines can be easily covered:  
#### tp->repair/tp->repair_queue
https://elixir.bootlin.com/linux/v4.17/source/net/ipv4/tcp.c#L1233 (5:0)
https://elixir.bootlin.com/linux/v4.17/source/net/ipv4/tcp.c#L2687 (6:0)
https://elixir.bootlin.com/linux/v4.17/source/net/ipv4/tcp.c#L2689 (5:0)
https://elixir.bootlin.com/linux/v4.17/source/net/ipv4/tcp.c#L3106 (5:2)

#### sk->sk_state
https://elixir.bootlin.com/linux/v4.17/source/net/ipv4/tcp.c#L1259 (6:0)
https://elixir.bootlin.com/linux/v4.17/source/net/ipv4/tcp.c#L2137 (6:2)

## Concludsion
1. Greater coverage then original syzkaller especially in function tcp_sendmsg. It is because historical state and nested condition. We can see in the second example.

2. The tcp_setsockopt coverage of customize syzkaller is only a little more then original syzkaller's because of powerful syscalls script. Most of uncovered code is similar in original syzkaller. Is it because of powerful syscalls script and mutation is not enough?

## RawData
* [Data](data.zip) get from syzkaller web. It's not macth to the table.
* The test will keep the same enable syscalls, run time, vm evironment.
* Collect different data as feedback( ebpftext) get different result.