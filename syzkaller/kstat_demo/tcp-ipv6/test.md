# A sample of tcp-ipv6 fuzz

## Feature of customize syzkaller
1. Socket state( historical state, high-32-bit) and kernel function arguments( low-32-bit, about code branch) feedback  
2. Coverage filter  
I implement runtime state feedback by using ebpf. ebpf collect a 64-bit state send to executor, executor separate to two 32-bit state. Then calculate low-32-bit ^ hash(high-32-bit). The result of it will look like original syzkaller coverage signal. Send these signals to fuzzer. Coverage filter implement in executor. You can get kernel function address region use the [fun2addr](https://github.com/hardenedlinux/harbian-qa/blob/master/syz_patch/fun2addr.go).

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

* [Data](data.zip) get from syzkaller web.  

## Concludsion
1. Greater coverage then original syzkaller especially in function tcp_sendmsg.
2. The tcp_setsockopt coverage of customize syzkaller is only a little more then original syzkaller's because of powerful syscalls script. Most of uncovered code is similar in original syzkaller. Is it because of powerful syscalls script and mutation is not enough?
3. SIOCINQ branch in tcp_ioctl can't be reached by both original and customize syzkaller. That means function arguments feedback is not so effective in this case. I think the reason is the value of SIOCINQ　is too complex. Here is a [paper](https://lifeasageek.github.io/class/cs52700-fall16/pages/prog-assignment-1.html) about branch exploration. But it is too complex to implement it by ebpf.
