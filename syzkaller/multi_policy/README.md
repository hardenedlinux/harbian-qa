# Multiple policy fuzzer( syz-hub)

## Original syz-hub
Syz-hub is a great tool to connect all the syz-managers. After all syz-managers connect to syz-hub, Every syz-manager will exchange their whole corpus with each other. This is called "Sync" in syz-hub, the interval of "Sync" is one minute which you can see a time.Sleep() in syz-manager/hub.go:loop(). After "Sync", every manager will check if the received progs can hit more coverage. You can immediately see a great number of "triage queue" after "Sync". That means syz-managers with different configure can exchange progs with each other also.

## Policy of fuzzer
### Original syzkaller fuzzer
Actrually, there are some mechanisms of syzkaller:
1. The feedback( coverage) of progs determin if it can be sent to corpus
2. Corpus will affect the progs generating( by mutating, syscall-choisetable, affect the probability)
3. Generated progs determin which feedback may be received.  
Syzkaller run these iteratively, and the feedback probabily determin where to fuzz. Original syzkaller use coverage of the whole kernel as feedback. So, syzkaller is a coverage-guided fuzzer of kernel. And the "coverage-guided" is what we called the policy of syzkaller.

### Faster or deeper fuzzer.
We have some survey of different-policy syzkaller. It shows that there is several point can be optimize if you want a directed fuzzer. For example, only want to fuzz sub-system of kernel. The customizing of these can be list:
1. Limit the coverage to a smaller scope. Include building kernel with partial-coverage( KCOV_INSTRUMENT_ALL=n), filtering coverage( by address).
2. Add other feedback. For example, we use ebpf collect the state of socket as feedbeck.
3. Directed fail-injection help cover the corners shouldn't be covered.  
Both 1 and 2 change the feedback of syzkaller. 1 limit syzkaller to fuzz a smaller scope of kernel. 2 directly introduce other feedback into syzkaller.
Our test shows that using these features properly can help syzkaller more directed, deeper and faster.

## Customize syz-hub
### Connect different policy syz-manager
It could be useful if we connect syz-managers with different policy. Different syz-managers focus on different sub-system or different scope.
For example, one of syz-managers fuzz the whole kernel, others fuzz several sub-system. It take less time to fuzz deeper corner( sub-system). And corpus can be sync to all manager( the whole kernel one). In other word, deeper or faster fuzzer can be sync to the widely and shallow fuzzer.

### Customize feature of syz-hub
Original syz-hub do "Sync" one time a minute. We know the corpus will affect the progs generating, frequently sync will guide all syz-managers to fuzz the same scope of kerenl. Spliting the upload( send out progs) and download( receive progs form) of corpus sync shows a better performence. The upload always done while "Sync" was called, and download sync only done if there is no coverage after a long time. So what we need to do is:
syz-hub: splite the upload and download of corpus sync.
syz-manager: add option for configuring the time of sync. Only download the corpus if there is no any input after a long time.

## Patch and usage
### Patch
These patch base on syz-0d1034:
1. Add ebpf feedback
2. Filtering coverage by address
3. Configurable ebpfsig and coverage filtering
4. Split the upload and download of sync

### Usage
Patch 1, 2 refer to [this](../kstat_demo/README.md).
After patch the 3, you need specify some new option for syz-manager:
* ebpfsig:   true/false
* covfilter: true/false
After patch the 4, you need specify a new option for syz-manager:
* hub_synctime: a integer
This option specify how many minute without any input, a syz-manager can receive progs.
Then you can run syzkaller as usual.

## A test for tcp/ipv6
### Original syz-hub
syz-manager1: Only enable syscalls for tcp/ipv6
syz-manager2: Only enable syscalls for tcp/ipv6
sync time: 1 time a minute
run time: 2h30min
coverage( chose the maximum):

| coverage | 1 | 2 | 3 | 4 | 5 | 6 | average |  
|----------| - | - | - | - | - | - | ------- |  
| total |10514 |9869 |10583 |10347 |10611 |8916 |10140 |  
| tcp.c |462 |460 |346 |471 |491 |359 |432 |

(Most of handle function of tcp/ipv6 is in tcp.c)

### Multi-policy syz-hub
syz-manager1: Only enable syscalls for tcp/ipv6
syz-manager2: Only enable syscalls for tcp/ipv6, add ebpf to collect socker state as feedback, limit coverage to tcp/ipv6 kernel function.
sync time: 3/4 minute without any input
run time: 2h30min
coverage( chose the maximum):

| coverage | 1 | 2 | 3 | 4 | 5 | 6 | average |  
|----------| - | - | - | - | - | - | ------- |  
| total |9962 |10060 |9356 |10832 |8952 |10122 |9879 |  
| tcp.c |487 |525 |507 |506 |515 |493 |506 |  

### Result
* One of the syz-manager focus on tcp/ipv6 fuzz. It have a 2% decrease of total coverage. This is beacuse we use one of the two	syz-manager to fuzz a smaller scope.
* Introduction of ebpf feedback have a 17% increase of tcp.c coverage. That means our directed fuzzer do well in fuzzing the deeper corner.