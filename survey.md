## Brief

This document will introduce some features or design of customizing fuzzer. Firstly, most of fuzzer implemented its own Genetic Algorithm( GA). Some features can be classified to one of GA component. For example, the optimizing of generate, mutate and crossover. Other features, such as special feedback or satifying deep nested condition, is strongly depend on what project you fuzz, although these problem is very common in real-world project.

Because this document is a by-product of customizing Linux kernel fuzzer(base on Syzkaller), Some problem appeared kernel fuzzing only. At the end this document, i will attach the paper the document involved, with a short introduction.  


## GA of fuzzer

In most fuzzers, GA is the engine of evolving testcase. For different purpose, the design of GA's components can be quite different.


### Generate & Mutate in evaluating programming

In evolutionary programming, if mutation and generating only base on random inputs, that fuzzer will perform badly. Useful information help reducing the search space of evolving the testcase you want. Generally, these following informations can benefit mutating or generating:
1. symbolic execution: static analyse target, deriver which inputs is useful.( KLEE)
2. Dynamically taint analysis( DTA): Dynamically trace and derive which input satisfy which conditions efficiently.( Vuzzer)
3. Manually write manner: hard-code some special inputs or enum inputs.( Syzkaller)
4. Extract input from real-world program( Moonshine).


### Crossover

In real-world, if you want to fuzz the entire project, generated testcases always should be length-indeterminate. The classical single-point randomly crossover couldn't work well. Block stacking evolutionary programming would be more efficient. Specially, some testcase is state-base( for example: socket programming), generate and crossover base on state-base blocks help evolving complex context testcase. In our practice, in state-base programming, state-base block-stacking evolution perform better than randomly crossover. Here are some idea of block-stacking crossover:
1. Static analysis state dependence of real world testcase( Moonshine).
2. Resource centric: treat generated testcase which use( create&operation) the same resource as a complex resource. Use them in the subsequent syscalls.( Syzkaller)
3. State-base Resource centric: classify testcase by states they trigger( base on syzkaller resource centric).  


### Fitness

Fitness is motivation of evolution in GA. A appropriate fitness reward helps efficiently select potential inputs or testcases. Moreover, gradient fitness will help evolving also. Fitness always base on what feedback fuzzer collected.


#### coverage

1. CFG position weight fitness( Vuzzer)
2. Sum of basic-block weight fitness( Syzkaller)
3. Class code: lower error handle fitness. (Vuzzer)
4. Statistical calculation of testcase( Syzkaller).  
* refer to the following survey


#### state

1. Symbolic execution: static analyse call-stack input, weight them base on its CFG  


#### Exploit vs Explore

A fuzzer for the entire project is usually a Multi-armed bandit problem. You may need to trade off explore and exploit.
Trade off them in a fuzzer is difficult, so we try to combinate several fuzzer with different policy( base on syz-hub). Refer to our [multi-policy fuzzer](syzkaller/multi_policy/README.md).


## Other design

Moreover, there are lots of design of fuzzer is base on what project you fuzz, it can't be classified into any step of GA, although it strongly associates with things mentioned above.


### Shortage of only coverage-guild fuzzer( kernel fuzzer only)

In some case, state-base fuzz could be more useful, for example:
```  
Coverage:
Cov(socket+setsockopt$1)+Cov(socket+setsockopt$2)+Cov(socket+sendmsg(flag_not_expect)) = Cov(socket+setsockopt1+setsockopt2) = Cov(socket+setsockopt$1+setsocketopt$2+sendmsg(ANY)) != Cov(socket+setsockopt$1+setsocketopt$2+sendmsg(EXPECT_FLAG))
```  
Without any gradient, syzkaller won't collect any testcases to corpus until all inputs are randomly put into the right position.
```  
State:
State(socket+setsockopt$1)+State(socket+setsockopt$2) != State(socket+setsockopt1+setsockopt$2) != State(socket+setsockopt$1+setsocketopt$2+sendmsg(ANY)) != State(socket+setsockopt$1+setsocketopt$2+sendmsg(EXPECT_FLAG))
```  
If we try to collect state of testcases, it will lead fuzzer to generate more complex context testcase. In our practice, we static analyse which state is widely used in condition. Collect those testcases if they can trigger such state. Refer to syzkaller resource centric( block-stacking generate) mentioned before, these testcases will be resource( state-base block) which can be used to generate testcase. Refer to this [documentation](syzkaller/kstat_demo/README.md). But, that will maintain a lot of testcases in corpus, testcases should be weigted.


### Shortage of Full Kernel Fuzzer

FKF is multi-solution search space, need a good trade off between explore and exploit.
1. Syzkaller has no explicit fitness, but it maintain syscall-to-syscall markov chain for prios choise and mutation. The prios include static and dynamic prios. The dynamic prios come from calculating count of syscall pair in each testcase of corpus. Note that testcases may be conflict with each other.
2. Subsystem syscall set: syzkaller support enable/disable a subset of syscalls to fuzz
3. Partly kernel fuzz: KCOV support only instement a part of source file in kernel.
4. Multi-policy fuzzer: base on syz-hub, customized fuzzer with different feedback share testcases with each other if the testcase is interested by other fuzzers. Refer to this [documentation](syzkaller/multi_policy/README.md).  


### Satisfy the condition constraint

Of course, most ideas of offering information to mutating and generating mentioned above is for staifying condition constraint. There are also some useful way for helping fuzzer satisfy the condition constraint.  


#### Condition constraint satisfied by single input
If we treat arguments of a function as a byte-base input. Some conditions constraint can be satisfied by mutating input of the function. For these conditions, the following ways can be used to improve the performence of fuzzer.
1. symbolic execution: static analysis of constraint, can't solve constraint indrectly from input, overhead.( KLEE)
2. dynamic taint analysis: build the relationship between input/condition constraint using testcase.( Vuzzer)
3. Weakening Strong Constraints: use QEMU Ting Code Generator to weaken strong constraints.( Qemu TCG)
4. comparison operand tracker: syzkaller use comparison tracker, __sanitizer_cov_trace_cmp for kernel( KCOV_COMPARISON).
5. Syzkaller: manually write syscall description.
6. Matryoshka shows how they try to help AFL evolving input statify nested condition constraint.( Matryoshka)  
Also, i attach a comparison of these differences of these ways.

| method | dependence | granularity | case |  
|--------|------------|-------------|------|  
| DTA + instrument | path-dependent | instruction-level | Vuzzer |  
| DTA + memory monitor | memory monitor | function-level | Matryoshka |  
| symbolic execution | path-independent | function-level | KLEE/CBMC/ClangChecker |
| KCOV_COMPARISON | path-dependent | instruction-level | Syzkaller |  
| Qemu TCG | path-dependent | instruction-level | QemuTCG + AFL |  

We can see comparison instrument can be use in DTA to solve nested condtion. But instrument depend on if condition is reachable.


#### Note that in Linux kernel fuzzer:

Syzkaller has powerful syscall descriptions, search space of a single syscall input was greatly reduce. The truly diffculty is to reach branches are depend on syscalls combination and arguments combination.
1. Syzkaller resource: recently syzkaller introduce a feature: resource centric. Syzkaller treat testcases as resource if they create or operate the same kind data structure( resource also). And use these resource to generate or mutate new testcase.
2. MoonShine: static analysis real world testcase to get the dependence of syscalls.
3. State-base resource: in our customized syzkaller, only testcase trigger a special state feedback can be resource. Further more, maintain a relationship between syscalls sequence and kernel state may help more.  
Also refer to mentioned above crossover.

Symbolic execution: if static analysis chose syscalls as entry, it will be effort and inefficient. Otherwise, if the entry is some kernel function in callstack may help more. Both [this paper](https://arxiv.org/abs/1903.02981) and (our fuzzer)[syzkaller/kstat_demo/README.md] chose the second way.  Get function-level input by using kernel function hook. We also have a [documentation]() of comparing some symbolic execution tool.
