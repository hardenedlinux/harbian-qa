## Brief

This document will introduce some features or design of customizing fuzzer. Firstly, most of fuzzer implemented its own Genetic Algorithm( GA). Some features can be classified to one of GA component. For example, the optimizing of generate, mutate and crossover. Other features, such as special feedback or satifying deep nested condition, is strongly depend on what project you fuzz, although these problem is very common in real-world project.

Because this document is a by-product of customizing Linux kernel fuzzer(base on Syzkaller), Some problem appeared kernel fuzzing only. At the end this document, i will attach the paper the document involved, with a short introduction.  


## GA of fuzzer

In most fuzzers, GA is the engine of evolving testcase. For different purpose, the design of GA's components can be quite different.


### Generate & Mutate in evaluating programming

In evolutionary programming, if mutation and generating only base on random inputs, that fuzzer will perform badly. Useful information help reducing the search space of evolving the testcase you want. Generally, these following informations can benefit mutating or generating:  
1. symbolic execution: static analyse target, deriver which inputs is useful.( KLEE)  
2. Dynamic taint analysis( DTA): dynamically trace inputs used by conditions.( VUzzer)  
3. Dynamic taint analysis: dynamically trace which inputs can satisfy which conditions efficiently.( GREYONE)  
4. Manually write manner: hard-code some special inputs or enum inputs.( Syzkaller)  
5. Extract inputs from real-world program.( Moonshine)  


### Crossover

In real-world, if you want to fuzz the entire project, generated testcases always should be length-indeterminate. The classical single-point randomly crossover couldn't work well. Block stacking evolutionary programming would be more efficient. Specially, some testcase is state-base( for example: socket programming), generate and crossover base on state-base blocks help evolving complex context testcase. In our practice, in state-base programming, state-base block-stacking evolution perform better than randomly crossover. Here are some idea of block-stacking crossover:
1. Static analysis state dependence of real world testcase.( Moonshine)  
2. Resource centric: treat generated testcase which use( create&operation) the same resource as a complex resource. Use them in the subsequent syscalls.( Syzkaller)  
3. State-base Resource centric: classify testcase by states they trigger.( base on syzkaller resource centric)  
4. Build N-Gram model for syscalls: select those testcases trigger a type of crash, build N-Gram model to analyse the pattern of crash testcases.( FastSyzkaller)  


### Fitness

Fitness is motivation of evolution in GA. A appropriate fitness reward helps efficiently select potential inputs or testcases. Moreover, gradient fitness will help evolving also. Fitness always base on what feedback fuzzer collected.


#### coverage

1. CFG position weight fitness.( VUzzer)  
2. Sum of basic-block weight fitness.( Syzkaller)  
3. Class code: lower error handle fitness.(VUzzer)  
4. Statistical calculation of testcase.( Syzkaller)  
* refer to the following survey  


#### state

1. Symbolic execution: static analyse call-stack input, weight them base on its CFG.  
2. Targeted symbolic execution: matching testcases' stack-trace to BUG's stack-trace report.( Wildfire)  
3. Distance of taint variable to condition expected value.( GREYONE)  

#### Exploit vs Explore

A fuzzer for the entire project is usually a Multi-armed bandit problem. You may need to trade off explore and exploit.
Trade off them in a fuzzer is difficult, so we try to combinate several fuzzer with different policy( base on syz-hub). Refer to our [multi-policy fuzzer](syzkaller/multi_policy/README.md).


## Other design

Moreover, there are lots of design of fuzzer is base on what project you fuzz, it can't be classified into any step of GA, although it strongly associates with things mentioned above.


### Shortage of only coverage-guide fuzzer  

Coverage-guide is the most widely used feedback of fuzzer. But, some reserachers found it's not enough for some case. In userspace fuzzing:
1. Collecting coverage and memory accessing information as fuzzer feedback.( MemFuzz)  
2. Collecting targeted functions' argument as feedback.( WildFire)  
In kernel fuzzing, state-base fuzz could be more useful, for example:
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
2. Subsystem syscall set: syzkaller support enable/disable a subset of syscalls to fuzz.  
3. Partly kernel fuzz: KCOV support only instement a part of source file in kernel.  
4. Multi-policy fuzzer: base on syz-hub, customized fuzzer with different feedback share testcases with each other if the testcase is interested by other fuzzers. Refer to this [documentation](syzkaller/multi_policy/README.md).  


### Satisfy the condition constraint

Of course, most ideas of offering information to mutating and generating mentioned above is for staifying condition constraint. There are also some useful way for helping fuzzer satisfy the condition constraint.  


#### Condition constraint satisfied by single input
If we treat arguments of a function as a byte-base input. Some conditions constraint can be satisfied by mutating input of the function. For these conditions, the following ways can be used to improve the performence of fuzzer.
1. Symbolic execution: static analysis of constraint, can't solve constraint indrectly from input, overhead.( KLEE)  
2. Dynamic taint analysis( DTA): dynamically trace inputs used by conditions.( VUzzer)  
3. Dynamic taint analysis: dynamically trace which inputs can satisfy which conditions efficiently.( GREYONE)  
4. Weakening Strong Constraints: use QEMU Ting Code Generator to weaken strong constraints.( Qemu TCG)  
5. comparison operand tracker: syzkaller use comparison tracker, __sanitizer_cov_trace_cmp for kernel.( KCOV_COMPARISON)  
6. Syzkaller: manually write syscall description.  
7. Matryoshka shows how they try to help AFL evolving input statify nested condition constraint.( Matryoshka)  
Also, i attach a comparison of these differences of these ways.

| method | dependence | granularity | indirectly use | case |  
|--------|------------|-------------|---------------------------|------|  
| cmp instrument to track data-flow( DTA) | path-dependent | instruction-level | insensitive | VUzzer |  
| cmp instrumnet to check satifing | path-denpendent | instruction-level | sensitive | GREYONE |  
| memory monitor | memory monitor | function-level | sensitive | Matryoshka |  
| symbolic execution | path-independent | function-level | insensitive | KLEE/CBMC/ClangChecker |  
| KCOV_COMPARISON | path-dependent | instruction-level | sensitive | Syzkaller |  
| Qemu TCG | path-dependent | instruction-level | sensitive | QemuTCG + AFL |  

We can see comparison instrument can be use in DTA to solve nested condtion. But instrument depend on if condition is reachable. And taint data monitor like VUzzer hard to trace complex indirectly taint( eg. memory copy).


#### Note that in Linux kernel fuzzer:

Syzkaller has powerful syscall descriptions, search space of a single syscall input was greatly reduce. The truly diffculty is to reach branches are depend on syscalls combination and arguments combination.
1. Syzkaller resource: recently syzkaller introduce a feature: resource centric. Syzkaller treat testcases as resource if they create or operate the same kind data structure( resource also). And use these resource to generate or mutate new testcase.  
2. MoonShine: static analysis real world testcase to get the dependence of syscalls.  
3. State-base resource: in our customized syzkaller, only testcase trigger a special state feedback can be resource. Further more, maintain a relationship between syscalls sequence and kernel state may help more.  
Also refer to mentioned above crossover.  

Symbolic execution: if static analysis chose syscalls as entry, it will be effort and inefficient. Otherwise, if the entry is some kernel function in callstack may help more. Both [this paper](https://arxiv.org/abs/1903.02981) and [our fuzzer](syzkaller/kstat_demo/README.md) chose the second way.  Get function-level input by using kernel function hook. We also have a [documentation](static_analysis_tools/README.md) of comparing some symbolic execution tools.


## Paper

[Weakening Strong Constraints for AFL](https://lifeasageek.github.io/class/cs52700-fall16/pages/prog-assignment-1.html):   
Strong constriant: a condition constraint need a bunch of memory to satisfy it. In this case, randomly mutating input will take a lot of time to satisfy it.  
Weakening strong constraint: try to slice the strong constraint to several weak constraints, replace that branch condition with several branch conditions. Each branch with weak branch can be easily satisfied. So the satisfying input can be gradually evoluted.  
The author use Qemu Tiny Code Generator( TCG), a instruction-by-instruction level instrumnetation, to weaken such strong constraints.

[Compositional Fuzzing Aided by Targeted Symbolic Execution](https://arxiv.org/pdf/1903.02981.pdf):  
Targeted symbolic execution: symbolic execution only analyse inputs for reaching targets of interest.  
Isolated function: functions that are parameterized( targeted functions).  
1. Repeatly generating testcases and populate testcases base on isolate functions' argements.
2. Run this testcases in another instrumented version of project, check if crash will happen.
3. If crash happened, run exploit testcases, collect the stack-trace information. Then try to generate testcases to macth it. Check if the target is reachable, if reachable, mutate inputs except those inputs satifying constrains of the path.  

[VUzzer: Application-aware Evolutionary Fuzzing]():  
Data-flow: dynamic taint analysis( DTA), implemented by instrument cmp instruction to trace which bits of input have an impact to the condition. The structure of input will be evoluted.
Control-flow: assign weight to basic block base on its depth; Assign negative weight to error-handling code.  
Static analysis: get immediate value of comparison.  

[MoonShine: Optimizing OS Fuzzer Seed Selection with Trace Distillation](http://www.cs.columbia.edu/~suman/docs/moonshine.pdf):  
Use an extended Strace to trace real-world testcases. Extract inputs and dependences of syscalls from Strace output( seed distillation). The dependences are similar to syzkaller resource( after resource centric introducted).  

[GREYONE: Data Flow Sensitive Fuzzing](https://www.usenix.org/system/files/sec20spring_gan_prepub.pdf):  
Fuzzing-driven Taint Inference: it's also DTA. But, unlike VUzzer, GREYONE track which input can satisfy condition constriants. So condition variable indirectly initialized from inputs can be found also.  
Taint-Guided Mutation: prioritize input bytes that affect more untouched branches to mutate.  
Conformance-Guided Evolution: the distance of tainted variables to the value expected by condition.  

[Matryoshka: Fuzzing Deeply Nested Branches](https://arxiv.org/pdf/1905.12228.pdf):  
1. Determinate all conditions constraint that target dependence on. Use taint analysis to determinate which conditions use same input.  
2. Randomly mutate inputs to satisfy these condition constraints. If all conditions use the same input( at less one input is the same one) are satisfied, these inputs are called dependent inputs.  
3. If the target is reached, that means all constraints can be satisfied by dependent inputs. if not, that means other inputs should be mutated to satisfy those conditions constraints that use indenpendent inputs.  

[FastSyzkaller: Improving Fuzz Efficiency for Linux Kernel Fuzzing](https://iopscience.iop.org/article/10.1088/1742-6596/1176/2/022013/pdf):  
FastSyzkaller classify crash type of syzkaller testcases, then use N-Gram model to extract N-Gram sequential syscall patterns from these testcases that may be potentially vulnerable. Generating new testcases from syscall patterns and pack them into the corpus. 

[MEMFUZZ: Using Memory Accesses to Guide Fuzzing]():  
1. Enhance AFL LLVM instrumentation pass: instrument load and store instruction to collect memory accessing information.  
2. Instrumentation site filtering: drop some information of memory accessing, for example, global variables or stack variables accessing.  
3. Extend AFL runtime library for tracking memory accessing. Bloom-filter for deduplicating.  