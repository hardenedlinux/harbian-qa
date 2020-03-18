# Clang checker for symbolic execution


## Introduction of Clang checker

Clang checker can be a great static analysis tool, you can do lots of amazing work by write your checker. For example, you can write a checker to do taint analysis, symbolic execution ...  
We write a checker to static analyse which data structure is relevant to satisfy conditions constraint( c language). Unlike IR parser, clang checker still remain the programing syntax information in compile time, it's readable if you reconstruct the source code from these information. Since we just want to extract these information of symbolic inputs, but not run a symbolic execution base on them, these information should be more readable. So, Clang checker is the best choice in our case.


### Clang checker guide

Clang checker have lots of great tutorial and document. You can easily build your clang with customized checker.  
* [Checker Developer Manual](https://clang-analyzer.llvm.org/checker_dev_manual.html)  
* [How to Write a Checker in 24 Hours](https://llvm.org/devmtg/2012-11/Zaks-Rose-Checker24Hours.pdf)  
* [Checker analyzer-guide](https://github.com/haoNoQ/clang-analyzer-guide/releases/download/v0.1/clang-analyzer-guide-v0.1.pdf)

Also, you can alse refer to "/clang/lib/StaticAnalyzer/Checkers/CheckerDocumentation.cpp" and the checker implement under "/clang/lib/StaticAnalyzer/Checkers/*".  


### Clang symbolic execution

At first, we only want to calculate which members of data structure are used in condition statement frequently and which members used by a function. Actually, in this case, AST parse checker is enough, so we implement these in ConditionChecker::ASTDecl() interface. AST-base parse is much faster than path-sensitive parse. Statistic result will be displayed in ConditionChecker::EndAnalysis().  
But, AST-base parse is hard to find out constraint of a condition. So, we also write a path-sensitive checker. Interface with parameter "CheckerContext &Ctx" is a path-sensitive checker interface. In path-sensitive parse, checker will walk thought all node( ExplodedNode) of ExplodedGraph. ExplodedGraph is a graph of paths of CFG and their ProgramState( clang option "-analyzer-checker=debug.ViewExplodedGraph" can dump the ExplodedNode). So, in our checker, while ConditionChecker::BranchCondition() is called, that means a branch condition is found in that path. We can extract the constriant( range or concrete value) from the ProgramState that attached to that node.


## Compare to other symbolic execution

| Tool | static/dynamic | symbolize | parse source |
|------|--------------- | --------- | ------------ |  
| Clang | static | original source | input of every func |  
| KLEE | static+dynamic | LLVM IR | input of entry func |  
| CBMC | static | original source | input of entry func |

Compare to KLEE, clang checker is totally a static analyzer. Clang won't execute any program. Clang ProgramState will maintain the state( constraint) of reaching a position of one path. While KLEE, CBMC only symbolize the input of entry. So, we can see, if a local variable initialized by the input of entry and pass it to other functions. These functions may use it in condition, and KLEE will not trace the variable in such case. But this condition is also indirectly from input of entry. Clang treat inputs of any functions as symbolic variable, so we can trace those mishandled condition.
* We have two tutorials for [KLEE](https://github.com/hardenedlinux/Debian-GNU-Linux-Profiles/blob/master/docs/harbian_qa/symexec/klee.md) and [CBMC](https://github.com/hardenedlinux/Debian-GNU-Linux-Profiles/blob/master/docs/harbian_qa/symexec/cbmc_kern.md).

## For kernel fuzzing
In our case, we use syzkaller for kernel fuzzing. While syzkaller only collect coverage as feedback. We try to trace more state if it is widely use in condition statement. Clang path-sensitive checker is what we actually need. After static analysis, we calculate which states( data) are widely used in conditions. These states will be collected as state-base block( syzkaller resource) at runtime. And we also collect inputs of some important functions to help to fuzz important paths more efficiently.
An example of part output:
```
clang -Xclang -analyze -Xclang -analyzer-checker=debug.ConditionChecker ... -c /root/linux/net/ipv4/tcp.c
...
# AST-base parse
[Function] ID-ID-0x271f29 tcp_ioctl
[ParmVar] ID-ID-0x271ef4 struct sock *sk
[ParmVar] ID-ID-0x271f04 intcmd
[ParmVar] ID-ID-0x271f14 unsigned longarg
[LocalVar] ID-ID-0x271f45 struct tcp_sock *
[Condition] RawSrcLine: if (sk->sk_state == TCP_LISTEN)
[BinaryOperator] unknown == 0x1ffb6f
[MemExpr] ID-ID-0x2024cc struct sock_common->volatile unsigned char skc_state
[MemExpr] ID-ID-0x202842 struct sock *->struct sock_common __sk_common
[DeclRefExpr] ID-ID-0x1ffb6f int TCP_LISTEN
...
# Path-sensitive parse
...
tcp_poll [ElementCast] (struct tcp_sock)struct sock * {}
tcp_poll [MemSymbol] struct socket *->struct sock * sk {}
tcp_poll [MemSymbol] struct tcp_sock *->u16 urg_data {}
tcp_poll [SymIntExpr] 0x100 {}
...
tcp_poll [MemSymbol] struct sock *->int sk_err {}
 [MemSymbol] struct sock *->int sk_err {0x-80000000, 0x-1, 0x1, 0x7FFFFFFF, }
...

# AST-base parse count
...
struct sock *->struct sock_common __sk_common:39
...
struct sock_common->volatile unsigned char skc_state:39
...
struct tcp_sock *->u8 repair:14
...

# Path-senstive parse count
...
struct sock *->struct sock_common __sk_common:119
...
struct sock_common *->volatile unsigned char skc_state:61
...
struct tcp_sock *->u8 repair:78
```  