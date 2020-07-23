# Syzkaller coverage filter and weighted PCs

## Content
1. Usage.
2. Implement detail.
3. Practice.

To implement coverage filter in syzkaller. we have to follow the next steps:

1. Get the LLVM ir code and assembly code of target.
2. Get the addresses map of target functions by analyzing ir code, assembly code and kernel ELF.
3. Support cover filter and weighted PCs in syzkaller.

After step 1 and 2, you will get a addresses map contains addresses of any kernel functions you need. Also, you can attach weight to every PC base on LLVM ir analysis, eg. weighted PCs base on CFG information.

## Usage

### Get LLVM ir code and assembly code

Lots of static analysis tools can be used to parse ir code. But ir code know nothing about addresses of the final executable file while the assembly code holds both address offset and basic block information. By analyzing them, we can associate ir information with addresses.
To get ir code and assembly code, you need to pick out the source file where your target functions located at. For example, if your target function is in /net/ipv4/tcp.c, you should run this command in your kernel build tree:

```  
make CC=clang net/ipv4/tcp.o -n | grep tcp.c
```  

to get the command of compiling tcp.c, command may look like:

```  
clang ...... -c -o net/ipv4/tcp.o net/ipv4/tcp.c
```  

To get the LLVM ir code of tcp.c, run:

```  
clang ...... -S -o net/ipv4/tcp.ll net/ipv4/tcp.c -emit-llvm
```  

To get the assembly code of tcp.c, run:

```  
clang ...... -S -o net/ipv4/tcp.s net/ipv4/tcp.c
```  

Repeat the mentioned steps to get all ir codes and assembly codes of your target functions. Move them to a IR_DIR and ASM_DIR. Then build your kernel and get a VMLINUX file.

### Get PCs table

We use a [kcov_map](../static_analysis_tools/IRParser/kcov_map.cpp) tool to get addresses of the kernel functions we are interested in.
Run the following command to build kcov_map:

```  
clang++-10 kcov_map.cpp -o kcov_map -O0  -g `llvm-config-10 --cxxflags --libs --ldflags --system-libs`
```  

```  
./kcov_map IR_DIR ASM_DIR VMLINUX_FILE FUNCTION_LIST LOG_DIR
```  

FUNCTION_LIST has functions name that we need to get their addresses.
IR_DIR: directory all the LLVM ir code we need.
ASM_DIR: directory all the assembly code we need.
VMLINUX_FILE: kernel ELF
LOG_DIR: after run the command, kcov_map will creat a "*.json" and a "*.addr.map" for every function.
Then run:

```  
cat LOG_DIR/*.addr.map > funcaddr.map
```  

Copy funcaddr.map to syzkaller work directory.
This is only one of ways when we try to build functions addresses map with weight. You can explore how to build your functions addresses map for you need.

#### Extend functions list

In our practice, when we choose some member functions as entry, some functions may be a wrapper function but not the truly implement function. We use [extend_func](../static_analysis_tools/IRParser/extend_func.cpp) extend the function list.

```  
clang++-10 extend_func.cpp -o extend_func -O0  -g `llvm-config-10 --cxxflags --libs --ldflags --system-libs`
```  

```  
./extend_func FUNCTION_LIST IR_DIR
```  

You will get a FUNCTION_LIST.new which you can pass to kcov_map.

### Support cover filter in syzkaller

#### Patch syzkaller

Clone syzkaller, and run:

```  
git checkout a2cdad9
git apply harbian-qa/syzkaller/cover_filter/*.patch
```  

Build syzkaller as usual.

#### Modify configure file

Add the following options in syz-manager configure file:

```  
"covfilter": true,
"coverpcs": PATH_TO_FUNCTION_ADDRESS_MAP,
```  

The "covfilter" enable coverage filter of executor. If you only want to use weighted PCs feature without filter, set it to false. If you want to use cover filter only, without weighted PCs, just create your map that every PC has weight 1.
Now you can run a syzkaller with cover filter.

## Implement detail of cover filter

### manager

#### Read weighted pcs from funcaddr.map

The configure specifies which funcaddr.map should be loaded and send to VM. Function readPCsWeight in syz-manager/manager.go will read the funcaddr.map and maintain a pcsWeight map in structure manager. This pcsWeight map can be used while calculating the weight of prog in web UI.

#### RPC interface for sending addresses map to fuzzer

Extend a getPCsWeight interface in RPCManagerView in syz-manager/rpc.go for waiting client call( fuzzer) for getting a pcsWeight map.

#### Display the pc and its weight in source code

Use the syzkaller web UI "cover", we extend an interface called bitmap. It will convert PCs table to source lines. The color of lines is black means the block of this line won't be drop while fuzzing. The number at the left is the weight of that line. Note that there may be multiple block maps to a source line. Their weight will add to this line.

### fuzzer

#### getPCsWeight from syz-manager

Add a getPCsWeight for fuzzer, so fuzzer can dynamically fetch PCs table from syz-manager. In other words, it's possible to dynamically distribute PCs table to different fuzzers. For example, light PCs weight while some block has been fully explored( [eg.](https://github.com/llvm/llvm-project/blob/master/compiler-rt/lib/fuzzer/FuzzerDataFlowTrace.cpp)).

#### Calculate the prog prio from its cover

We implement a function calCoverWeight in syz-fuzzer/proc.go to calculate the weight and attach to structure prog. You can implement your algorithm of calculating weight base on weighted pc in this function.

#### Choose prog to mutate base on prog prio

Syzkaller already has its prior choice base on signals length of the prog. We have to modify the addInputToCorpus function to use out prog weight.

### executor

#### Read pcs map

The executor/bitmap.h implement function for getting PCs table from the map.

##### Fast cover filtering.

Unlike manager and fuzzer, executor coverage filter run more frequently. Without a fast search, if the PCs table grow up, the affect of performance can be a disaster. So we use a fast but rough way, bitmap, to address this program. We assume that kernel text size is less than 0x3000000, and we maintain a map:
```  
#define COVERAGE_BITMAP_SIZE 0x300000 / sizeof(uint32)
static uint32 kTextBitMap[COVERAGE_BITMAP_SIZE];
```  
Because address align, the lowest 4-bit is dropped off. So, for quickly setting and accessing the bit which record if a pc should be filtered, we can search by:
```  
pc &= 0xffffffff;
pc -= KERNEL_TEXT_BASE;
uint64 pcc = pc >> 4;
uint64 index = pcc / 32;
uint64 shift = pcc % 32;

kTextBitMap[index] & (0x1 << shift)
```  
The affect of performance will not grow up no mater how many PCs should be filtered.

## Some PCs-weight-guide fuzzing practice

Cover filtering is quite certain that you can only set if the edge of that pc will be sent to fuzzer as a signal or not. But, weighted PCs can guide fuzzer to evolve prog flexibly. You can assign weight to PCs base on the result from LLVM ir static analysis.

### Cyclomatic complexity base on llvm CFG

In the theory of cyclomatic [complexity](https://en.wikipedia.org/wiki/Cyclomatic_complexity), a function can be treated as a one-entry and one-exit model, the complexity can be easily calculated. In realistic application, complexity indicates that program testing should pay more attention to those functions that are more complex.

### Basic block count base on llvm BlockFrequenceInfo

The LLVM class [BlockFrequencyInfo](https://llvm.org/doxygen/classllvm_1_1BlockFrequencyInfo.html) is a convenient way to get the frequency of a block will appear in all potential control-flow paths. It's reasonable that if a basic block appeared more frequently, mutate the prog that triggers this block has a higher probability to cover more other PCs edge.

### Basic block to basic block count base on llvm BranchProbabiltyInfo

The LLVM class [BranchProbabiltyInfo](https://llvm.org/doxygen/classllvm_1_1BranchProbabilityInfo.html) is another tool that can be used in fuzzing. The class has information about the probability of from a block to another block. If you want the fuzzer to evolve a testcase can cover a specific basic block, it's a good choice that uses BranchProbabilityInfo weighted the PCs.

### Weighted function call stack

The mentioned tools focus on if the functions should be fuzzed is already picked out, how to assign priorities to PCs base on CFG information. Sometimes, you may want to fuzz an approximate range, for example, a serial of functions from a call stack. LLVM class [CallGraph](https://llvm.org/doxygen/classllvm_1_1CallGraph.html) can help build the associate of functions call. You can assign low weight to those functions if they are deep and not so complex.
