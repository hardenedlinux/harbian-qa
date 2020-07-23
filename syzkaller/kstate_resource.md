# Kernel state based fuzzer: a LLVM approach

## Content

1. Usage.
2. Implement detail.
3. Practice

To implement collect kernel states as syzkaller resource, we have to follow the next steps:

1. Build kernel with GEPOperator tracker instrument.
2. Support collecting kernel state in syzkaller.
3. Weighted kernel states for fuzzer.

## Usage

### Kernel instrument

First, we need to implement a [LLVM pass](../static_analysis_tools/kern_instrument/AssignTrackerPass)  to do instrument. While we already knew, lots of states of kernel are located in some field of structure. Tracking the store operation of a variable of GEPointer can detect states which may help to fuzzer. Then, refer to [this document](https://llvm.org/docs/WritingAnLLVMPass.html) to build you compiler with field assignment tracker. While building kernel, you have to add line such like:
```  
CFLAGS_*.o = -Xclang -load -Xclang PATH_TO_YOUR_PASS.so -fno-discard-value-names
```  
to Makefile for the object file you need to instrument it. The kernel state id is the hash of structure name and field name.

### Implement the instrument function in kernel

Refer to our [implement](../static_analysis_tools/kern_instrument/kern_patch) of instrument to collect kernel state. Then, build your kernel as usual.

### Patch syzkaller

Clone syzkaller, run:
```  
git checkout a2cdad9
git apply harbian-qa/syzkaller/cover_filter/*.patch
```   

build syzakller as usual. Add the following line to configure file:

```  
"kstatemap": "PATH_TO_KERNEL_STATE.map"
```  

You can use our tool [kstate_map](../static_analysis_tools/IRParser/kstate_map.cpp) get the kernel state map. run:

```  
clang++-10 kstate_map.cpp -o kstate_map -O0  -g -fsanitize=address `llvm-config-10 --cxxflags --libs --ldflags --system-libs`
./kstate_map LLVM_IR_DIR ASM_DIR VMLINUX FUNCTION_LIST LOG_DIR
```  

FUNCTION_LIST has the functions name we need to get their addresses.
IR_DIR: directory all the LLVM ir code we need.
LOG_DIR: after run the command, kstate_map will creat a "*.json" and a "*.state.map" for every function.
Write the output to PATH_TO_KERNEL_STATE.map. And run patched syzkaller as usual. This map assigns weight base on the frequency of state using. 

## Kernel state base fuzzer
Now, you can run syzkaller as usual, and you can find there is a list of kernel states if you access a "\input" interface. You can also get states weight of every prog in "/corpus" interface.

## Implement detail of kernel state resource

### Kernel instrument

We reuse the KCOV interface instead of using a separate mode. So, we encode the state id with 0xfefe at the highest 16-bit. While syzkaller gets a kcov pc started with 0xfefe, it realizes this pc is a kstate id and the value and address of the state will occupy the followed 2*64-bit. No matter how many bit the variable used, we formalize to 64-bit. Noted if you want to collect other information, you have to implement a corresponding syzkaller for it.

### Syzkaller support

#### executor

syz-executor have to pick out kernel states and send them out after all signal was sent. These handling can be found in our patch for executor.cc function write_coverage_signl. While executor read a pc started with 0xfefe, that means it receives a kernel state. And we use a chunk of shared memory for this state after coverage signal shared memory. syz-fuzzer will handle them later.

#### syz-fuzzer

Correspondingly, parseOutput in pkg/ipc.go is called by fuzzer and we add a readKernState for parse the executor output. And these kernel states information will be put into a structure called KernState in pkg/kstate/kstate.go. Every input from executor has an array for kernstate, and every prog has a state weight calculated from kernstates. Also, KernState support searching the map by its ID or ID^Value which called it hash.

syz-fuzzer/proc.go: calStateWeight will calculate the weight of a prog. Minus count for eliminating the influence of the length of kstate. prog/rand.go: chooseReaProgramIdx function implement a prior choice of prog base on its states weight

## Kernel state guide fuzzing practice

We have explored two ways in assigning weight to resources.

#### Get frequency of using kernel state

This tool is what we mentioned above kstate_map. We use LLVM api static analyze the using of states in target functions. Without any awareness of the value of a state, it just encourages fuzzer to preferentially choose and extract those progs that frequently rewrite important states. In other words, the prog has  complex states.

#### Specify kernel state value weight

We use a [clang checker](../static_analysis_tools/ConditionChecker/) to get symbolic information of condition constraint:

```  
clang -Xclang -analyze -Xclang -analyzer-checker=debug.ConditionChecker  ...... -c -o *.o *.c
```  

You can get some constraint value of variables. And patched syzkaller support a hash mode, if a ID^value can be found in the kstate map, use it as a unique state. So, you can specify a weight for a state with special value. Now, it can be specified in kstatemap manually only.
