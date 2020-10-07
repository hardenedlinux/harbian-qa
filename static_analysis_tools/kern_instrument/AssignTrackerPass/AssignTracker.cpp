#include <llvm/IR/LegacyPassManager.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/Operator.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/Bitcode/BitcodeWriter.h>

#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Function.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"

typedef unsigned long long uint64;
typedef unsigned int uint32;
typedef unsigned short uint16;

using namespace llvm;
using namespace legacy;

static const char *const SanCovTraceSrt1Name = "__sanitizer_cov_trace_srt1";
static const char *const SanCovTraceSrt2Name = "__sanitizer_cov_trace_srt2";
static const char *const SanCovTraceSrt4Name = "__sanitizer_cov_trace_srt4";
static const char *const SanCovTraceSrt8Name = "__sanitizer_cov_trace_srt8";

namespace {
    struct AssignTracker : public ModulePass {
        static char ID; // Pass identification, replacement for typeid
        FunctionCallee SanCovTraceSrt1;
        FunctionCallee SanCovTraceSrt2;
        FunctionCallee SanCovTraceSrt4;
        FunctionCallee SanCovTraceSrt8;
        Type *VoidTy;
        Type *Int8Ty;
        Type *Int16Ty;
        Type *Int32Ty;
        Type *Int64Ty;
        std::map<std::string, uint64> StructIDMap;
        StringRef SourceFileName;

        LLVMContext *C;
        AssignTracker() : ModulePass(ID) {}

        bool runOnModule(Module &M) override {
            C = &M.getContext();
            IRBuilder<> IRB(*C);

            VoidTy = IRB.getVoidTy();
            Int8Ty = IRB.getInt8Ty();
            Int16Ty = IRB.getInt16Ty();
            Int32Ty = IRB.getInt32Ty();
            Int64Ty = IRB.getInt64Ty();

            SanCovTraceSrt1 = M.getOrInsertFunction(SanCovTraceSrt1Name, VoidTy, Int64Ty, Int8Ty);
            SanCovTraceSrt2 = M.getOrInsertFunction(SanCovTraceSrt2Name, VoidTy, Int64Ty, Int16Ty);
            SanCovTraceSrt4 = M.getOrInsertFunction(SanCovTraceSrt4Name, VoidTy, Int64Ty, Int32Ty);
            SanCovTraceSrt8 = M.getOrInsertFunction(SanCovTraceSrt8Name, VoidTy, Int64Ty, Int64Ty);
            SourceFileName = M.getName();

            for (Function &F : M)
                instrumentFieldAssign(F);
            for (auto i : StructIDMap) {
                errs() << i.first << ": " << std::to_string(i.second) << "\n";
            }
            return true;
        }
        void injectFieldAssignTracker(Instruction *I, uint64 id);
        void instrumentFieldAssign(Function &func);
    };
}

std::string stripNum(std::string name) {
    size_t len = name.size();
    char tmp[len];
    strncpy(tmp, name.c_str(), len);
    if (len < 1)
        return name;
    while ((tmp[len-1] <= '9' && tmp[len-1] >= '0' && len > 1)
            || (tmp[len-1] == 'i' && tmp[len-2] == '.' && len > 2)
            || (tmp[len-1] == '.' && len > 1)) {
        if (tmp[len-1] == 'i' && tmp[len-2] == '.') {
            tmp[len-1] = 0;
            tmp[len-2] = 0;
            len -= 2;
            continue;
        }
        tmp[len-1] = 0;
        len--;
    }
    name = name.substr(0, len);
    return name;
}

uint16 crc16(std::string name) {
    unsigned len = name.length();
    if (len == 0)
        return 0;
    char *tmp = (char*)malloc(len+1);
    strcpy(tmp, name.c_str());
    uint16 data, hash = 0x3e7a, crc = 0xffff;
    for (unsigned i = 0; i < len; i++) {
        data = *(uint16*)(tmp + i);
        if ((crc&0x0001) ^ (data&0x0001))
            crc = (crc >> 1) ^ (hash |0x8005);
        else
            crc >>= 1;
        hash = data ^ hash;
    }
    crc = ~crc;
    data = crc;
    crc = (crc << 8) | (data >> 8 &0xff);
    return crc;
}

bool isStruct(const Value *val, const Value *var) {
    if (!val->getType()->isIntegerTy())
        return false;
    const GetElementPtrInst *gepInst = dyn_cast<GetElementPtrInst>(var);
    if (gepInst == nullptr)
        return false;
    Type *greTy = gepInst->getResultElementType();
    if (greTy && greTy->isPointerTy())
        return false;
    if (gepInst->getSourceElementType()->isStructTy()) {
        const StructType *srtTy = dyn_cast<StructType>(gepInst->getSourceElementType());
        return srtTy->hasName();
    }
    return false;
}

std::string getStructName(const Value *var) {
    const GetElementPtrInst *gepInst = dyn_cast<GetElementPtrInst>(var);
    std::string srtName = gepInst->getSourceElementType()->getStructName();
    std::string fieldName = gepInst->getName();
    return stripNum(srtName) + "->" + stripNum(fieldName);
}

uint64 getSrtIDFromName(const Value *var) {
    const GetElementPtrInst *gepInst = dyn_cast<GetElementPtrInst>(var);
    std::string srtName = gepInst->getSourceElementType()->getStructName();
    std::string fieldName = gepInst->getName();
    uint16 srtID = crc16(stripNum(srtName));
    uint16 fieldID = crc16(stripNum(fieldName));
    return (((uint64)srtID << 16) | (uint64)fieldID) & 0xffffffff;
}

uint64 getSourceFileID(std::string sourceFileName) {
    uint64 srcID = (uint64)crc16(sourceFileName);
    return srcID & 0xffff;
}

void AssignTracker::instrumentFieldAssign(Function &func) {
    if (!func.size())
        return;
    for (BasicBlock &bb : func) {
        for (Instruction &i : bb) {
            if (StoreInst *si = dyn_cast<StoreInst>(&i)) {
                const Value *val_op = si->getOperand(0);
                const Value *var_op = si->getPointerOperand();
                if (isStruct(val_op, var_op)) {
                    std::string srtName = getStructName(var_op);
                    uint64 srtID = getSrtIDFromName(var_op);
                    srtID |= (getSourceFileID(SourceFileName) & 0xffff) << 32;
                    if (StructIDMap.find(srtName) == StructIDMap.end())
                        StructIDMap[srtName] = srtID;
                    injectFieldAssignTracker(si, StructIDMap[srtName]);
                }
            }
        }
    }
}

void AssignTracker::injectFieldAssignTracker(Instruction *I, uint64 id) {
    IRBuilder<> IRB(I);
    Value *val = I->getOperand(0);
    unsigned bitWidth = val->getType()->getIntegerBitWidth();
    switch (bitWidth) {
        case 8: {
            IRB.CreateCall(SanCovTraceSrt1, {IRB.getInt64(id), IRB.CreateIntCast(val, Int8Ty, true)});
            break;
        }
        case 16: {
            IRB.CreateCall(SanCovTraceSrt2, {IRB.getInt64(id), IRB.CreateIntCast(val, Int16Ty, true)});
            break;
        }
        case 32: {
            IRB.CreateCall(SanCovTraceSrt4, {IRB.getInt64(id), IRB.CreateIntCast(val, Int32Ty, true)});
            break;
        }
        case 64: {
            IRB.CreateCall(SanCovTraceSrt8, {IRB.getInt64(id), IRB.CreateIntCast(val, Int64Ty, true)});
            break;
        }
    }
}

char AssignTracker::ID = 0;
static RegisterPass<AssignTracker> X("AssignTracker", "AssignTracker Pass", false, false);

static void registerAssignTrackerPass(const PassManagerBuilder &, legacy::PassManagerBase &PM)
{
    PM.add(new AssignTracker());
}

static RegisterStandardPasses RegisterAPass(PassManagerBuilder::EP_OptimizerLast, registerAssignTrackerPass);
