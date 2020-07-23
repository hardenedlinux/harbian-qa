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
        std::hash<std::string> hashSrt;
        std::map<std::string, unsigned> StructIDMap;

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

            SanCovTraceSrt1 = M.getOrInsertFunction(SanCovTraceSrt1Name, VoidTy, Int32Ty, Int8Ty);
            SanCovTraceSrt2 = M.getOrInsertFunction(SanCovTraceSrt2Name, VoidTy, Int32Ty, Int16Ty);
            SanCovTraceSrt4 = M.getOrInsertFunction(SanCovTraceSrt4Name, VoidTy, Int32Ty, Int32Ty);
            SanCovTraceSrt8 = M.getOrInsertFunction(SanCovTraceSrt8Name, VoidTy, Int32Ty, Int64Ty);

            for (Function &F : M)
                instrumentFieldAssign(F);
            for (auto i : StructIDMap) {
                errs() << i.first << ": " << std::to_string(i.second) << "\n";
            }
            return true;
        }
        void injectFieldAssignTracker(Instruction *I, unsigned id);
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

;
}

void AssignTracker::instrumentFieldAssign(Function &func) {
    if (!func.size())
        return;
    for (BasicBlock &bb : func) {
        for (Instruction &i : bb) {
            if (StoreInst *si = dyn_cast<StoreInst>(&i)) {
                const Value *val_op = si->getOperand(0);
                const Value *var_op = si->getPointerOperand();
                if (!val_op->getType()->isIntegerTy())
                    continue;
                if (const GEPOperator *gep = dyn_cast<GEPOperator>(var_op)) {
                    const Value *intPtr = gep->getPointerOperand(); 
                    if (Type *gepOpTy = dyn_cast<PointerType>(intPtr->getType())->getElementType()) {
                        if (gepOpTy->isStructTy()) {
                            std::string srtName = gepOpTy->getStructName();
                            std::string fieldName = var_op->getName();
                            std::string key = stripNum(srtName) + "->" + stripNum(fieldName);
                            if (StructIDMap.find(key) == StructIDMap.end())
                                StructIDMap[key] = hashSrt(key);
                            injectFieldAssignTracker(si, StructIDMap[key]);
                        }
                    }
                }
            }
        }
    }
}

void AssignTracker::injectFieldAssignTracker(Instruction *I, unsigned id) {
    IRBuilder<> IRB(I);
    Value *val = I->getOperand(0);
    unsigned bitWidth = val->getType()->getIntegerBitWidth();
    switch (bitWidth) {
        case 8: {
            IRB.CreateCall(SanCovTraceSrt1, {IRB.getInt32(id), IRB.CreateIntCast(val, Int8Ty, true)});
            break;
        }
        case 16: {
            IRB.CreateCall(SanCovTraceSrt2, {IRB.getInt32(id), IRB.CreateIntCast(val, Int16Ty, true)});
            break;
        }
        case 32: {
            IRB.CreateCall(SanCovTraceSrt4, {IRB.getInt32(id), IRB.CreateIntCast(val, Int32Ty, true)});
            break;
        }
        case 64: {
            IRB.CreateCall(SanCovTraceSrt8, {IRB.getInt32(id), IRB.CreateIntCast(val, Int64Ty, true)});
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
