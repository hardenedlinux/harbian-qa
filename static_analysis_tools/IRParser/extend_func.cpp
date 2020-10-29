#include <llvm/IR/Module.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/Analysis/CmpInstAnalysis.h>
#include <llvm/IR/DebugLoc.h>
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/DIBuilder.h"
#include "llvm/IR/Function.h"
#include <llvm/IR/DebugInfoMetadata.h>
#include <llvm/IR/CFG.h>
#include <llvm/IR/Metadata.h>

#include <string>
#include <iostream>
#include <sstream>
#include <fstream>
#include <sys/types.h>
#include <dirent.h>
#include <vector>

#include "log.h"
#include "info.h"


using namespace std;
using namespace llvm;


std::map<std::string, funcInfoInCFG> funcsInfo;


std::vector<std::string> readFuncList(std::string funcListPath);
void getCalledFunc(Module *mod, Function *func, int blockNum, int level);
void writeToNewFuncList(std::vector<std::string> funcList, std::string oldPath);
void writeToLogDir(std::string fn, std::string funcCallTree, std::string dirPath);


int main(int argc, const char *argv[]) {
    if (argc < 5 || argv[1] == nullptr) {
        outs() << "./extern_func functions_list ir_path call_depth block_num log_dir\n";
        return 1;
    }
    std::string FuncListPath = argv[1];
    std::string IRPath = argv[2];
    unsigned depth = std::stoi(argv[3]);
    unsigned blockNum = std::stoi(argv[4]);
    std::string logDir = argv[5];

    std::vector<std::string> funcList = readFuncList(FuncListPath);
    std::vector<std::string> extFuncList;

    LLVMContext ctx;
    SMDiagnostic err;
    std::unique_ptr<Module> mod_unique = parseIRFile(IRPath, err, ctx);
    if (mod_unique == nullptr) {
        outs() << FAIL << "Failed to open ir file: " << IRPath << "\n" << RESET;
        return 1;
    }
    Module *mod = mod_unique.get();

    for (std::string fn : funcList) {
        Function *func = mod->getFunction(fn);
        getCalledFunc(std::move(mod), func, blockNum, depth);
    }

    for (std::string fn : funcList) {
        std::string funcCallTree;
        if (funcsInfo.find(fn) != funcsInfo.end())
            funcCallTree = funcsInfo[fn].callTree(funcsInfo, 0, depth);
        else {
            funcCallTree = fn;
            outs() << FAIL << fn << " was not found!\n";
        }
        writeToLogDir(fn, funcCallTree, logDir);
    }
    std::vector<std::string> newFuncList;
    for (auto &fn : funcsInfo) {
        if (fn.second.getBlockNum() > blockNum)
        newFuncList.push_back(fn.first);
    }
    writeToNewFuncList(newFuncList, FuncListPath);
}

std::vector<std::string> readFuncList(std::string funcListPath) {
    fstream funcListFile(funcListPath);
    std::vector<std::string> funcList;
    std::string fn = "";
    if (!funcListFile.is_open()) {
        outs() << FAIL << "Failed to open init function list\n" << RESET;
        return funcList;
    }
    while (getline(funcListFile, fn)) {
        if(fn != "")
            funcList.push_back(fn);
    }
    return funcList;
}

/* Recursively get the called functions, use blockNum and level limit functions */
void getCalledFunc(Module *mod, Function *func, int blockNum, int level) {
    if (level < 1)
        return;
    if (func == nullptr) {
        outs() << FAIL << "unvariable function\n"<< RESET;
        return;
    }
    if (func->size() < 1) {
        func = mod->getFunction(func->getName());
    }

    if (func != nullptr) {
        funcInfoInCFG *thisFuncInfo = new funcInfoInCFG(func->getName(), func->size());
        if (funcsInfo.find(func->getName()) == funcsInfo.end())
            funcsInfo[func->getName()] = *thisFuncInfo;
        delete thisFuncInfo;
    }

    if (func != nullptr && func->size() > 0) {
        for (BasicBlock &bb : *func) {
            for (Instruction &i : bb) {
                CallInst *callInst = dyn_cast<CallInst>(&i);
                if (callInst != nullptr) {
                    Function *calledFunc = callInst->getCalledFunction();
                    if (calledFunc == nullptr) {
                        calledFunc = dyn_cast<Function>(callInst->getCalledValue()->stripPointerCasts());
                    }
                    if (calledFunc != nullptr) {
                        /* Skip the instument function */
                        if (calledFunc->getName().find("saniti") != std::string::npos)
                            continue;
                        if (calledFunc->getName().find("asan") != std::string::npos)
                            continue;
                        if (calledFunc->getName().find("llvm.") != std::string::npos)
                            continue;
                        /* Recursive call with a depth level */
                        funcsInfo[func->getName()].addCalledFunc(calledFunc->getName());
                        getCalledFunc(mod, calledFunc, blockNum, level - 1);
                    }
                }
            }
        }
    }
}

void writeToNewFuncList(std::vector<std::string> funcList, std::string oldPath) {
    ofstream newFuncList;
    newFuncList.open(oldPath + ".new");
    for (std::string f : funcList) {
        newFuncList << f << "\n";
    }
    newFuncList.close();
}

void writeToLogDir(std::string fn, std::string funcCallTree, std::string dirPath) {
    ofstream funcLogFile;
    funcLogFile.open(dirPath + "/" + fn);
    funcLogFile << funcCallTree << "\n";
    funcLogFile.close();
}
