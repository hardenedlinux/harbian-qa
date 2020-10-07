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
#include <llvm/Analysis/CallGraph.h>

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
std::map<std::string, funcInfoInCFG> thisModFuncsInfo;


std::vector<std::string> readFuncList(std::string funcListPath);
std::vector<std::string> getIRList(std::string IRDirPath);
void getCalledFunc(CallGraph *CG, const Function *f, int blockNum, int level);
void writeToNewFuncList(std::vector<std::string> funcList, std::string oldPath);
void writeToLogDir(std::string fn, std::string funcCallTree, std::string dirPath);


int main(int argc, const char *argv[]) {
    if (argc < 5 || argv[1] == nullptr) {
        outs() << "./extern_func functions_list ir_dir call_depth block_num log_dir\n";
        return 1;
    }
    std::string FuncListPath = argv[1];
    std::string IRDirPath = argv[2];
    unsigned depth = std::stoi(argv[3]);
    unsigned blockNum = std::stoi(argv[4]);
    std::string logDir = argv[5];

    std::vector<std::string> IRList = getIRList(IRDirPath);
    std::vector<std::string> funcList = readFuncList(FuncListPath);
    std::vector<std::string> extFuncList;

    for (std::string ir : IRList) {
        LLVMContext ctx;
        SMDiagnostic err;
        std::unique_ptr<Module> mod = parseIRFile(ir, err, ctx);
        if (mod == nullptr) {
            outs() << FAIL << "Failed to open ir file: " << ir << "\n" << RESET;
            continue;
        }
        Module *constMod = mod.get();
        CallGraph CG(*constMod);
        for (std::string fn : funcList) {
            const Function *func = constMod->getFunction(fn);
            if (func == nullptr || func->size() < 1)
                continue;
            getCalledFunc(&CG, func, blockNum, depth);
        }
    }
    for (std::string ir : IRList) {
        LLVMContext ctx;
        SMDiagnostic err;
        std::unique_ptr<Module> mod = parseIRFile(ir, err, ctx);
        if (mod == nullptr) {
            outs() << FAIL << "Failed to open ir file: " << ir << "\n" << RESET;
            continue;
        }
        Module *constMod = mod.get();
        CallGraph CG(*constMod);
        for (auto &fn : funcsInfo) {
            std::string funcName = fn.first;
            const Function *func = constMod->getFunction(funcName);
            if (func == nullptr || func->size() < 1)
                continue;
            thisModFuncsInfo[funcName] = fn.second;
        }
    }
    for (std::string fn : funcList) {
        std::string funcCallTree;
        if (thisModFuncsInfo.find(fn) != thisModFuncsInfo.end())
            funcCallTree = funcsInfo[fn].callTree(thisModFuncsInfo, 0, depth);
        else {
            funcCallTree = fn;
            outs() << FAIL << fn << " was not found!\n";
        }
        writeToLogDir(fn, funcCallTree, logDir);
    }
    std::vector<std::string> newFuncList;
    for (auto &fn : thisModFuncsInfo) {
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

std::vector<std::string> getIRList(std::string IRDirPath) {
    std::vector<std::string> ret;
   struct dirent *entry;
   DIR *dir = opendir(IRDirPath.c_str());
   if (dir == NULL) {
      return ret;
   }
   while ((entry = readdir(dir)) != NULL) {
       ret.push_back(IRDirPath + "/" + entry->d_name);
   }
   closedir(dir);
   return ret;
}

/* Recursively get the called functions, use blockNum and level limit functions */
void getCalledFunc(CallGraph *CG, const Function *f, int blockNum, int level) {
    const CallGraphNode *n = (*CG)[f];
    if (level < 1)
        return;
    if (n == nullptr) {
        outs() << FAIL << "Failed to get call graph node\n" << RESET;
        return;
    }
    funcInfoInCFG *thisFunc = new funcInfoInCFG(f->getName(), f->size());
    if (funcsInfo.find(f->getName()) == funcsInfo.end()) {
        funcsInfo[f->getName()] = *thisFunc;
    }
    for (auto i : *n) {
        Function *calledFunc = i.second->getFunction();
        if (calledFunc != nullptr) {
            /* Skip the instument function */
            if (calledFunc->getName().find("saniti") != std::string::npos)
                continue;
            if (calledFunc->getName().find("asan") != std::string::npos)
                continue;
            /* Recursive call with a depth level */
            funcsInfo[f->getName()].addCalledFunc(calledFunc->getName());
            getCalledFunc(CG, calledFunc, blockNum, level - 1);
        }
    }
    return;
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
