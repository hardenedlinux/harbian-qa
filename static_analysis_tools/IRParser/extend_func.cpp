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


using namespace std;
using namespace llvm;


std::vector<std::string> readFuncList(std::string funcListPath);
std::vector<std::string> getIRList(std::string IRDirPath);
std::map<std::string, int> FuncComplexity;

void getCalledFunc(CallGraph *CG, const Function *f, int blockNum, int level, std::vector<std::string> *funcList, std::string rootFunc);
void writeToNewFuncList(std::vector<std::string> funcList, std::string oldPath);

int main(int argc, const char *argv[]) {
    if (argc < 2 || argv[1] == nullptr) {
        outs() << "./extern_func functions_list ir_dir\n";
        return 1;
    }
    std::string FuncListPath = argv[1];
    std::string IRDirPath = argv[2];

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
            FuncComplexity[fn] = func->size();
            outs() << "Function: " << fn << " was found\n";
            if (func->size() < 20)
                getCalledFunc(&CG, func, 7, 3, &extFuncList, fn);
            }
        }

    /* Show the sum blocks of enable functions of a root function */
    outs() << "Extended function:\n";
    for (auto &i : FuncComplexity) {
        outs() << "Function: " << i.first << " with " << i.second << " blocks\n";
    }

    for (std::string f : extFuncList) {
        bool found = false;
        for (std::string ff : funcList) {
            if (f == ff) {
                found = true;
                break;
            }
        }
        if (found)
            continue;
        funcList.push_back(f);
    }
    /* Create a FuncListPath.new file for extended functions list */
    writeToNewFuncList(funcList, FuncListPath);
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
void getCalledFunc(CallGraph *CG, const Function *f, int blockNum, int level, std::vector<std::string> *funcList, std::string rootFunc) {
    const CallGraphNode *n = (*CG)[f];
    if (level < 1)
        return;
    if (n == nullptr) {
        outs() << FAIL << "Failed to get call graph node\n" << RESET;
        return;
    }
    for (auto i : *n) {
        Function *calledFunc = i.second->getFunction();
        if (calledFunc != nullptr) {
            /* Skip the instument function */
            if (calledFunc->getName().find("saniti") != std::string::npos)
                continue;
            if (calledFunc->getName().find("asan") != std::string::npos)
                continue;
            if (calledFunc->size() > blockNum) {
                funcList->push_back(calledFunc->getName());
                outs() << "Add function " << calledFunc->getName() << " to root " << rootFunc << " at level " << level << "\n";
                /* Calculate the sum of blocks from root function to every called functions */
                FuncComplexity[rootFunc] += calledFunc->size();
            }
            /* Recursive call with a depth level */
            getCalledFunc(CG, calledFunc, blockNum, level - 1, funcList, rootFunc);
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
