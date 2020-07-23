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

#include <iostream>
#include <sstream>
#include <fstream>
#include <stdio.h>
#include <vector>
#include <sys/types.h>
#include <dirent.h>

#include "log.h"
#include "info.h"


using namespace llvm;
using namespace std;


std::vector<std::string> getFuncListFromFile(std::string funcListFile);
std::vector<std::string> listIRFile(std::string IRFileDir);
std::vector<gepInfo> getGEPInfoFromFunc(Function *func);
void writeDebugInfo(std::vector<gepInfo> info, std::string path);
void writeFuncAddrMap(std::vector<gepInfo> info, std::string path);

int main(int argc, const char *argv[]) {
    if (argc < 3) {
        outs() << FAIL << "./kcov_map ir_dir func_list log_dir\n" << RESET;
        return 1;
    }
    std::string IRFileDir    = argv[1];
    std::string FuncListFile = argv[2];
    std::string LogDir       = argv[3];

    std::vector<std::string> FuncList = getFuncListFromFile(FuncListFile);
    std::vector<std::string> IRFiles = listIRFile(IRFileDir);
    std::map<unsigned, gepInfo> gepInfoMap;
    for (std::string funcName : FuncList) {
        bool found = false;
        /* Search which file is the function located in*/
        for (std::string f : IRFiles) {
            LLVMContext context;
            SMDiagnostic error;
            std::unique_ptr<Module> mod = parseIRFile(f, error, context);
            Module const *mod_const = mod.get();
            if (mod_const == nullptr) {
                outs() << FAIL_LINE("Failed to open " + f + ".");
                return 1;
            }

            Function *func = mod_const->getFunction(funcName);
            if (func == nullptr) continue;

            if (func != nullptr) {
                if (func->size() == 0) {
                    continue;
                }
                found = true;
                outs() << SUCC_LINE("Function " + funcName + " was found");

                std::vector<gepInfo> gepInfos = getGEPInfoFromFunc(func);
                for (gepInfo i : gepInfos) {
                    if (gepInfoMap.find(i.getGEPointerID()) != gepInfoMap.end()) {
                        gepInfoMap[i.getGEPointerID()].incCount();
                    } else {
                        gepInfoMap[i.getGEPointerID()] = i;
                        gepInfoMap[i.getGEPointerID()].incCount();
                    }
                }
                /* Write log file of every functions */
                writeDebugInfo(gepInfos, LogDir + "/" + funcName + "state.json");
                writeFuncAddrMap(gepInfos, LogDir + "/" + funcName + ".state.map");
                break;
            }
        }
        if (!found)
            outs() << FAIL_LINE("Function " + funcName + " was not found");
    }
    /* struct a->b: HASH_ID WEIGHT */
    for (auto i : gepInfoMap) {
        outs() << i.second.getStructName() << ": " << i.second.getGEPointerID() << " " << i.second.getCount() << "\n";
    }
}

std::vector<std::string> getFuncListFromFile(std::string funcListPath) {
    fstream funcListFile(funcListPath);
    std::vector<std::string> funcList;
    std::string fn = "";
    if (!funcListFile.is_open()) {
        outs() << FAIL_LINE( "Failed to open init function list");
        return funcList;
    }
    while (getline(funcListFile, fn)) {
        if(fn != "")
                funcList.push_back(fn);
    }
    return funcList;
}

std::vector<std::string> listIRFile(std::string IRDirPath) {
    std::vector<std::string> irList;
    struct dirent *entry;
    DIR *dir = opendir(IRDirPath.c_str());
    if (dir == NULL) {
        outs() << FAIL_LINE("Dir wrong");
        return irList;
    }
    while ((entry = readdir(dir)) != NULL) {
        std::string fn(entry->d_name);
        if (fn.find(".ll") != std::string::npos)
            irList.push_back(IRDirPath + "/" + entry->d_name);
    }
    closedir(dir);
    return irList;
}

/* It's hard to track if GEPointer will be use in condition, we count every GEPOperation */
std::vector<gepInfo> getGEPInfoFromFunc(Function *func) {
    std::map<string, bool> gepInfoMap;
    std::vector<gepInfo> ret;
    for (BasicBlock &bb : *func) {
        for (Instruction &i : bb) {
            GetElementPtrInst *gepInst = dyn_cast<GetElementPtrInst>(&i);
            if (gepInst != nullptr) {
                unsigned width = 0;
                if (gepInst->getType()) {
                    if (gepInst->getType()->isIntegerTy())
                        width = gepInst->getType()->getIntegerBitWidth();
                }

                if (gepInst->getSourceElementType()->isStructTy()) {
                    std::string structName = gepInst->getSourceElementType()->getStructName();
                    std::string fieldName = gepInst->getName();
                    gepInfo thisGEP(structName, fieldName, width);
                    if (!gepInfoMap[thisGEP.getStructName()]) {
                        gepInfoMap[thisGEP.getStructName()] = true;
                        ret.push_back(thisGEP);
                    } else {
                        thisGEP.incCount();
                    }
                }
            }
        }
    }
    return ret;
}

void writeDebugInfo(std::vector<gepInfo> info, std::string path) {
    ofstream json;
    json.open(path);
    for (auto i : info) {
        json << i.getAsJson();
    }
    json.close();
}

void writeFuncAddrMap(std::vector<gepInfo> info, std::string path) {
    ofstream map;
    map.open(path);
    for (auto i : info) {
        map << i.getStructName() << ": 0x" << std::hex << i.getGEPointerID() << "\n";
    }
    map.close();
    }
