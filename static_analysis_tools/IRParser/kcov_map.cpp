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
#include "llvm/Support/BlockFrequency.h"
#include "llvm/Analysis/BlockFrequencyInfo.h"
#include "llvm/Analysis/BranchProbabilityInfo.h"
#include "llvm/IR/Dominators.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/Analysis/LoopInfo.h"

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
Function &getFuncFromMods(std::vector<std::string> IRFiles, std::string funcName);
std::map<std::string, unsigned> getBlockIDMap(Function *func);
std::map<unsigned, blockInfo> getBlockInfo(Function *func, std::map<std::string, unsigned> blockIDMap);
std::string getASMCodeFileName(std::string ASMCodeDir, std::string sourceFile);
std::vector<sanCallInfo> getSanCallsFromAsmLine(std::string asmFileName, std::string funcName, std::map<std::string, unsigned> blockInfosMap);
std::vector<unsigned> getAddrFromObjdumpAsm(std::string vmLinux, std::string funcName);
void writeDebugInfo(std::map<unsigned, blockInfo> blockInfos, std::string path);
void writeFuncAddrMap(std::map<unsigned, blockInfo> blockInfo, std::string path);
uint64_t encode(unsigned addr, unsigned num);


int main(int argc, const char *argv[]) {
    if (argc < 5) {
        outs() << FAIL << "./kcov_map ir_dir asm_dir vmlinux func_list log_dir\n" << RESET;
        return 1;
    }
    std::string IRFileDir    = argv[1];
    std::string ASMCodeDir   = argv[2];
    std::string VMLinux      = argv[3];
    std::string FuncListFile = argv[4];
    std::string LogDir       = argv[5];

    std::vector<std::string> FuncList = getFuncListFromFile(FuncListFile);
    std::vector<std::string> IRFiles = listIRFile(IRFileDir);

    for (std::string funcName : FuncList) {
        bool found = false;
        /* Search which riFile the function is loacted in */
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
                    //outs() << WARN_LINE("Function " + funcName + " declaration, pass");
                    continue;
                }
                found = true;
                outs() << SUCC_LINE("Function " + funcName + " was found");

                /* Get the IR of function, extract block infomation */
                std::map<std::string, unsigned> blockIDMap = getBlockIDMap(func);
                std::map<unsigned, blockInfo> blockInfosMap = getBlockInfo(func, blockIDMap);
                /* Get the sanitizer_* call of assamble code */
                std::string asmFile = getASMCodeFileName(ASMCodeDir, mod_const->getSourceFileName());
                std::vector<sanCallInfo> sanCallInfos = getSanCallsFromAsmLine(asmFile, funcName, blockIDMap);
                /* objdump assebly code should be matched to assemble one by one */
                std::vector<unsigned> objdumpAddrs = getAddrFromObjdumpAsm(VMLinux, funcName);
                if (sanCallInfos.size() != objdumpAddrs.size()) {
                    outs() << std::to_string(sanCallInfos.size()) << ":" << std::to_string(objdumpAddrs.size()) << "\n";
                    outs() << FAIL_LINE("Function " + funcName + " assemble and objdump is mismatch\n");
                    continue;
                }

                unsigned idx = 0;
                for (sanCallInfo sc : sanCallInfos) {
                    sc.AttachAddress(objdumpAddrs[idx]);
                    blockInfosMap[sc.getBlockID()].addSanCall(sc);
                    idx++;
                }
                writeDebugInfo(blockInfosMap, LogDir + "/" + funcName + ".json");
                writeFuncAddrMap(blockInfosMap, LogDir + "/" + funcName + ".addr.map");
                break;
            }
        }
        if (!found)
            outs() << FAIL_LINE("Function " + funcName + " was not found");
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

std::map<std::string, unsigned> getBlockIDMap(Function *func) {
    std::map<std::string, unsigned> blockIDMap;
    unsigned bID = 0, count = 0;
    std::string funcName = func->getName();
    for (BasicBlock &bb : *func) {
        count++;
        std::string blockName = bb.getName();
        if (blockName != "") 
            blockIDMap[blockName] = bID++;
        else {
            bb.setValueName(ValueName::Create(funcName + "." + std::to_string(count)));
            blockIDMap[funcName + "." + std::to_string(count)] = bID++;
        }
    }

    return blockIDMap;
}

std::map<unsigned, blockInfo> getBlockInfo(Function *func, std::map<std::string, unsigned> blockIDMap) {
    std::map<unsigned, blockInfo> blockInfosMap;
    DominatorTree *DT = new DominatorTree(const_cast<Function &>(func->getFunction()));
    LoopInfo *LI = new LoopInfo(*DT);
    BranchProbabilityInfo *BPI = new BranchProbabilityInfo(func->getFunction(), *LI);
    BlockFrequencyInfo *BFI = new BlockFrequencyInfo(func->getFunction(), *BPI, *LI);
    unsigned bID = 0;
    BasicBlock &entry = func->getEntryBlock();

    /* The frequency of entry block is maxium, 
     * all the maxium will formalize to 100 
     */
    unsigned long zoom = 1, maxFreq = BFI->getBlockFreq(&entry).getFrequency();
    if (maxFreq > 100)
        zoom = maxFreq / 100;
    else if (maxFreq > 0 && maxFreq <= 100)
        zoom = 100 / maxFreq;
    else
        zoom = 1;
    if (zoom < 1)
        zoom = 1;

    for (BasicBlock &bb : *func) {
        bID++;
        std::string blockName = bb.getName();
        std::string funcName = func->getName();
        if (blockName == "")
            blockName = funcName + "." + std::to_string(bID);
        unsigned long weight = BFI->getBlockFreq(&bb).getFrequency();
        if (maxFreq > 100)
            weight = weight / zoom;
        else
            weight = weight * zoom;
        /* weight/zoom maybe zero */
        if (weight > 100 || weight < 1)
            weight = 1;

        blockInfo binfo(blockIDMap[blockName], blockName, funcName, weight);
        for (BasicBlock *predbb : predecessors(&bb)) {
            std::string predbbName = predbb->getName();
            if (predbbName != "")
                binfo.addPredBlock(blockIDMap[predbbName]);
            else
                binfo.addPredBlock(0xffff);
        }
        for (BasicBlock *succbb : successors(&bb)) {
            std::string succbbName = succbb->getName();
            if (succbbName != "")
                binfo.addSuccBlock(blockIDMap[succbbName]);
            else
                binfo.addSuccBlock(0xffff);
        }
        blockInfosMap[binfo.getBlockID()] = binfo;
    }
    delete DT;
    delete LI;
    delete BPI;
    delete BFI;

    return blockInfosMap;
}

std::string getASMCodeFileName(std::string ASMCodeDir, std::string sourceFile) {
    while (std::size_t pos = sourceFile.find("/") != std::string::npos) {
        sourceFile = sourceFile.substr(pos);
    }
    std::size_t pos = sourceFile.find(".");
    sourceFile = sourceFile.substr(0, pos + 1) + "s";
    return ASMCodeDir + "/" + sourceFile;
}

std::vector<sanCallInfo> getSanCallsFromAsmLine(std::string asmFileName, std::string funcName, std::map<std::string, unsigned> blockIDMap) {
    fstream asmFile(asmFileName);
    std::vector<sanCallInfo> sanCallInfos;
    if (!asmFile.is_open()) {
        outs() << FAIL_LINE(asmFileName + " can't be found\n");
        return sanCallInfos;
    }

    std::string ln;
    bool infunc = false;
    std::string blockName = "";
    while (getline(asmFile, ln)) {
        if (ln.size() < 1)
            continue;
        if (ln.find(funcName + ":") != std::string::npos) {
            if (ln.find("@" + funcName) != std::string::npos) {
                infunc = true;
                continue;
            }
        }
        if (ln.find("Lfunc_end") != std::string::npos && infunc) {
            infunc = false;
            break;
        }
        if (infunc) {
            std::size_t foundPos = ln.find("# %");
            if (foundPos != std::string::npos) {
                ln = ln.substr(foundPos + 3, ln.size()-1);
                foundPos = ln.find("# %");
                if (foundPos != std::string::npos)
                    ln = ln.substr(foundPos + 3, ln.size()-1);
                if (ln.find("SP_return") != std::string::npos) continue;
                if (blockIDMap.find(ln) == blockIDMap.end()) {
                    continue;
                }
                blockName = ln;
            }
            if (ln.find("__sanitizer_cov_trace") != std::string::npos) {
                sanCallInfo scall(ln, blockIDMap[blockName]);
                sanCallInfos.push_back(scall);
            }
        }
    }
    return sanCallInfos;
}

std::vector<unsigned> getAddrFromObjdumpAsm(std::string vmLinux, std::string funcName) {
    std::vector<unsigned> address;
    std::string objdump = "objdump";
    std::string disAsmFunc = "--disassemble=";
    std::string noRaw =  "--no-show-raw-insn";
    std::string cmd = objdump + " " + disAsmFunc+funcName + " " + noRaw + " " + vmLinux;
    FILE *pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        outs() << FAIL_LINE("Failed to read objdump\n");
        outs() << WARN_LINE("Try this command line: \"" + cmd + "\" to get the output\n");
        return address;
    }

    char buffer[0x100];
    bool infunc = false;
    bool foundSanCall = false;
    while (fgets(buffer, 0x100, pipe) != NULL) {
        std::string ln(buffer);
        if (ln.find("<" + funcName + ">:") != std::string::npos) {
            infunc = true;
            continue;
        }
        if (infunc && ln == "\n")
            break;
        if (infunc && foundSanCall) {
            foundSanCall = false;
            std::size_t colon = ln.find(":");
            if (colon == std::string::npos) {
                outs() << FAIL_LINE("Failed to get address of " + ln);
                break;
            }
            uint64_t addr_full = std::stoull(ln.substr(0, colon), nullptr, 16);
            unsigned addr = unsigned(addr_full);
            address.push_back(addr);
            foundSanCall = false;
        }
        if (infunc) {
            if (ln.find("<__sanitizer_cov_trace") != std::string::npos) {
                foundSanCall = true;
                continue;
            }
        }
    }
    return address;
}

void writeDebugInfo(std::map<unsigned, blockInfo> blockInfos, std::string path) {
    ofstream json;
    json.open(path);
    for (auto i : blockInfos) {
        json << i.second.getAsJson();
    }
    json.close();
}

void writeFuncAddrMap(std::map<unsigned, blockInfo> blockInfos, std::string path) {
    ofstream map;
    map.open(path);
    for (auto i : blockInfos) {
        auto bi = i.second;
        for (auto sc : bi.getSanCalls()) {
            if (sc.getAsLine().find("trace_pc") != std::string::npos) 
                map << "0x" << std::hex << encode(sc.getAddress(), bi.getForwardEdgeNum()) << "\n";
            if (sc.getAsLine().find("trace_srt") != std::string::npos)
                map << "0x" << std::hex << encode(sc.getAddress(), 1) << "\n";
        }
    }
    map.close();
}

uint64_t encode(unsigned addr, unsigned num) {
    uint64_t ret = (uint64_t)num;
    return  ((ret&0xffff)<<32) | (uint64_t)(addr&0xffffffff);
}
