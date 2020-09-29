#include <string>
#include <unordered_map>

#include <string>
#include <iostream>
#include <sstream>
#include <fstream>
#include <sys/types.h>
#include <dirent.h>
#include <vector>

#include "log.h"

using namespace std;

class sanCallInfo {
private:
    std::string rawInst;
    unsigned    blockID;
    unsigned    address;
public:
    sanCallInfo(std::string rawI, unsigned bID) {
        rawInst = rawI;
        blockID = bID;
    }
    sanCallInfo(){};
    void AttachAddress(unsigned addr) {
        address = addr;
    }
    unsigned getBlockID() {
        return blockID;
    }
    std::string getAsLine() {
        return std::to_string(address) + ": " + rawInst;
    }
    unsigned getAddress() {
        return address;
    }
};

class blockInfo {
private:
    unsigned      blockID;
    std::string   blockName;
    std::string   funcName;
    unsigned long count;

    std::vector<sanCallInfo> sanCalls;
    std::vector<unsigned>    succBlock;
    std::vector<unsigned>    predBlock;

public:
    blockInfo(unsigned bID, std::string bName, std::string fName, unsigned cnt) {
        blockID   = bID;
        blockName = bName;
        funcName  = fName;
        count     = cnt;
    }

    blockInfo(){};

    unsigned getBlockID() {
        return blockID;
    }

    void addSuccBlock(unsigned bID) {
        for (unsigned i : succBlock) {
            if (i == bID)
                return;
        }
        succBlock.push_back(bID);
    }

    void addPredBlock(unsigned bID) {
        for (unsigned i : predBlock) {
            if (i == bID)
                return;
        }
        predBlock.push_back(bID);
    }

    void addSanCall(sanCallInfo sc) {
        sanCalls.push_back(sc);
    }

    std::vector<sanCallInfo> getSanCalls() {
        return sanCalls;
    }

    unsigned getForwardEdgeNum() {
        /* We use this method to get the weight of this block */
        //return count;
        return succBlock.size();
    }

    std::string getAsJson() {
        std::string ret = "";
        ret += "{\n";
        ret += "Function: \"" + funcName + "\",\n";
        ret += "Block: \"" + blockName + "\",\n";
        ret += "BlockID: " + std::to_string(blockID) + ",\n";
        ret += "Count: " + std::to_string(count) + ",\n";
        ret += "Predblocks: [";
        for (unsigned b : predBlock)
            ret += std::to_string(b) + ", ";
        ret += "],\n";
        ret += "Succblocks: [";
        for (unsigned b : succBlock)
            ret += std::to_string(b) + ", ";
        ret += "],\n";
        ret += "SanitizerCall: [\n";
        for (sanCallInfo sc : sanCalls) {
            ret += "\t" + sc.getAsLine() + ",\n";
        }
        ret += "\t],\n";
        ret += "}\n";
        return ret;
    }
};

class gepInfo {
private:
    std::string structName;
    std::string fieldName;
    unsigned    bitWidth;
    unsigned    count;
    unsigned    ID;

    unsigned hash(string s) {
        std::hash<std::string> hashFunc;
        return hashFunc(s);
    }

    std::string stripNum(std::string name) {
        size_t len = name.size();
        char tmp[len];
        strncpy(tmp, name.c_str(), len);
        if (len < 1)
            return name;
        /* llvm will add suffix to variable name, we have to strip away*/
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

public:
    gepInfo(std::string srtName, std::string fName, unsigned bitWid) {
        structName = srtName;
        fieldName  = fName;
        bitWidth   = bitWid;
        ID         = hash(getStructName());
        count      = 0;
    }

    gepInfo(){};

    std::string getStructName() {
        return stripNum(structName) + "->" + stripNum(fieldName);
    }

    void incCount() {count++;}

    /* We use this method to get the weight of a kernel state */
    unsigned getCount() {return count;}

    unsigned getGEPointerID() {return ID;}

    std::string getAsJson() {
        std::string ret;
        ret += "{\n";
        ret += "\tName: " + structName + "->" + fieldName + ",\n";
        ret += "\tBitWidth: " + std::to_string(bitWidth) + ",\n";
        ret += "\tID: " + std::to_string(ID) + "\n";
        ret += "}\n";
        return ret;
    }
};

class funcInfoInCFG {
private:
    std::string   funcName;
    unsigned      blockNum;

    std::vector<std::string> calledFuncs;
public:
    funcInfoInCFG(std::string fName, unsigned bNum) {
        funcName = fName;
        blockNum = bNum;
    }
    
    funcInfoInCFG(){};

    void addCalledFunc(std::string cFunc) {
        for (std::string f : calledFuncs) {
            if (f == cFunc)
                return;
        }
        calledFuncs.push_back(cFunc);
    }

    unsigned getBlockNum() {return blockNum;}

    std::string callTree(std::map<std::string, funcInfoInCFG> funcInfoList, int startlevel, int depth) {
        std::string ret = thisFuncInfo(startlevel);
        if (depth < 1)
            return ret;
        for (std::string calledFunc : calledFuncs) {
            if (funcInfoList.find(calledFunc) != funcInfoList.end()) {
                ret += funcInfoList[calledFunc].callTree(funcInfoList, startlevel + 1, depth - 1);
            }
        }
        return ret;
    }
    std::string thisFuncInfo(int level) {
        std::string ret = "|";
        for (unsigned i=0; i<level; i++)
            ret += "--";
        ret += (funcName + "( " + std::to_string(blockNum) + ") -depth( " + std::to_string(level) + ")\n");
        return ret;
    }
};
