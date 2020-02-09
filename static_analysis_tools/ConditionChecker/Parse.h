#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Support/raw_ostream.h"
#include "clang/AST/ParentMap.h"
#include "clang/Basic/TargetInfo.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"

using namespace clang;
using namespace ento;

class stmtInfo {
 public:
  std::string  typeName;
  unsigned int ID;
  std::string  target;
  /* For MemberExpr base->target */
  std::string  base;
  std::string  srcLine;

  void init(std::string tpnm, int64_t id, std::string targetinfo, std::string bsinfo, std::string srcline) {
    typeName = tpnm;
    ID = id;
    target = targetinfo;
    base = bsinfo;
    srcline.erase(std::remove(srcline.begin(), srcline.end(), '\n'), srcline.end());
    srcline.erase(std::remove(srcline.begin(), srcline.end(), '\t'), srcline.end());
    srcLine = srcline;
  }
  
  std::string toString() {    
    std::string retStr, IDStr;
    char IDChars[0x10];
    if (ID > 0) {
      sprintf(IDChars, "0x%x", ID);
      IDStr = "ID-" + std::string(IDChars);
    }
    retStr = "[" + typeName + "] ";
    if (ID != 0) {
      retStr = retStr.append("ID-" + IDStr + " ");
    }
    if (base != "") {
      retStr = retStr.append(base) + "->";
    }
    retStr = retStr.append(target);
    if (srcLine != "") {
      retStr = retStr.append("\nRawSrcLine: " + srcLine);
    }
    return retStr;
  }
};

typedef bool(*stmtHandle)(const SourceManager &SM, const Stmt *s, std::vector<stmtInfo> *info);

/* Recursicely parse the children statement, use the stmtHandle function */
void handleChildrenStmt(const SourceManager &SM, const Stmt *s, stmtHandle handle, std::vector<stmtInfo> *info);

/* Implement of handle specified statement */
bool searchLocalVar(const SourceManager &SM, const Stmt *s, std::vector<stmtInfo> *info);
bool searchParm(const SourceManager &SM, const Stmt *s, std::vector<stmtInfo> *info);
bool searchCondition(const SourceManager &SM, const Stmt *s, std::vector<stmtInfo> *info);

std::string srcLineToString(const SourceManager &SM, SourceLocation SRs, SourceLocation SRe);
stmtInfo FuncInfo(const FunctionDecl *FD);
std::vector<stmtInfo> ListAllParmInfo(const SourceManager &SM, const FunctionDecl *FD);






