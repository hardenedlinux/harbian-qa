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

#include <iostream>
#include <map>

#include "Parse.h"

using namespace clang;
using namespace ento;

/* FuncMap[FUNC_NAME] = SUBSTMT_INFO_STRUCT*/
std::map<std::string, std::vector<stmtInfo>> FuncMap;
/* MemCount[BASE->MEMBER] = COUNT_OF_APPEARING_IN_CONDITION  */
std::map<std::string, unsigned int> MemCount;

namespace {
  class ConditionChecker : public Checker< check::ASTDecl<FunctionDecl>,
					   check::EndAnalysis> {
  public:
    void checkASTDecl(const FunctionDecl *FD, AnalysisManager &Mgr, BugReporter &BR) const;
    void checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const;
  };
} // end anonymous namespace

void ConditionChecker::checkASTDecl(const FunctionDecl *FD, AnalysisManager &Mgr, BugReporter &BR) const {
  const SourceManager &SM = Mgr.getSourceManager();
  const ASTContext &ASTCtx = FD->getASTContext();
  std::string funcName = FD->getNameInfo().getAsString();
  if (FuncMap.find(funcName) != FuncMap.end()) {
    return;
  }

  if (!SM.isInMainFile(FD->getBeginLoc())) {
    return;
  }

  std::vector<stmtInfo> funcInfoVec, parmInfoList;
  funcInfoVec.push_back(FuncInfo(FD));
  parmInfoList = ListAllParmInfo(SM, FD);
  funcInfoVec.insert(funcInfoVec.end(), parmInfoList.begin(), parmInfoList.end());

  if (FD->hasBody()) {
    /* Local variable may initialized by functions parameters */
    for (Stmt *c : FD->getBody()->children()) {
      std::vector<stmtInfo> localVarInfo;
      handleChildrenStmt(SM, c, searchLocalVar, &localVarInfo);
      for (stmtInfo tmpInfo : localVarInfo) {
	if (tmpInfo.typeName == "ParmVar") {
	  funcInfoVec.insert(funcInfoVec.end(), localVarInfo.begin(), localVarInfo.end());
	  break;
	}
      }
    }
    /* Search if there are member operation or parameters in condition substatement */
    for (Stmt *c : FD->getBody()->children()) {
      std::vector<stmtInfo> condInfo;
      handleChildrenStmt(SM, c, searchCondition, &condInfo);
      if (condInfo.size()>0) {
	funcInfoVec.insert(funcInfoVec.end(), condInfo.begin(), condInfo.end());
      }
      for (stmtInfo i : condInfo) {
	/* calculate the using of member operation */
	if (i.typeName == "MemExpr") {
	  std::string key = i.base + "->" + i.target;
	  if (MemCount.find(key) != MemCount.end()) {
	    MemCount[key]++;
	  } else {
	    MemCount[key] = 1;
	  }
	}
      }
    }
  }
    
  FuncMap[funcName] = funcInfoVec;
  for (stmtInfo i : funcInfoVec) {
    llvm::outs() << i.toString() << "\n";
  }
  llvm::outs() << "\n";
}

void ConditionChecker::checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const {
  static int count = 0;
  if (count < 1) {
    llvm::outs() << "MemberExpr count of condition statement: " << "\n";
    for (auto const & m : MemCount) {
      llvm::outs() << m.first << ":" << m.second << "\n";
    }
  }
  count++;
}


void ento::registerConditionChecker(CheckerManager &mgr) {
  mgr.registerChecker<ConditionChecker>();
}

bool ento::shouldRegisterConditionChecker(const LangOptions &LO) {
  return true;
}









