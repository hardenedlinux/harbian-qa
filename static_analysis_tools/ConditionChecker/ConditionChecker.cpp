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
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramState.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExprEngine.h"

#include <iostream>
#include <map>

#include "Parse.h"

using namespace clang;
using namespace ento;

/* FuncMap[FUNC_NAME] = SUBSTMT_INFO_STRUCT*/
std::map<std::string, std::vector<stmtInfo>> FuncMap;
/* MemCount[BASE->MEMBER] = COUNT_OF_APPEARING_IN_CONDITION  */
std::map<std::string, unsigned int> ASTMemCount;
std::map<std::string, unsigned int> CFGMemCount;

namespace {
  class ConditionChecker : public Checker< check::ASTDecl<FunctionDecl>,
					   check::BranchCondition,
					   check::EndAnalysis> {
  public:
    void checkASTDecl(const FunctionDecl *FD, AnalysisManager &Mgr, BugReporter &BR) const;
    void checkEndAnalysis(ExplodedGraph &G, BugReporter &BR, ExprEngine &Eng) const;
    void checkBranchCondition(const Stmt *s, CheckerContext &Ctx) const;
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
      for (stmtInfo tmpInfo : condInfo) {
	if(tmpInfo.typeName == "MemExpr" || tmpInfo.typeName == "ParmVar") {
	  funcInfoVec.insert(funcInfoVec.end(), condInfo.begin(), condInfo.end());
	  break;
	}
      }
      for (stmtInfo i : condInfo) {
	/* calculate the using of member operation */
	if (i.typeName == "MemExpr") {
	  std::string key = i.base + "->" + i.target;
	  if (ASTMemCount.find(key) != ASTMemCount.end()) {
	    ASTMemCount[key]++;
	  } else {
	    ASTMemCount[key] = 1;
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
  llvm::outs() << "Count MemberExpr in condition statement(AST Parse): " << "\n";
  for (auto const & m : ASTMemCount) {
    llvm::outs() << m.first << ":" << m.second << "\n";
  }
  llvm::outs() << "Count MemberExpr in condition statement(CFG Parse): " << "\n";
  for (auto const & m : CFGMemCount) {
    llvm::outs() << m.first << ":" << m.second << "\n";
  }
}

void ConditionChecker::checkBranchCondition(const Stmt *s, CheckerContext &Ctx) const {
  ProgramStateRef State = Ctx.getState();
  const LocationContext *LC = Ctx.getLocationContext();
  SVal val = State->getSVal(s, LC);

  const SymExpr *SE = val.getAsSymbolicExpression();
  std::string thisMemRegStr = "";
  std::string funcName = "";
  if (SE != nullptr) {
    std::vector<symInfo> tmp;
    if (SE->getOriginRegion() != nullptr) {
      thisMemRegStr = SE->getOriginRegion()->getString();
    }
    const Decl *D = LC->getDecl();

    if (D != nullptr) {
      const FunctionDecl *FD = D->getAsFunction();
      if (FD != nullptr) {
	funcName = FD->getName();
      }
    }
    parseSymExpr(SE, &tmp);
    if (tmp.size() > 0) {
      llvm::outs() << "Condition parse:\n";
      for (symInfo s : tmp) {
	s.addFuncName(funcName);
	llvm::outs() << s.toString() << "\n";
	if (s.typeName == "MemSymbol") {
	  std::string key = s.targetStr;
	  if (CFGMemCount.find(key) != CFGMemCount.end()) {
	    CFGMemCount[key]++;
	  } else {
	    CFGMemCount[key] = 1;
	  }
	}
      }
    }
  } else {
    return;
  }

  std::vector<symInfo> SymbolInfo;
  Optional<DefinedOrUnknownSVal> dval = val.getAs<DefinedOrUnknownSVal>();
  if (dval) {
    ProgramStateRef cState = State->assume(*dval, true);
    if (cState != nullptr) {
      ConstraintRangeTy Constraints = cState->get<ConstraintRange>();
      if (!Constraints.isEmpty()) {
	for (ConstraintRangeTy::iterator i = Constraints.begin();
	     i != Constraints.end(); i++) {
	  if (i.getKey()->getOriginRegion() != nullptr) {
	    if (i.getKey()->getOriginRegion()->getString() == thisMemRegStr) {
	      parseSymExpr(i.getKey(), &SymbolInfo);
	      symInfo *tmp = nullptr;
	      for (unsigned int j = 0; j < SymbolInfo.size(); j++) {
		if (SymbolInfo[j].typeName == "MemSymbol") {
		  tmp = &SymbolInfo[j];
		}
	      }
	      for (llvm::APSInt e : splitRangeSet(i.getData())) {
		if (tmp != nullptr) {
		  tmp->addConcreteValue(e);
		}
	      }
	      for (symInfo s : SymbolInfo) {
		llvm::outs() << s.toString() << "\n";
	      }
	      llvm::outs() << "\n\n";
	    }
	  }
	}
      }
    }
  }
  return;
}

void ento::registerConditionChecker(CheckerManager &mgr) {
  mgr.registerChecker<ConditionChecker>();
}

bool ento::shouldRegisterConditionChecker(const LangOptions &LO) {
  return true;
}
