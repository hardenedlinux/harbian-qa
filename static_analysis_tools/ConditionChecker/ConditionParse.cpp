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

/* Get the source line from SourceLoation */
std::string srcLineToString(const SourceManager &SM, SourceLocation SRs, SourceLocation SRe) {
  std::string tmp;
  SourceLocation SSRs = SM.getSpellingLoc(SRs), SSRe = SM.getSpellingLoc(SRe);

  if (SSRs.isInvalid() && SSRe.isInvalid()) {
    tmp = "Wrong SourceLocation";
  }
  else if (SM.getFileOffset(SSRs) > SM.getFileOffset(SSRe)) {
    tmp = "SourceLocation is mismatch";
  }
  else if (SM.isInMainFile(SSRs) > SM.isInMainFile(SSRe)) {
    tmp = "SourceLocation is not in main file";
  }
  else {
    tmp = SM.getBufferData(SM.getFileID(SSRs), NULL);
    tmp = tmp.substr(SM.getFileOffset(SSRs), SM.getFileOffset(SSRe)-SM.getFileOffset(SSRs));
  }
  return tmp;
}

stmtInfo FuncInfo(const FunctionDecl *FD) {
  stmtInfo fdInfo;
  fdInfo.init("Function", FD->getID(), FD->getNameInfo().getAsString(), "", "");
  return fdInfo;
}

/* List the parameters of a function from FunctionDecl */
std::vector<stmtInfo> ListAllParmInfo(const SourceManager &SM, const FunctionDecl *FD) {
  std::vector<stmtInfo> FuncParmList;
  for (ParmVarDecl *p : FD->parameters()) {
    /* SourceRange ParmSR = p->getSourceRange();
     *  srcLineToString(SM, ParmSR.getBegin(), ParmSR.getEnd())
     */
    stmtInfo tmpParmInfo;
    tmpParmInfo.init("ParmVar", p->getID(), p->getType().getAsString() + p->getNameAsString(), "", "");
    FuncParmList.push_back(tmpParmInfo);
  }
  return FuncParmList;
}

/* Callback handle function for ParmVar and MemberExpr statement*/
bool searchParm(const SourceManager &SM, const Stmt *s, std::vector<stmtInfo> *info) {
  const ValueDecl *VD = nullptr;
  switch (s->getStmtClass()) {
  case Stmt::DeclStmtClass: {
    const DeclStmt *DS = dyn_cast<DeclStmt>(s);
    if (DS->isSingleDecl()) {
      VD = dyn_cast<ValueDecl>(DS->getSingleDecl());
    }
    break;
  }
  case Stmt::DeclRefExprClass: {
    const DeclRefExpr *DR = dyn_cast<DeclRefExpr>(s);
    if (DR != NULL) {
      VD = dyn_cast<ValueDecl>(DR->getDecl());
    }
    break;
  }
  case Stmt::MemberExprClass: {
    const MemberExpr *ME = dyn_cast<MemberExpr>(s);
    const Expr *BE = ME->getBase();
    const QualType BT = BE->getType(), MT = ME->getType();
    /* [MemExpr] struct BASE_STRUCTURE -> strcut MEMBER_STRUCTURE MEMBER_NAME */
    stmtInfo tmpInfo;
    tmpInfo.init("MemExpr", 0, MT.getAsString() + " " + ME->getMemberDecl()->getNameAsString(), BT.getAsString(), "");
    info->push_back(tmpInfo);
    return false;
  }
  default: {return false;}
  }

  if (VD != NULL) {
    if (VD->getKind() == Decl::ParmVar) {
      const ParmVarDecl *PV = dyn_cast<ParmVarDecl>(VD);
      stmtInfo tmpInfo;
      /* [ParmVar] ID-VAR_ID VAR_TYPE VAR_NAME */
      tmpInfo.init("ParmVar", PV->getID(), PV->getType().getAsString()+ VD->getNameAsString(), "", "");
      info->push_back(tmpInfo);
      return false;
    }
  }
  return false;
}

/* Pick out local variables whick its initialization has any parameters */
bool searchLocalVar(const SourceManager &SM, const Stmt *s, std::vector<stmtInfo> *info) {
  std::vector<stmtInfo> tmpInfo;
  const ValueDecl *VD = nullptr;
  /* Local variable handle, 
   * every case will call handleChildrenStmt(,,searchParm,)
   * to check if there is any ParmVar in the substatement.
   */
  switch (s->getStmtClass()) {
  case Stmt::DeclRefExprClass: {
    const DeclRefExpr *DR = dyn_cast<DeclRefExpr>(s);
    if (DR != NULL) {
      VD = dyn_cast<ValueDecl>(DR->getDecl());
    }
    for (const Stmt *c : s->children()) {
      handleChildrenStmt(SM, c, searchParm, &tmpInfo);
    }
    break;
  }
  case Stmt::DeclStmtClass: {
    const DeclStmt *DS = dyn_cast<DeclStmt>(s);
    if (DS->isSingleDecl()) {
      VD = dyn_cast<ValueDecl>(DS->getSingleDecl());
    }
    for (const Stmt *c : s->children()) {
      handleChildrenStmt(SM, c, searchParm, &tmpInfo);
    }
    break;
  }
  case Stmt::BinaryOperatorClass: {
    const BinaryOperator *BO = dyn_cast<BinaryOperator>(s);
    if (BO->getOpcodeStr() == "=") {
      if (BO->getLHS()->getStmtClass() ==  Stmt::DeclRefExprClass) {
	const DeclRefExpr *DR = dyn_cast<DeclRefExpr>(BO->getLHS());
	if (DR != NULL) {
	  VD = dyn_cast<ValueDecl>(DR->getDecl());
	}
	for (const Stmt *c : s->children()) {
	  handleChildrenStmt(SM, c, searchParm, &tmpInfo);
	}
      }
    }
    break;
  }
  default: {return false;}
  }

  /* size > 0 means: has one or more ParmVar in the substatement */
  if (tmpInfo.size() > 0) {
    stmtInfo tmpVDInfo;
    if (VD != nullptr) {
      /* [LocalVar] (ID-LOCALVAR_ID) LOCALVAR_TYPE LOCALVAR_NAME*/
      tmpVDInfo.init("LocalVar", VD->getID(), VD->getType().getAsString(), "", srcLineToString(SM, s->getBeginLoc(), s->getEndLoc()));
    } else {
      /* If local variable ValueDecl can't be found, we use soureceline */
      tmpVDInfo.init("LovalVar", 0, "", "", srcLineToString(SM, s->getBeginLoc(), s->getEndLoc()));
      }
    info->push_back(tmpVDInfo);
    info->insert(info->end(), tmpInfo.begin(), tmpInfo.end());
    return true;
  }
  return false;
}

/* Callback handle function for if/while condition, list ParmVar and MemberExpr */
bool searchCondition(const SourceManager &SM, const Stmt *s, std::vector<stmtInfo> *info) {
  const Stmt *subStmt;
  SourceLocation condStart, condEnd;
  bool isConstexpr = false;

  if (s->getStmtClass() == Stmt::IfStmtClass) {
    const IfStmt *IS = dyn_cast<IfStmt>(s);
    condStart = IS->getBeginLoc();
    condEnd = IS->getThen()->getBeginLoc();
    subStmt = dyn_cast<Stmt>(IS->getCond());
    if (IS->isConstexpr()) {
      isConstexpr = true;
    }
  }else if (s->getStmtClass() == Stmt::WhileStmtClass) {
    const WhileStmt *WS = dyn_cast<WhileStmt>(s);
    condStart = WS->getBeginLoc();
    condEnd = WS->getBody()->getBeginLoc();
    subStmt = dyn_cast<Stmt>(WS->getCond());
  } else { 
    /* ForStmt condition is more complicated 
     * and most of its constrain is local variable
     */
    return false;
  }

  stmtInfo condInfo;
  condInfo.init("Condition", 0, "", "", srcLineToString(SM, condStart, condEnd));
  info->push_back(condInfo);
  /* search if there is any ParmVar in the condition statement */
  if (subStmt != NULL) {
    handleChildrenStmt(SM, subStmt, searchParm, info);
  }
  return false;
}

/* Recursively walk all children and collect information by handle function */
void handleChildrenStmt(const SourceManager &SM, const Stmt *s, stmtHandle handle, std::vector<stmtInfo> *info) {
  /* If handle return TRUE, stop walk thought children.
   * We should carefully use return in the handle function.
   */
  if (handle(SM, s, info)) {
    return;
  }
  for (const Stmt *c : s->children()) {
    if (c != NULL) {
      /* We only analyse main source file
       * Macro statment and inline function will not be parse
       */
      if(SM.isInMainFile(SM.getSpellingLoc(c->getBeginLoc()))) {
	handleChildrenStmt(SM, c, handle, info);
      }
    }
  }
}

