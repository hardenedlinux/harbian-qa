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

bool searchCondVar(const SourceManager &SM, const Stmt *s, std::vector<stmtInfo> *info) {
  stmtInfo tmpInfo;
  switch (s->getStmtClass()) {
  case Stmt::DeclStmtClass: {
    const DeclStmt *DS = dyn_cast<DeclStmt>(s);
    if (DS->isSingleDecl()) {
      const ValueDecl *VD = nullptr;
      VD = dyn_cast<ValueDecl>(DS->getSingleDecl());
      if (VD != NULL) {
	if (VD->getKind() == Decl::ParmVar) {
	  const ParmVarDecl *PV = dyn_cast<ParmVarDecl>(VD);
	  /* [ParmVar] ID-VAR_ID VAR_TYPE VAR_NAME */
	  tmpInfo.init("ParmVar", PV->getID(), PV->getType().getAsString()+ VD->getNameAsString(), "", "");
	  info->push_back(tmpInfo);
	}
      }
    }
    return false;
  }
  case Stmt::DeclRefExprClass: {
    const DeclRefExpr *DR = dyn_cast<DeclRefExpr>(s);
    if (DR != NULL) {
      const ValueDecl *VD = nullptr;
      VD = dyn_cast<ValueDecl>(DR->getDecl());
      if (VD != NULL) {
	if (VD->getKind() == Decl::ParmVar) {
	  const ParmVarDecl *PV = dyn_cast<ParmVarDecl>(VD);
	  /* [ParmVar] ID-VAR_ID VAR_TYPE VAR_NAME */
	  tmpInfo.init("ParmVar", PV->getID(), PV->getType().getAsString() + " " + VD->getNameAsString(), "", "");
	  return false;
	} else {
	  tmpInfo.init("DeclRefExpr", VD->getID(), VD->getType().getAsString() + " " + VD->getNameAsString(), "", "");
	}
	info->push_back(tmpInfo);
      }
    }
    return false;
  }
  case Stmt::MemberExprClass: {
    const MemberExpr *ME = dyn_cast<MemberExpr>(s);
    const Expr *BE = ME->getBase();
    const QualType BT = BE->getType(), MT = ME->getType();
    /* [MemExpr] struct BASE_STRUCTURE -> strcut MEMBER_STRUCTURE MEMBER_NAME */
    tmpInfo.init("MemExpr", ME->getMemberDecl()->getID(), MT.getAsString() + " " + ME->getMemberDecl()->getNameAsString(), BT.getAsString(), "");
    info->push_back(tmpInfo);
    return false;
  }
  case Stmt::BinaryOperatorClass: {
    const BinaryOperator *BO = dyn_cast<BinaryOperator>(s);
    std::string opcodeStr = BO->getOpcodeStr();
    if (opcodeStr == "==" || opcodeStr == "!=" || opcodeStr == "<" || opcodeStr == ">") {
      const Expr *LHS = BO->getLHS(), *RHS = BO->getRHS();
      char LID[0x20] = "unknown", RID[0x20] = "unknown";
      if (LHS != nullptr) {
	if (LHS->getStmtClass() == Stmt::DeclRefExprClass) {
	  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(LHS);
	  const ValueDecl *VD = DRE->getDecl();
	  sprintf(LID, "0x%x", VD->getID());
	}
	/* Most of time, variable appeal as left var */
	if (LHS->getStmtClass() == Stmt::ImplicitCastExprClass) {
	  const ImplicitCastExpr *ICE = dyn_cast<ImplicitCastExpr>(LHS);
	  const Expr *subExpr = ICE->getSubExpr();
	  if (subExpr->getStmtClass() == Stmt::MemberExprClass) {
	    const MemberExpr *ME = dyn_cast<MemberExpr>(subExpr);
	    sprintf(LID, "m-0x%x", ME->getMemberDecl()->getID());
	  } else if (subExpr->getStmtClass() == Stmt::DeclRefExprClass) {
	    const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(subExpr);
	      sprintf(LID, "d-0x%x", DRE->getDecl()->getID());
	  }
	}
      }
      if (RHS != nullptr) {
	if (RHS->getStmtClass() == Stmt::DeclRefExprClass) {
	  const DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(RHS);
	  const ValueDecl *VD = DRE->getDecl();
	  sprintf(RID, "0x%x", VD->getID());
	}
      }
      tmpInfo.init("BinaryOperator", 0, std::string(LID) + " " + opcodeStr + " " + std::string(RID), "", "");
      info->push_back(tmpInfo);
    }
      return false;
  }
  case Stmt::IntegerLiteralClass: {
    const IntegerLiteral *IL = dyn_cast<IntegerLiteral>(s);
    std::string valueString = std::to_string(IL->getValue().getLimitedValue(UINT64_MAX));
    tmpInfo.init(s->getStmtClassName(), 0, valueString , "", "");
    info->push_back(tmpInfo);
    return false;
  }
  case Stmt::ImplicitCastExprClass: {
    const ImplicitCastExpr *ICE = dyn_cast<ImplicitCastExpr>(s);
    if (ICE->getCastKind() == CK_FunctionToPointerDecay) {
      const Expr* subExpr = ICE->getSubExpr();
      if (subExpr->getStmtClass() == Stmt::DeclRefExprClass) {
	const ValueDecl* VD = dyn_cast<DeclRefExpr>(subExpr)->getDecl();
	if (VD != nullptr) {
	  tmpInfo.init(ICE->getCastKindName(), VD->getID(), VD->getType().getAsString() + " " + VD->getNameAsString(), "", "");
	  info->push_back(tmpInfo);
	}
      }
    }
    return false;
  }
  default: {return false;}
  }

  return false;
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
    tmpInfo.init("MemExpr", ME->getMemberDecl()->getID(), MT.getAsString() + " " + ME->getMemberDecl()->getNameAsString(), BT.getAsString(), "");
    info->push_back(tmpInfo);
    return false;
  }
  case Stmt::ImplicitCastExprClass: {
    stmtInfo tmpInfo;
    const ImplicitCastExpr *ICE = dyn_cast<ImplicitCastExpr>(s);
    if (ICE->getCastKind() == CK_FunctionToPointerDecay) {
      const Expr* subExpr = ICE->getSubExpr();
      if (subExpr->getStmtClass() == Stmt::DeclRefExprClass) {
	const ValueDecl* VD = dyn_cast<DeclRefExpr>(subExpr)->getDecl();
	if (VD != nullptr) {
	  tmpInfo.init(ICE->getCastKindName(), VD->getID(), VD->getType().getAsString() + " " + VD->getNameAsString(), "", "");
	  info->push_back(tmpInfo);
	}
      }
    }
  }
  default: {return false;}
  }

  if (VD != NULL) {
    if (VD->getKind() == Decl::ParmVar) {
      const ParmVarDecl *PV = dyn_cast<ParmVarDecl>(VD);
      stmtInfo tmpInfo;
      /* [ParmVar] ID-VAR_ID VAR_TYPE VAR_NAME */
      tmpInfo.init("ParmVar", PV->getID(), PV->getType().getAsString() + " " + VD->getNameAsString(), "", "");
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

  if (s->getStmtClass() == Stmt::IfStmtClass) {
    const IfStmt *IS = dyn_cast<IfStmt>(s);
    condStart = IS->getBeginLoc();
    condEnd = IS->getThen()->getBeginLoc();
    subStmt = dyn_cast<Stmt>(IS->getCond());
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
    handleChildrenStmt(SM, subStmt, searchCondVar, info);
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
       * Macro statment and extern function will not be parse
       */
      //if(SM.isInMainFile(SM.getSpellingLoc(c->getBeginLoc()))) {
	handleChildrenStmt(SM, c, handle, info);
	// }
    }
  }
}

void handleRegion(const MemRegion *MR, std::vector<symInfo> *SymbolInfo) {
  switch(MR->getKind()) {
    /* FieldRegion: information of member access operation */
  case MemRegion::FieldRegionKind: {
    const FieldRegion *FR = dyn_cast<FieldRegion>(MR);
    if (FR != nullptr) {
      const MemRegion *SMR = FR->getSuperRegion();
      const TypedValueRegion *tmpTVR = dyn_cast<TypedValueRegion>(SMR);
      const SymbolicRegion *SR = SMR->getSymbolicBase();
      if (SR == nullptr) {return;}
      SymbolRef tmpSym = SR->getSymbol();
      symInfo tmpSymInfo;
      std::string tmpStr = "";
      /* superRegion have another symbol, may need parse */
      if (tmpSym->getKind() == SymExpr::SymbolRegionValueKind) {
	const SymbolRegionValue *SRV = dyn_cast<SymbolRegionValue>(tmpSym);
	/* no subMemRegion in superRegion, use Symbol in superRegion */
	if (tmpTVR == nullptr) {
	  tmpStr = tmpStr.append(SRV->getType().getAsString());
	}
      }
      /* there is subMemRegion have to be parsed */
      if (tmpTVR != nullptr) {
	handleRegion(tmpTVR, SymbolInfo);
	tmpStr = tmpStr.append(tmpTVR->getValueType().getAsString());
      }
      /* information of member access operation */
      const FieldDecl *FD = dyn_cast<FieldDecl>(FR->getDecl());
      if (FD != nullptr) {
	tmpStr = tmpStr.append("->" + FD->getType().getAsString() + " " + FD->getNameAsString());
	tmpSymInfo.init("MemSymbol", 0, tmpStr);
	SymbolInfo->push_back(tmpSymInfo);
      }
    }
    break;
  }
  case MemRegion::VarRegionKind: {
    const DeclRegion *DR = dyn_cast<DeclRegion>(MR->getBaseRegion());
    if (DR != nullptr) {
      const VarDecl *VD = dyn_cast<VarDecl>(DR->getDecl());
      if (VD != nullptr) {
	symInfo tmpSymInfo;
	//llvm::outs() << "VarRegion: " << VD->getType().getAsString() << " " << VD->getNameAsString() << "\n";
	tmpSymInfo.init("VarSymbol", 0, VD->getType().getAsString() + " " + VD->getNameAsString());
	SymbolInfo->push_back(tmpSymInfo);
      }
    }
    break;
  }
  case MemRegion::ElementRegionKind: {
    const ElementRegion *ER = dyn_cast<ElementRegion>(MR);
    const MemRegion *SMR = ER->getSuperRegion();
    std::string castBase = "";
    symInfo tmpSymInfo;
    if (SMR->getKind() == MemRegion::SymbolicRegionKind) {
      SymbolRef tmpSR = dyn_cast<SymbolicRegion>(SMR)->getSymbol();
      castBase = tmpSR->getType().getAsString();
    }
    /* Element means type casting or array access */
    tmpSymInfo.init("ElementCast", 0, "(" + ER->getElementType().getAsString() + ")" + castBase);
    SymbolInfo->push_back(tmpSymInfo);
    handleRegion(SMR, SymbolInfo);
    break;
  }
  case MemRegion::SymbolicRegionKind: {
    const SymbolicRegion *SymRegion = dyn_cast<SymbolicRegion>(MR);
    SymbolRef SymRef = SymRegion->getSymbol();
    parseSymExpr(SymRef, SymbolInfo);
    break;
  }
  default: {break;}
  }
}

void parseSymExpr(const SymExpr *s, std::vector<symInfo> *SymbolInfo) {
  switch(s->getKind()) {
    /* IntSymExpr/SymIntExpr/SymIntExpr means binaryOperator between Int and Sym
       Most of time, Int is mask.
    */
  case SymExpr::IntSymExprKind: {
    symInfo tmpSymInfo;
    const IntSymExpr *ISE = dyn_cast<IntSymExpr>(s);
    if (ISE != nullptr) {
      const SymExpr *RHS = ISE->getRHS();
      if (RHS != nullptr) {
	parseSymExpr(RHS, SymbolInfo);
      }
      // TODO: ISE->getOpcode()
      tmpSymInfo.init("IntSymExpr", 0, ISE->getLHS().toString(0x10));
      SymbolInfo->push_back(tmpSymInfo);
    }
    break;
  }
  case SymExpr::SymIntExprKind: {
    symInfo tmpSymInfo;
    const SymIntExpr *SIE = dyn_cast<SymIntExpr>(s);
    if (SIE != nullptr) {
      const SymExpr *LHS = SIE->getLHS();
      if (LHS != nullptr) {
	parseSymExpr(LHS, SymbolInfo);
      }
      // TODO: SIE->getOpcode() << "\n";
      tmpSymInfo.init("SymIntExpr", 0, SIE->getRHS().toString(0x10));
      SymbolInfo->push_back(tmpSymInfo);
    }
    break;
  }
  case SymExpr::SymSymExprKind: {
    const SymSymExpr *SSE = dyn_cast<SymSymExpr>(s);
    if (SSE != nullptr) {
      const SymExpr *LHS = SSE->getLHS(), *RHS = SSE->getRHS();
      if (LHS != nullptr) {
	parseSymExpr(LHS, SymbolInfo);
      }
      if (RHS != nullptr) {
	parseSymExpr(RHS, SymbolInfo);
      }
      // TODO: SIE->getOpcode() << "\n";
    }
    break;
  }
  case SymExpr::SymbolDerivedKind: {
    const SymbolDerived *SD = dyn_cast<SymbolDerived>(s);
    SymbolRef paSR = SD->getParentSymbol();
    //llvm::outs() << "Derived: ";
    parseSymExpr(paSR, SymbolInfo);
    handleRegion(SD->getRegion(), SymbolInfo);
    break;
  }
  case SymExpr::SymbolConjuredKind: {
    break;
  }
  case SymExpr::SymbolExtentKind: {
    const SymbolExtent *SE = dyn_cast<SymbolExtent>(s);
    //llvm::outs() << "Extent: \n";
    if (SE != nullptr) {
      const MemRegion *SEM = SE->getRegion();
      if (SEM->getKind() == MemRegion::SymbolicRegionKind) {
	const SymbolicRegion *tmpSym = dyn_cast<SymbolicRegion>(SEM);
	if (tmpSym != nullptr) {
	  parseSymExpr(tmpSym->getSymbol(), SymbolInfo);
	}
      }
    }
    break;
  }
  case SymExpr::SymbolMetadataKind: {
    const SymbolMetadata *SMD = dyn_cast<SymbolMetadata>(s);
    symInfo tmpSymInfo;
    tmpSymInfo.init("Meta", 0, SMD->getType().getAsString());
    SymbolInfo->push_back(tmpSymInfo);
    const MemRegion *MDM = SMD->getRegion();
    if (MDM->getKind() == MemRegion::SymbolicRegionKind) {
      const SymbolicRegion *tmpSym = dyn_cast<SymbolicRegion>(MDM);
      if (tmpSym != nullptr) {
	parseSymExpr(tmpSym->getSymbol(), SymbolInfo);
      }
    }
    break;
  }
    /* SymbolRegionValue's MemRegion include information of symbol */
  case SymExpr::SymbolRegionValueKind: {
    const SymbolRegionValue *SRV = dyn_cast<SymbolRegionValue>(s);
    if (SRV != nullptr) {
      const TypedValueRegion *TVR = SRV->getRegion();
      if (TVR != nullptr) {
	handleRegion(dyn_cast<MemRegion>(TVR), SymbolInfo);
      }
    }
    break;
  }
  default: {return;}
  }
  return;
}
