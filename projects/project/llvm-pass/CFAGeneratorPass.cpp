#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/CFG.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/Support/raw_ostream.h"

#include <map>
#include <vector>
#include <set>
#include <fstream>
#include <iostream>
#include <cstdlib>
#include <functional>

using namespace llvm;

namespace {
  // Per-loop metadata exported to policy JSON and consumed by monitor loop folding.
  struct LoopPolicyEntry {
    int depth;
    int header;
    std::vector<int> body;
    std::vector<int> exits;
  };

  struct CFAPolicy {
    std::map<std::pair<int, int>, int> EdgeTable;
    std::map<int, LoopPolicyEntry> LoopTable;
    std::map<int, std::vector<int>> CallReturnTable;
  };

  struct CFAGeneratorPass : public PassInfoMixin<CFAGeneratorPass> {
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM) {
      int bbid_counter = 1;
      int edge_counter = 1;
      int loop_counter = 1;

      // 1) Split blocks after calls so call and return-site transitions are explicit.
      std::vector<CallBase*> CallsToSplit;
      for (Function &F : M) {
        if (F.isDeclaration() || F.getName() == "cfa_bb_enter") continue;
        for (BasicBlock &BB : F) {
          for (Instruction &I : BB) {
            if (auto *CB = dyn_cast<CallBase>(&I)) {
              if (CB->getCalledFunction() && CB->getCalledFunction()->getName() == "cfa_bb_enter") continue;
              if (CB->isInlineAsm()) continue;
              // Intrinsics do not represent control-flow edges in attested policy.
              if (CB->getCalledFunction() && CB->getCalledFunction()->isIntrinsic()) continue;
              CallsToSplit.push_back(CB);
            }
          }
        }
      }
      for (auto *CB : CallsToSplit) {
        if (!CB->isTerminator()) {
          BasicBlock *OldBB = CB->getParent();
          OldBB->splitBasicBlock(CB->getNextNode(), "call.ret");
        }
      }

      std::map<BasicBlock*, int> BBMap;
      CFAPolicy Policy;
      bool Modified = false;

      errs() << "CFA Generator Pass: Processing module " << M.getName() << "\n";

      LLVMContext &Ctx = M.getContext();
      // Runtime instrumentation hook consumed by monitor trap handler.
      FunctionType *FuncType = FunctionType::get(Type::getVoidTy(Ctx), {Type::getInt32Ty(Ctx), Type::getInt32Ty(Ctx)}, false);
      FunctionCallee CFAFunc = M.getOrInsertFunction("cfa_bb_enter", FuncType);
        bool EnableBranchProbe = std::getenv("CFA_BRANCH_TRACE_PROTO") != nullptr;
        FunctionType *ProbeTy = FunctionType::get(Type::getVoidTy(Ctx), {Type::getInt32Ty(Ctx)}, false);
        InlineAsm *BranchProbeAsm = InlineAsm::get(
          ProbeTy,
          "mv t0, $0\n\tli t1, 128\n\tebreak",
          "r,~{t0},~{t1}", true);

      // 2) Assign stable BB IDs before policy extraction/instrumentation.
      for (Function &F : M) {
        if (F.isDeclaration() || F.getName() == "cfa_bb_enter") continue;
        for (BasicBlock &BB : F) {
          int bbid = bbid_counter++;
          BBMap[&BB] = bbid;
        }
      }

      std::map<int, int> BBTypes; 
      std::map<int, int> CallReturns; 
      std::map<int, std::vector<int>> IndirectTargets; 

      // Conservative target set for unresolved indirect calls.
      std::vector<int> AddressTakenFuncEntryBBs;
      for (Function &F : M) {
        if (F.isDeclaration() || F.getName() == "cfa_bb_enter") continue;
        if (F.hasAddressTaken()) {
          AddressTakenFuncEntryBBs.push_back(BBMap[&F.getEntryBlock()]);
        }
      }

      auto &FAM = AM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();

      std::function<void(LoopInfo&, int&)> collectLoops;
      collectLoops = [&](LoopInfo &LIRef, int &counterRef) {
        std::function<void(Loop*)> visitLoop;
        visitLoop = [&](Loop *L) {
          errs() << "Loop: " << L->getHeader()->getName() << "\n";
          int loop_id = counterRef++;
          std::vector<int> body_edges;
          std::vector<int> exit_edges;

          SmallVector<BasicBlock *, 8> Exits;
          L->getExitBlocks(Exits);
          std::set<BasicBlock*> ExitSet(Exits.begin(), Exits.end());

          for (BasicBlock *BB : L->getBlocks()) {
            int src_id = BBMap[BB];
            Instruction *Term = BB->getTerminator();
            if (!Term) continue;
            for (unsigned i = 0; i < Term->getNumSuccessors(); ++i) {
              BasicBlock *Succ = Term->getSuccessor(i);
              int dst_id = BBMap[Succ];
              if (Policy.EdgeTable.count({src_id, dst_id})) {
                int edge_id = Policy.EdgeTable[{src_id, dst_id}];
                if (ExitSet.count(Succ)) {
                  exit_edges.push_back(edge_id);
                } else if (L->contains(Succ)) {
                  body_edges.push_back(edge_id);
                }
              }
            }
          }

          Policy.LoopTable[loop_id] = {
              static_cast<int>(L->getLoopDepth()),
              BBMap[L->getHeader()],
              body_edges,
              exit_edges,
          };

          for (Loop *Sub : L->getSubLoops()) {
            visitLoop(Sub);
          }
        };

        for (Loop *TopLevel : LIRef) {
          visitLoop(TopLevel);
        }
      };

      // 3) Extract edge policy, block types, call-return links, and loop metadata.
      for (Function &F : M) {
        if (F.isDeclaration() || F.getName() == "cfa_bb_enter") continue;
        LoopInfo &LI = FAM.getResult<LoopAnalysis>(F);

        for (BasicBlock &BB : F) {
          int src_id = BBMap[&BB];
          Instruction *Term = BB.getTerminator();
          if (!Term) continue;

          // Detect a call in the instruction immediately before the terminator.
          CallBase *CB = nullptr;
          if (Term->getPrevNode() && isa<CallBase>(Term->getPrevNode())) {
             CB = dyn_cast<CallBase>(Term->getPrevNode());
          }
           // Also handle call-like terminators directly (e.g., callbr).
           if (!CB && isa<CallBase>(Term)) {
             CB = dyn_cast<CallBase>(Term);
           }

          if (CB && !CB->isInlineAsm() && !(CB->getCalledFunction() && CB->getCalledFunction()->getName() == "cfa_bb_enter") && !(CB->getCalledFunction() && CB->getCalledFunction()->isIntrinsic())) {
              // Tail calls do not return to the local return-site block.
              if (CB->isTailCall()) {
               BasicBlock *RetBB = Term->getNumSuccessors() > 0 ? Term->getSuccessor(0) : nullptr;
                 if (Function *TargetF = CB->getCalledFunction()) {
                if (!TargetF->isDeclaration() && !TargetF->empty()) {
                  BBTypes[src_id] = 1; // Direct tail call
                        int callee_id = BBMap[&TargetF->getEntryBlock()];
                        Policy.EdgeTable[{src_id, callee_id}] = edge_counter++;
                } else if (RetBB) {
                  // Optimized tail-call to external function can still
                  // branch to a local return block in IR.
                  BBTypes[src_id] = 0;
                  int ret_id = BBMap[RetBB];
                  Policy.EdgeTable[{src_id, ret_id}] = edge_counter++;
                } else {
                  BBTypes[src_id] = 1;
                    }
                 } else {
                    BBTypes[src_id] = 3; // Indirect tail call
                    for (int target_id : AddressTakenFuncEntryBBs) {
                        IndirectTargets[src_id].push_back(target_id);
                        // Explicitly add indirect targets to edge policy.
                        Policy.EdgeTable[{src_id, target_id}] = edge_counter++;
                    }
                 }
                  // No call-return relation is emitted for tail calls.
                 continue;
              }

              BasicBlock *RetBB = Term->getSuccessor(0);
              if (Function *TargetF = CB->getCalledFunction()) {
                 if (!TargetF->isDeclaration() && !TargetF->empty()) {
                   BBTypes[src_id] = 1; // Direct Call
                   CallReturns[src_id] = BBMap[RetBB];
                   int callee_id = BBMap[&TargetF->getEntryBlock()];
                   Policy.EdgeTable[{src_id, callee_id}] = edge_counter++;
                 } else {
                   // External call target is not instrumented; model as fallthrough.
                   int ret_id = BBMap[RetBB];
                   BBTypes[src_id] = 0;
                   Policy.EdgeTable[{src_id, ret_id}] = edge_counter++;
                 }
              } else {
                 BBTypes[src_id] = 3; // Indirect Call
                 CallReturns[src_id] = BBMap[RetBB];
                 for (int target_id : AddressTakenFuncEntryBBs) {
                     IndirectTargets[src_id].push_back(target_id);
                     // Explicitly add indirect targets to edge policy.
                     Policy.EdgeTable[{src_id, target_id}] = edge_counter++;
                 }
              }
                  continue; // Return edge is validated by monitor shadow-stack logic.
          }

          if (isa<ReturnInst>(Term)) {
              BBTypes[src_id] = 2; // Return
              continue;
          }

          // Inline assembly branches are treated as opaque control-flow.
          if (CB && CB->isInlineAsm()) {
              if (InlineAsm *IA = dyn_cast<InlineAsm>(CB->getCalledOperand())) {
                  std::string AsmStr = IA->getAsmString().str();
                  if (AsmStr.find("j ") != std::string::npos ||
                      AsmStr.find("jr ") != std::string::npos ||
                      AsmStr.find("jal ") != std::string::npos ||
                      AsmStr.find("jalr ") != std::string::npos ||
                      AsmStr.find("ret") != std::string::npos ||
                      AsmStr.find("tail ") != std::string::npos) {
                      BBTypes[src_id] = 5; // INLINE_ASM_BRANCH
                      errs() << "CFA WARNING: Inline asm with branch in BB " << src_id
                             << " (" << F.getName() << "): " << AsmStr << "\n";
                        // Opaque branch block: skip successor-based policy extraction.
                      continue;
                  }
              }
          }

          if (isa<IndirectBrInst>(Term)) {
              BBTypes[src_id] = 4; // Indirect Jump
              IndirectBrInst *IBR = cast<IndirectBrInst>(Term);
              for (unsigned i = 0; i < IBR->getNumDestinations(); ++i) {
                  int dst_id = BBMap[IBR->getDestination(i)];
                  IndirectTargets[src_id].push_back(dst_id);
                  // Explicitly add indirect jump destinations to edge policy.
                  Policy.EdgeTable[{src_id, dst_id}] = edge_counter++;
              }
              continue;
          }

              // Handle callbr (asm goto / label addresses) as indirect jump.
              if (auto *CBR = dyn_cast<CallBrInst>(Term)) {
                BBTypes[src_id] = 4; // Indirect Jump
                int def_id = BBMap[CBR->getDefaultDest()];
                IndirectTargets[src_id].push_back(def_id);
                Policy.EdgeTable[{src_id, def_id}] = edge_counter++;
                for (unsigned i = 0; i < CBR->getNumIndirectDests(); ++i) {
                  int dst_id = BBMap[CBR->getIndirectDest(i)];
                  IndirectTargets[src_id].push_back(dst_id);
                  Policy.EdgeTable[{src_id, dst_id}] = edge_counter++;
                }
                continue;
              }

          // Treat switch dispatch as a constrained indirect jump.
          if (SwitchInst *SI = dyn_cast<SwitchInst>(Term)) {
              BBTypes[src_id] = 4; // Treat switch as indirect jump
              // Default destination
              int def_id = BBMap[SI->getDefaultDest()];
              IndirectTargets[src_id].push_back(def_id);
              Policy.EdgeTable[{src_id, def_id}] = edge_counter++;
              // Case destinations
              for (auto Case : SI->cases()) {
                  int case_id = BBMap[Case.getCaseSuccessor()];
                  IndirectTargets[src_id].push_back(case_id);
                  Policy.EdgeTable[{src_id, case_id}] = edge_counter++;
              }
              continue;
          }

          BBTypes[src_id] = 0; // Normal
          for (unsigned i = 0; i < Term->getNumSuccessors(); ++i) {
            BasicBlock *Succ = Term->getSuccessor(i);
            int dst_id = BBMap[Succ];
            int edge_id = edge_counter++;
            Policy.EdgeTable[{src_id, dst_id}] = edge_id;
          }
        }

        collectLoops(LI, loop_counter);
      }

      // 4) Insert per-BB instrumentation call with block role flags.
      for (Function &F : M) {
        if (F.isDeclaration() || F.getName() == "cfa_bb_enter" || F.getName() == "setup_uart") continue;
        for (BasicBlock &BB : F) {
          int bbid = BBMap[&BB];
          // Runtime flag consumed by monitor to drive call/return validation.
          int flags = 0;
          if (BBTypes.count(bbid)) {
            int bbt = BBTypes[bbid];
            if (bbt == 1 || bbt == 3) flags = 1;
            else if (bbt == 2) flags = 2;
          }
          IRBuilder<> Builder(&*BB.getFirstInsertionPt());
          Value *Args[] = {
            ConstantInt::get(Type::getInt32Ty(Ctx), bbid),
            ConstantInt::get(Type::getInt32Ty(Ctx), flags)
          };
          Builder.CreateCall(CFAFunc, Args);

          if (EnableBranchProbe) {
            Instruction *Term = BB.getTerminator();
            if (Term && !isa<ReturnInst>(Term)) {
              IRBuilder<> TermBuilder(Term);
              Value *ProbeArg[] = {
                ConstantInt::get(Type::getInt32Ty(Ctx), bbid)
              };
              TermBuilder.CreateCall(BranchProbeAsm, ProbeArg);
            }
          }
          Modified = true;
        }
      }

      std::ofstream Out("cfa_policy.json");
      Out << "{\n  \"edges\": [\n";
      bool first = true;
      for (auto &E : Policy.EdgeTable) {
        if (!first) Out << ",\n";
        Out << "    {\"src\": " << E.first.first << ", \"dst\": " << E.first.second << ", \"id\": " << E.second << "}";
        first = false;
      }
      Out << "\n  ],\n  \"loops\": [\n";
      first = true;
      for (auto &L : Policy.LoopTable) {
        if (!first) Out << ",\n";
        Out << "    {\"id\": " << L.first << ", \"depth\": " << L.second.depth << ", \"header\": " << L.second.header << ", \"body\": [";
        for (size_t i=0; i<L.second.body.size(); ++i) Out << L.second.body[i] << (i+1 < L.second.body.size() ? ", " : "");
        Out << "], \"exits\": [";
        for (size_t i=0; i<L.second.exits.size(); ++i) Out << L.second.exits[i] << (i+1 < L.second.exits.size() ? ", " : "");
        Out << "]}";
        first = false;
      }
      
      Out << "\n  ],\n  \"bb_types\": [\n";
      first = true;
      for (auto &KV : BBTypes) {
        if (!first) Out << ",\n";
        Out << "    {\"bbid\": " << KV.first << ", \"type\": " << KV.second << "}";
        first = false;
      }

      Out << "\n  ],\n  \"call_returns\": [\n";
      first = true;
      for (auto &KV : CallReturns) {
        if (!first) Out << ",\n";
        Out << "    {\"src\": " << KV.first << ", \"ret\": " << KV.second << "}";
        first = false;
      }

      Out << "\n  ],\n  \"indirect_targets\": [\n";
      first = true;
      for (auto &KV : IndirectTargets) {
        if (!first) Out << ",\n";
        Out << "    {\"src\": " << KV.first << ", \"targets\": [";
        for (size_t i=0; i<KV.second.size(); ++i) Out << KV.second[i] << (i+1 < KV.second.size() ? ", " : "");
        Out << "]}";
        first = false;
      }

      Out << "\n  ]\n}\n";
      Out.close();

      return Modified ? PreservedAnalyses::none() : PreservedAnalyses::all();
    }
  };
}

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK llvmGetPassPluginInfo() {
  return {
    LLVM_PLUGIN_API_VERSION, "CFAGeneratorPass", "v0.1",
    [](PassBuilder &PB) {
      PB.registerPipelineParsingCallback(
        [](StringRef Name, ModulePassManager &MPM, ArrayRef<PassBuilder::PipelineElement>) {
          if (Name == "cfa-gen") {
            MPM.addPass(CFAGeneratorPass());
            return true;
          }
          return false;
        });
      PB.registerOptimizerLastEPCallback(
        [](ModulePassManager &MPM, OptimizationLevel Level, ThinOrFullLTOPhase Phase) {
          MPM.addPass(CFAGeneratorPass());
        });
    }
  };
}
