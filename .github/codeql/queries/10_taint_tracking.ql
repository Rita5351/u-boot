/**
 * @name Vulnerabilita Network Byte Swap (U-Boot)
 * @description Un attaccante puo causare un buffer overflow tramite dati di rete non validati.
 * @kind path-problem
 * @problem.severity critical
 * @id cpp/uboot/network-taint-memcpy
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking

class NetworkByteSwap extends Expr {
    NetworkByteSwap () {
        exists(MacroInvocation mac |
            mac.getMacro().getName().matches("ntoh%")
            and this = mac.getExpr()
        )
    }
}

module TaintConfig implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node source) {
        source.asExpr() instanceof NetworkByteSwap
    }

    predicate isSink(DataFlow::Node sink) {
        exists(FunctionCall memc |
            memc.getTarget().getName()="memcpy" 
            and sink.asExpr() = memc.getArgument(2)
        )
    }

    // --- EXTRA TASK: BARRIERA DI SANIFICAZIONE ---
    predicate isBarrier(DataFlow::Node node) {
        // Se il nodo si trova all'interno di uno statement 'if', blocca il taint tracking
        exists(IfStmt ifs | node.asExpr().getEnclosingStmt().getParentStmt*() = ifs)
    }
}

module TaintFlow = TaintTracking::Global<TaintConfig>;
import TaintFlow::PathGraph

from TaintFlow::PathNode source, TaintFlow::PathNode sink
where TaintFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Network byte swap flows to memcpy"