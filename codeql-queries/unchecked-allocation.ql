/**
 * @name Unchecked allocation used in buffer operation
 * @description Finds calls to malloc/calloc/realloc whose return value is used
 *              without a NULL check, risking null-pointer dereference.
 * @kind problem
 * @problem.severity error
 * @precision medium
 * @id xnuimagefuzzer/unchecked-allocation
 * @tags security memory correctness
 */

import cpp

from FunctionCall alloc, Expr use
where
  alloc.getTarget().hasName(["malloc", "calloc", "realloc"]) and
  exists(LocalVariable v |
    v.getInitializer().getExpr() = alloc.getParent*() and
    use = v.getAnAccess() and
    // The use is not inside an if-null check
    not exists(IfStmt check |
      check.getCondition().getAChild*() = v.getAnAccess() and
      check.getLocation().getStartLine() < use.getLocation().getStartLine()
    ) and
    // The use is an argument to memset, memcpy, or array subscript
    (
      exists(FunctionCall sink |
        sink.getTarget().hasName(["memset", "memcpy", "memmove"]) and
        sink.getAnArgument() = use
      )
      or
      exists(ArrayExpr ae | ae.getArrayBase() = use)
    )
  )
select use,
  "Allocated buffer from $@ is used without a NULL check.",
  alloc, alloc.getTarget().getName() + "()"
