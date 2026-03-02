/**
 * @name Unchecked CGBitmapContextCreate return value
 * @description CGBitmapContextCreate returns NULL on failure. Using the context
 *              without checking leads to null-pointer dereference in subsequent
 *              CoreGraphics calls.
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id xnuimagefuzzer/unchecked-bitmap-context
 * @tags security correctness coregraphics
 */

import cpp

from FunctionCall create, FunctionCall use, LocalVariable ctx
where
  create.getTarget().hasName("CGBitmapContextCreate") and
  ctx.getInitializer().getExpr() = create and
  use.getAnArgument() = ctx.getAnAccess() and
  use.getTarget().getName().matches("CG%") and
  // No null check between creation and use
  not exists(IfStmt check |
    check.getCondition().getAChild*() = ctx.getAnAccess() and
    check.getLocation().getStartLine() >= create.getLocation().getStartLine() and
    check.getLocation().getStartLine() <= use.getLocation().getStartLine()
  )
select use,
  "CoreGraphics function $@ uses context from $@ without a NULL check.",
  use, use.getTarget().getName(),
  create, "CGBitmapContextCreate"
