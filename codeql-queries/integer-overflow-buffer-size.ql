/**
 * @name Integer overflow in buffer size calculation
 * @description Multiplication of width, height, or bytesPerRow for buffer allocation
 *              without overflow protection may cause undersized allocation and heap
 *              buffer overflow.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id xnuimagefuzzer/integer-overflow-buffer-size
 * @tags security integer-overflow memory
 */

import cpp

from FunctionCall alloc, MulExpr mul
where
  alloc.getTarget().hasName(["malloc", "calloc"]) and
  mul = alloc.getAnArgument().getAChild*() and
  // Multiplication involves variables named like dimensions
  exists(VariableAccess va |
    va = mul.getAChild*() and
    va.getTarget().getName().regexpMatch(".*(width|height|bytesPerRow|bytesPerPixel|bufferSize).*")
  ) and
  // No overflow check (e.g., comparison or division before the alloc)
  not exists(IfStmt guard |
    guard.getCondition().getAChild*() instanceof DivExpr and
    guard.getLocation().getStartLine() < alloc.getLocation().getStartLine() and
    guard.getLocation().getStartLine() > alloc.getLocation().getStartLine() - 10
  )
select alloc,
  "Buffer allocation uses unchecked multiplication $@ that may overflow.",
  mul, mul.toString()
