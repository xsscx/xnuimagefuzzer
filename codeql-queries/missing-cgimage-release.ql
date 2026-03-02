/**
 * @name Missing CGImageRelease for created CGImage
 * @description CGBitmapContextCreateImage returns a CGImageRef that must be released.
 *              Missing CGImageRelease causes a Core Graphics memory leak.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id xnuimagefuzzer/missing-cgimage-release
 * @tags security memory-leak coregraphics
 */

import cpp

from FunctionCall createImg, Function enclosing
where
  createImg.getTarget().hasName("CGBitmapContextCreateImage") and
  enclosing = createImg.getEnclosingFunction() and
  // No corresponding CGImageRelease in the same function
  not exists(FunctionCall release |
    release.getTarget().hasName("CGImageRelease") and
    release.getEnclosingFunction() = enclosing
  )
select createImg,
  "CGBitmapContextCreateImage in $@ has no corresponding CGImageRelease — memory leak.",
  enclosing, enclosing.getName()
