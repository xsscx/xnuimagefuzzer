/**
 * @name Environment variable used as file path without validation
 * @description Using getenv() output directly in file paths without checking
 *              for NULL or validating the path enables directory traversal and
 *              null-pointer dereference.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id xnuimagefuzzer/unsafe-getenv-path
 * @tags security path-traversal environment
 */

import cpp

from FunctionCall getenvCall, Expr use
where
  getenvCall.getTarget().hasName("getenv") and
  exists(LocalVariable v |
    v.getInitializer().getExpr() = getenvCall and
    use = v.getAnAccess() and
    // Used in a file-related context (string format, path construction)
    (
      exists(FunctionCall fileOp |
        fileOp.getTarget().hasName([
          "fopen", "open", "access", "stat", "mkdir",
          "stringWithFormat", "stringByAppendingPathComponent",
          "initWithString", "stringWithUTF8String",
          "writeToFile", "createDirectoryAtPath"
        ]) and
        fileOp.getAnArgument().getAChild*() = use
      )
      or
      // Used in NSString format for path construction
      exists(FunctionCall fmt |
        fmt.getTarget().hasName("stringWithFormat") and
        fmt.getAnArgument().getAChild*() = use
      )
    ) and
    // No NULL check before use
    not exists(IfStmt check |
      check.getCondition().getAChild*() = v.getAnAccess() and
      check.getLocation().getStartLine() >= getenvCall.getLocation().getStartLine() and
      check.getLocation().getStartLine() <= use.getLocation().getStartLine()
    )
  )
select use,
  "Environment variable from $@ is used in a file path without validation.",
  getenvCall, "getenv()"
