# Safeish Eval
Uses python's AST module to parse expression specified in SQL specification
file. To use, create instance of SqlVisitor, and call `safe_eval`
method on candidate code string. Create function with `compile` method.

    >>> v = SqlVisitor(safe_funcs=[cmp])
    >>> f = v.compile('float(_)')
    >>> f("3") => 3.0
    >>> v.compile('cmp(_, 4)')(5) => 1
    >>> v.compile('ord(_)')('f') => ArbitraryCode exception: `ord` not allowed
    >>> v.compile('_[:2]')('abcd') => 'ab'
    >>> v.compile('_[:2]')('abcd') => 'ab'
    >>> v.safe_eval('(lambda x: x)(1)') => raises ArbitraryCode Exception

The `check` method, which is run before `safe_eval` evaluates the code,
attempts to prevent execution of unsafe code by allowing only
a restricted subset of python code to be executed, and raising an
`ArbitraryCode` Exception for invalid code. The intention is to restrict
the permitted code to (1) single python expressions and (2) only function calls
specifically designated in `SqlVisitor.allowed_funcs`, by default: float, str, int.

To allow other custom functions, simply pass a list with them on initializing
the visitor. Functions MUST have a `__name__` attribute, i.e., they must be created
with `def ...`, and not with a lambda.

It's probably still a good idea to use `check` before testing on potentially
malicious input.

## Examples:
    >>> v.safe_eval("ord('S')") => ArbitraryCode Exception!
    >>> v2 = SqlVisitor(safe_funcs=[ord])
    >>> v2.safe_eval("ord('S')") => 83
    >>> v.safe_eval('float()') => 0
    >>> v.safe_eval('[1,2,3][:2]') => [1, 2]
    >>> v.safe_eval('str([1.5])') => '[1.5]'
    >>> v.safe_eval('import evil_script') => ArbitraryCode Exception!
    >>> v.safe_eval("os.rmdir('.')") => ArbitraryCode Exception!
