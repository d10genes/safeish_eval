import ast


class ArbitraryCode(Exception):
    pass


class SqlVisitor(ast.NodeVisitor):
    """Uses python's AST module to parse expression specified in SQL specification
    file. To use, create instance of SqlVisitor, and call `safe_eval`
    method on candidate code string.
    TODO: compiler ex.
    >>> v = SqlVisitor()
    >>> v.safe_eval('(lambda x: x)(1)') => raises ArbitraryCode Exception

    The `check` method, which is run before `safe_eval` evaluates the code,
    attempts to prevent execution of unsafe code by allowing only
    a restricted subset of python code to be executed, and raising an
    `ArbitraryCode` Exception for invalid code. The intention is to restrict
    the permitted code to (1) single python expressions and (2) only function calls
    specifically designated in `SqlVisitor.allowed_funcs`.

    To allow other custom functions, simply pass a list with their names on initializing
    the visitor.

    It's probably still a good idea to check with `check` before testing on potentially
    malicious input.

    Examples:
    >>> v.safe_eval("ord('S')") => ArbitraryCode Exception!
    >>> v2 = SqlVisitor(safe_funcs=['ord'])
    >>> v2.safe_eval("ord('S')") => 83
    >>> v.safe_eval('float()') => 0
    >>> v.safe_eval('[1,2,3][:2]') => [1, 2]
    >>> v.safe_eval('str([1.5])') => '[1.5]'
    >>> v.safe_eval('import evil_script') => ArbitraryCode Exception!
    >>> v.safe_eval("os.rmdir('.')") => ArbitraryCode Exception!
    """

    def __init__(self, safe_funcs=[], vb=False):  # TODO: safe_funcs doc
        # try_float
        self.vb = vb
        allowed_funcs = {float, str, int}
        allowed_funcs.update(set(safe_funcs))
        self.func_dct = gen_fmap(allowed_funcs)

        self.allowed_funcs = set(self.func_dct)  # just names

    def compile(self, s):
        """Turns SQL string specifications into functions, with
        compile-time check.
        `_` serves as the argument.

        Example:
        >>> f = compile('float(_)')
        >>> ("3") => 3.0
        >>> g = compile('_[:2]')
        >>> g('abcd') => 'ab'

        NOTE: To use custom functions, they must have been passed in
        `safe_funcs` list on init.

        """
        self.check(s)

        def f(x):
            _ = x
            locs = locals()
            locs.update(self.func_dct)
            return self.safe_eval(s, locs=locs)
        return f

    def check(self, s):
        return self.visit(ast.parse(s))

    def safe_eval(self, s, globs=None, locs=None):
        self.check(s)
        if globs is None:
            globs = globals()
        if locs is None:
            locs = locals()
        return eval(s, globs, locs)

    def visit_Module(self, mod):
        if self.vb:
            print('M...')
            print(mod)
        if len(mod.body) != 1:
            raise ArbitraryCode('Must pass single expression. "{}" not valid.'.format(mod.body))
        [node] = mod.body
        if not isinstance(node, ast.Expr):
            raise ArbitraryCode('Must pass single expression. "{}" not valid.'.format(node))
        return self.visit(node)

    def visit_Call(self, call):
        if self.vb:
            print('Call...')
            print(call)
        func_name = getattr(call.func, 'id', '<unnamed>')
        if func_name not in self.allowed_funcs:
            raise ArbitraryCode('Function {} not in allowed list.'.format(func_name))
        self.rec_visit(call)

    def generic_visit(self, s):
        if self.vb:
            print('Gen: {}'.format(s))
        self.rec_visit(s)

    def rec_visit(self, n):
        if n is None:
            return
        for child in ast.iter_child_nodes(n):
            self.visit(child)


def gen_fmap(fs):
    d = {f.__name__: f for f in fs}
    return d
