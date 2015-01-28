from pytest import raises
from safe_eval import SqlVisitor, ArbitraryCode


def test_code_check():

    v = SqlVisitor()
    v2 = SqlVisitor(safe_funcs=[ord, cmp])

    oks = [
        'a[0:250]',
        'float(a)',
        'float()',
        'float(x=6)',
        'float(*[])',
        'float(**[])',
        'x if y else z',
        '[float() for float in [(lambda x: 1)]]',
        '[derp for float in [(lambda x: 1)]]'
    ]

    notoks = [
        'a=b; d()',
        'float(a); float(a)',
        'float(malicious_func())',
        'float(x=malicious_func())',
        'float(x=malicious_func(), x2=malicious_func())',
        'float(*malicious_func())',
        'float(*[malicious_func()])',
        'float(**malicious_func())',
        'float(**[malicious_func()])',
        'float(*[malicious_func() for u in [1]])',
        'float(*[float() for float in [(lambda x: malicious_func())]])',
        'x() if y else z',
        '(lambda x: x)()',
    ]

    for good_expr in oks:
        v.check(good_expr)

    for bad_expr in notoks:
        with(raises(ArbitraryCode)):
            v.check(bad_expr)

    # Cust func's
    cust_exprs = [
        ("ord('S')", 83),
        ("cmp(1, 2)", -1)
    ]

    for cust_expr, val in cust_exprs:
        with(raises(ArbitraryCode)):
            v.safe_eval(cust_expr) == val

    for cust_expr, val in cust_exprs:
        assert v2.safe_eval(cust_expr) == val


def test_compile():

    def dunder(s):
        return '__{}__'.format(s)

    v = SqlVisitor()
    assert v.compile('_[:3]')(list(range(9))) == [0, 1, 2]
    assert v.compile('float(_)')("3") == 3.0
    assert v.compile('str(float(_))')("3") == '3.0'
    assert v.compile('9 if _ else 4')(False) == 4

    fs_arg = [
        ('dunder(_)', 'name'),
        ('ord(_)', 'f'),
        ('cmp(_, 4)', 5),
    ]

    for f, a in fs_arg:
        with raises(ArbitraryCode):
            v.compile(f)(a)

    v2 = SqlVisitor(safe_funcs=[dunder, ord, cmp])
    assert v2.compile('dunder(_)')('name') == '__name__'
    assert v2.compile('ord(_)')('f') == 102
    assert v2.compile('cmp(_, 4)')(5) == 1
