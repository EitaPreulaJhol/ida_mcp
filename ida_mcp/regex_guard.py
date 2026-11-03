"""Guard for client-supplied regular expressions.

Tool regexes run with the backtracking ``re`` engine on the IDA main thread.
A catastrophic pattern such as ``(a+)+b`` can backtrack exponentially, and
the tool timeout cannot interrupt it: the ``sys.setprofile`` watchdog only
fires between bytecodes, never inside the C matcher. So patterns are vetted
before compiling instead.

The check rejects nested repetition where either level is unbounded
(``(a+)+``, ``(\\w*\\s?)*``, ``(?:x|y+){2,}``) - the classic exponential
shape. It is a heuristic, not a proof of linear time: overlapping
alternation under a single repeat (``(a|aa)+``) still passes. Possessive
repeats and atomic groups (Python 3.11+) never backtrack, so they reset the
nesting and are the suggested rewrite.

No ``ida_*`` imports, so this module is importable outside IDA.
"""
import functools
import re

try:
    from re import _parser as _sre_parse, _constants as _sre_c  # type: ignore[attr-defined]
except ImportError:  # Python < 3.11
    import sre_parse as _sre_parse
    import sre_constants as _sre_c

MAX_PATTERN_LEN = 1000

_REPEATS = (_sre_c.MAX_REPEAT, _sre_c.MIN_REPEAT)
# Non-backtracking constructs (3.11+); absent on older Pythons.
_ATOMIC = tuple(op for op in (getattr(_sre_c, "POSSESSIVE_REPEAT", None),
                              getattr(_sre_c, "ATOMIC_GROUP", None))
                if op is not None)


def _children(av):
    if isinstance(av, _sre_parse.SubPattern):
        yield av
    elif isinstance(av, (tuple, list)):
        for x in av:
            yield from _children(x)


def _check(sub, enclosing_unbounded):
    """``enclosing_unbounded``: None outside any repeat, else whether some
    enclosing repeat (max > 1) is unbounded."""
    for op, av in sub:
        if op in _REPEATS:
            _lo, hi, item = av
            if hi > 1:
                unbounded = hi == _sre_c.MAXREPEAT
                if enclosing_unbounded is not None and (enclosing_unbounded or unbounded):
                    raise re.error(
                        "nested quantifiers (e.g. '(a+)+') can backtrack "
                        "exponentially and are rejected; flatten the pattern "
                        "or use a possessive '++' / atomic '(?>...)' group")
                _check(item, bool(enclosing_unbounded) or unbounded)
                continue
        elif op in _ATOMIC:
            for child in _children(av):
                _check(child, None)
            continue
        for child in _children(av):
            _check(child, enclosing_unbounded)


@functools.lru_cache(maxsize=64)
def compile_client_regex(pattern: str, flags: int = 0) -> "re.Pattern":
    """Compile a client regex after rejecting ReDoS-prone shapes.

    Raises ``re.error`` (like ``re.compile``) for invalid or rejected input.
    """
    if len(pattern) > MAX_PATTERN_LEN:
        raise re.error(f"pattern longer than {MAX_PATTERN_LEN} characters")
    _check(_sre_parse.parse(pattern, flags), None)
    return re.compile(pattern, flags)
