"""Guard for client-supplied regular expressions.

Tool regexes run with the backtracking ``re`` engine on the IDA main thread.
A catastrophic pattern such as ``(a+)+b`` can backtrack exponentially, and
the tool timeout cannot interrupt it: the ``sys.setprofile`` watchdog only
fires between bytecodes, never inside the C matcher. So patterns are vetted
before compiling instead.

The check rejects nested repetition where either level is unbounded
(``(a+)+``, ``(\\w*\\s?)*``, ``(?:x|y+){2,}``) - the classic exponential
shape - and ambiguous alternation inside an unbounded repeat
(``(a|aa)+``, ``(foo|foobar)+``, ``(a|ab\\d)+``). The latter also covers
alternatives that can match the empty string (``(?:a?|b)+``), because each
iteration can then end in more than one place. It is a heuristic, not a
proof of linear time: overlap hidden behind character classes (for example
``(a\\d|a\\w)+``, which the parser merges into one class) still passes.
Possessive repeats and atomic groups (Python 3.11+) never backtrack, so they
reset the nesting and are the suggested rewrite.

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
_BRANCH = _sre_c.BRANCH
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


def _literal_prefix(sub) -> str:
    """Longest literal prefix guaranteed at the start of ``sub``.

    Only a conservative prefix is needed: stop at the first construct whose
    text is not a fixed string (a class, a repeat with variable width, ...).
    """
    out = []
    for op, av in sub:
        if op == _sre_c.LITERAL:
            out.append(chr(av))
        elif op == _sre_c.SUBPATTERN:
            child = av[-1]
            out.append(_literal_prefix(child))
            if not _is_pure_literal(child):
                break
        elif op in _REPEATS:
            lo, _hi, item = av
            if lo <= 0:
                break
            prefix = _literal_prefix(item)
            if not prefix or not _is_pure_literal(item):
                break
            out.append(prefix * lo)
            # A variable-width repeat is not a fixed string after its
            # mandatory repetitions, so the prefix ends there.
            break
        elif op == getattr(_sre_c, "ATOMIC_GROUP", None):
            out.append(_literal_prefix(av))
            break
        elif op == getattr(_sre_c, "POSSESSIVE_REPEAT", None):
            lo, _hi, item = av
            if lo <= 0:
                break
            prefix = _literal_prefix(item)
            if not prefix or not _is_pure_literal(item):
                break
            out.append(prefix * lo)
            break
        else:
            break
    return "".join(out)


def _is_pure_literal(sub) -> bool:
    """True when ``sub`` is a fixed literal string (no classes/repeats)."""
    for op, av in sub:
        if op == _sre_c.LITERAL:
            continue
        if op == _sre_c.SUBPATTERN:
            if not _is_pure_literal(av[-1]):
                return False
            continue
        if op in _REPEATS:
            lo, hi, item = av
            if lo != hi or not _is_pure_literal(item):
                return False
            continue
        if op == getattr(_sre_c, "ATOMIC_GROUP", None):
            if not _is_pure_literal(av):
                return False
            continue
        if op == getattr(_sre_c, "POSSESSIVE_REPEAT", None):
            lo, hi, item = av
            if lo != hi or not _is_pure_literal(item):
                return False
            continue
        return False
    return True


def _check_alternation(branches) -> None:
    """Reject ambiguous alternatives inside an unbounded repeat.

    The parser factors common literal prefixes, so ``(a|aa)+`` arrives as
    ``a`` followed by a branch whose second alternative is empty. An empty
    alternative (or one that can match empty) is therefore the main signal.
    For the remaining shapes, a pure-literal alternative that prefixes a
    longer alternative (``foo|foobar``) is ambiguous too.
    """
    infos = []
    for branch in branches:
        min_width = branch.getwidth()[0]
        if min_width == 0:
            raise re.error(
                "alternation inside a repeated group can match empty, which "
                "causes ambiguous backtracking; remove the empty alternative "
                "or rewrite the group without repetition")
        infos.append((_literal_prefix(branch), _is_pure_literal(branch)))

    for i, (prefix, pure) in enumerate(infos):
        if not prefix:
            continue
        for j, (other, other_pure) in enumerate(infos):
            if i == j:
                continue
            if (other == prefix and pure and other_pure) or (
                    pure and other.startswith(prefix) and len(other) > len(prefix)):
                raise re.error(
                    "ambiguous alternation inside a repeated group "
                    "(e.g. '(a|aa)+'); make the alternatives disjoint or "
                    "use a possessive '++' / atomic '(?>...)' group")


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
        elif op == _BRANCH:
            if enclosing_unbounded:
                _check_alternation(av[1])
            for branch in av[1]:
                _check(branch, enclosing_unbounded)
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
    try:
        _check(_sre_parse.parse(pattern, flags), None)
        # re.compile() parses the pattern again internally, a few frames
        # deeper: a pattern just under the recursion limit passes the first
        # parse and overflows here, so both calls must share the handler.
        return re.compile(pattern, flags)
    except RecursionError:
        # Deeply nested groups (still under MAX_PATTERN_LEN) overflow the
        # parser's recursion before any nesting check runs. Callers only
        # catch re.error, so this must not escape as RecursionError.
        raise re.error("pattern nesting too deep (rejected)") from None
