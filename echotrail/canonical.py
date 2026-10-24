"""Canonical JSON for hashing — identical bytes from Python and Node.

Stdlib-only and self-contained: this module's source is also embedded in
the standalone verify.py shipped inside evidence bundles.

Keys are sorted recursively, separators are compact, non-ASCII is kept
as-is, and numbers are written the way ECMAScript's JSON.stringify writes
them (2.0 -> "2", 1e-05 -> "0.00001", 1e16 -> "10000000000000000",
1e-07 -> "1e-7"). That makes a trace written by the Node SDK verify in
Python and vice versa.

Traces written before v0.13 hashed numbers with Python's float repr;
`canonical_legacy` reproduces that so older traces keep verifying. Both
encodings serialize the same parsed values, so accepting either does not
let anyone change what an event says.
"""

import json
from decimal import Decimal


def js_number(x):
    """Format a float exactly like ECMAScript Number.prototype.toString."""
    if x != x or x in (float("inf"), float("-inf")):
        raise ValueError("NaN/Infinity cannot be hashed canonically")
    if x == 0:
        return "0"
    if x.is_integer() and abs(x) < 1e21:
        return str(int(x))
    sign = "-" if x < 0 else ""
    # repr() gives the shortest round-tripping digits, as ECMAScript does
    _, digits, exp = Decimal(repr(abs(x))).as_tuple()
    s = "".join(map(str, digits)).rstrip("0") or "0"
    k = len(s)
    n = len(digits) + exp  # value = 0.s * 10**n
    if k <= n <= 21:
        out = s + "0" * (n - k)
    elif 0 < n <= 21:
        out = s[:n] + "." + s[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + s
    else:
        e = n - 1
        out = s[0] + ("." + s[1:] if k > 1 else "") + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + out


def _encode(obj, parts):
    if obj is None:
        parts.append("null")
    elif obj is True:
        parts.append("true")
    elif obj is False:
        parts.append("false")
    elif isinstance(obj, int):
        parts.append(str(obj))
    elif isinstance(obj, float):
        parts.append(js_number(obj))
    elif isinstance(obj, str):
        parts.append(json.dumps(obj, ensure_ascii=False))
    elif isinstance(obj, dict):
        parts.append("{")
        # JS sorts keys by UTF-16 code units, which differs from code-point order
        for i, k in enumerate(sorted(obj, key=lambda k: str(k).encode("utf-16-be"))):
            if i:
                parts.append(",")
            parts.append(json.dumps(str(k), ensure_ascii=False))
            parts.append(":")
            _encode(obj[k], parts)
        parts.append("}")
    elif isinstance(obj, (list, tuple)):
        parts.append("[")
        for i, v in enumerate(obj):
            if i:
                parts.append(",")
            _encode(v, parts)
        parts.append("]")
    else:
        raise TypeError(f"not JSON-serializable: {type(obj).__name__}")


def canonical(obj):
    """Canonical bytes used for every hash written from v0.13 on."""
    parts = []
    _encode(obj, parts)
    return "".join(parts).encode("utf-8")


def canonical_legacy(obj):
    """Pre-v0.13 canonical bytes (Python float repr). Verification only."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
