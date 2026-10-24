"""RFC 3161 timestamp token checks — stdlib only.

Self-contained: this module's source is also embedded in the standalone
verify.py shipped inside evidence bundles, so it must not import anything
outside the standard library.

Two levels of checking:

- `check_token` (always, no dependencies): parses the DER token and
  confirms its messageImprint is SHA-256 of the anchored chain hash. A
  rewritten chain can't reuse an old token, and editing the anchor record
  to the new head no longer matches the token.
- `verify_signature` (needs the `openssl` CLI and the TSA's CA
  certificate): confirms the token was really signed by that TSA, so it
  can't be fabricated either.
"""

import hashlib
import os
import shutil
import subprocess
import tempfile

_OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
_OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
_OID_SHA256 = "2.16.840.1.101.3.4.2.1"


def _tlv(b, i):
    tag = b[i]
    length = b[i + 1]
    i += 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(b[i:i + n], "big")
        i += n
    if i + length > len(b):
        raise ValueError("truncated DER")
    return tag, b[i:i + length], i + length


def _children(b):
    out, i = [], 0
    while i < len(b):
        tag, value, i = _tlv(b, i)
        out.append((tag, value))
    return out


def _oid(value):
    first = value[0]
    parts = [str(min(first // 40, 2)), str(first - 40 * min(first // 40, 2))]
    n = 0
    for byte in value[1:]:
        n = (n << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(n))
            n = 0
    return ".".join(parts)


def anchor_digest(anchored_hash):
    """The digest a TSA is asked to sign for an anchored chain hash."""
    return hashlib.sha256(anchored_hash.encode()).digest()


def parse_timestamp(der):
    """Parse a TimeStampToken or a TimeStampResp.

    Returns {hash_alg, hashed_message, serial, gen_time, is_response}.
    Raises ValueError on anything that isn't a well-formed granted token.
    """
    try:
        tag, outer, _ = _tlv(der, 0)
        top = _children(outer)
        is_response = top[0][0] == 0x30  # TimeStampResp starts with PKIStatusInfo
        if is_response:
            status = int.from_bytes(_children(top[0][1])[0][1], "big")
            if status not in (0, 1):
                raise ValueError(f"TSA refused the request (status {status})")
            if len(top) < 2:
                raise ValueError("response carries no token")
            content_info = _children(top[1][1])
        else:
            content_info = top
        if content_info[0][0] != 0x06 or _oid(content_info[0][1]) != _OID_SIGNED_DATA:
            raise ValueError("not a CMS SignedData token")
        signed_data = _children(_children(content_info[1][1])[0][1])
        encap = _children(signed_data[2][1])
        if _oid(encap[0][1]) != _OID_TST_INFO:
            raise ValueError("token does not contain TSTInfo")
        octets = _children(encap[1][1])[0][1]  # [0] EXPLICIT OCTET STRING holding TSTInfo DER
        tst_info = _children(_tlv(octets, 0)[1])
        imprint = _children(tst_info[2][1])
        alg = _oid(_children(imprint[0][1])[0][1])
        return {
            "hash_alg": "sha256" if alg == _OID_SHA256 else alg,
            "hashed_message": imprint[1][1],
            "serial": int.from_bytes(tst_info[3][1], "big"),
            "gen_time": tst_info[4][1].decode("ascii", "replace"),
            "is_response": is_response,
        }
    except (IndexError, ValueError, UnicodeDecodeError) as e:
        raise ValueError(f"malformed timestamp token: {e}") from None


def check_token(der, anchored_hash):
    """(ok, detail): does this token timestamp exactly `anchored_hash`?"""
    try:
        info = parse_timestamp(der)
    except ValueError as e:
        return False, str(e)
    if info["hash_alg"] != "sha256":
        return False, f"unexpected imprint algorithm {info['hash_alg']}"
    if info["hashed_message"] != anchor_digest(anchored_hash):
        return False, "token does not timestamp the anchored hash"
    return True, f"TSA time {info['gen_time']}, serial {info['serial']}"


def verify_signature(der, anchored_hash, ca_file):
    """(ok, detail) via `openssl ts -verify`; ok is None if openssl is missing."""
    openssl = shutil.which("openssl")
    if openssl is None:
        return None, "openssl not found; TSA signature not checked"
    try:
        is_response = parse_timestamp(der)["is_response"]
    except ValueError as e:
        return False, str(e)
    fd, path = tempfile.mkstemp(suffix=".tsr")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(der)
        cmd = [openssl, "ts", "-verify", "-digest", anchor_digest(anchored_hash).hex(),
               "-in", path, "-CAfile", str(ca_file)]
        if not is_response:
            cmd.append("-token_in")
        r = subprocess.run(cmd, capture_output=True, text=True)
    finally:
        os.unlink(path)
    if r.returncode == 0 and "Verification: OK" in r.stdout:
        return True, "TSA signature valid"
    detail = (r.stderr or r.stdout).strip().splitlines()
    return False, "TSA signature invalid: " + (detail[-1] if detail else "openssl failed")
