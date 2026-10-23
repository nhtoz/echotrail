"""RFC 3161 timestamp token verification (stdlib + the `openssl` CLI only).

Kept dependency-free on purpose: this file is also embedded verbatim in
every evidence bundle's verify.py, so an auditor can check anchors with
nothing but Python and OpenSSL, trusting neither echotrail nor its user.

A token is accepted only if OpenSSL confirms that:
  * its message imprint is SHA-256 of the anchored chain hash, and
  * it is signed by a TSA whose certificate chains to a CA in the
    verifier's own trust store (never a certificate supplied by the bundle).
"""

import base64
import os
import re
import shutil
import subprocess
import tempfile

_CA_CANDIDATES = [
    "/etc/ssl/certs/ca-certificates.crt",   # Debian/Ubuntu
    "/etc/pki/tls/certs/ca-bundle.crt",     # RHEL/Fedora
    "/etc/ssl/cert.pem",                    # macOS, Alpine
    "/usr/local/etc/openssl/cert.pem",      # Homebrew
]


def default_ca_file():
    """Best available trust store: certifi if installed, else the system bundle."""
    try:
        import certifi  # type: ignore
        return certifi.where()
    except Exception:
        pass
    for p in _CA_CANDIDATES:
        if os.path.exists(p):
            return p
    return None


def verify_timestamp_token(token_b64, anchored_hash, ca_file=None):
    """Return {"ok": True/False/None, "reason": str, "gen_time": str|None, "tsa": str|None}.

    ok is None when verification could not be attempted (no openssl / no CA).
    """
    openssl = shutil.which("openssl")
    if not openssl:
        return {"ok": None, "reason": "openssl not found; cannot check the timestamp signature",
                "gen_time": None, "tsa": None}
    ca_file = ca_file or default_ca_file()
    if not ca_file or not os.path.exists(ca_file):
        return {"ok": None, "reason": "no CA trust store found; pass a CA file",
                "gen_time": None, "tsa": None}
    try:
        token = base64.b64decode(token_b64)
    except Exception:
        return {"ok": False, "reason": "timestamp token is not valid base64", "gen_time": None, "tsa": None}

    with tempfile.TemporaryDirectory() as d:
        tok, data = os.path.join(d, "token.der"), os.path.join(d, "data.txt")
        with open(tok, "wb") as f:
            f.write(token)
        with open(data, "wb") as f:
            f.write(anchored_hash.encode())
        r = subprocess.run(
            [openssl, "ts", "-verify", "-token_in", "-in", tok, "-data", data, "-CAfile", ca_file],
            capture_output=True, text=True,
        )
        info = subprocess.run(
            [openssl, "ts", "-reply", "-token_in", "-in", tok, "-token_out", "-text"],
            capture_output=True, text=True,
        )
    gen_time = tsa = None
    m = re.search(r"Time stamp:\s*(.+)", info.stdout)
    if m:
        gen_time = m.group(1).strip()
    m = re.search(r"TSA:\s*(.+)", info.stdout)
    if m:
        tsa = m.group(1).strip()
    if r.returncode == 0 and "Verification: OK" in r.stdout:
        return {"ok": True, "reason": "valid RFC 3161 timestamp", "gen_time": gen_time, "tsa": tsa}
    errs = re.findall(r"error:[0-9A-F]+:[^:]*:[^:]*:(.+)", r.stderr)
    why = errs[-1].strip() if errs else "verification failed"
    if "message imprint mismatch" in r.stderr.lower() or "imprint" in why.lower():
        why = "token was issued for a different hash"
    elif "issuer" in why.lower() or "certificate" in why.lower():
        why = "TSA certificate does not chain to a trusted CA"
    return {"ok": False, "reason": "timestamp token rejected: " + why[:200],
            "gen_time": gen_time, "tsa": tsa}
