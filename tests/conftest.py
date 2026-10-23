"""Shared fixtures: a throwaway local RFC 3161 TSA built with the openssl CLI.

Lets the anchor tests exercise real signed timestamp tokens (and real
signature/chain verification) without any network access.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

TSA_CNF = """
[ req ]
distinguished_name = dn
prompt = no
[ dn ]
CN = {cn}
[ v3_ca ]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[ v3_tsa ]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, timeStamping
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ tsa ]
default_tsa = tsa_config
[ tsa_config ]
dir = {dir}
serial = $dir/serial
signer_cert = $dir/tsa.crt
signer_key = $dir/tsa.key
signer_digest = sha256
default_policy = 1.2.3.4.1
digests = sha256
accuracy = secs:1
ordering = no
tsa_name = yes
ess_cert_id_chain = no
ess_cert_id_alg = sha256
"""


def _run(*args, cwd):
    subprocess.run(args, cwd=cwd, check=True, capture_output=True)


def make_tsa(d: Path, name: str = "Test TSA"):
    d.mkdir(parents=True, exist_ok=True)
    (d / "ts.cnf").write_text(TSA_CNF.format(cn=name, dir=str(d)))
    (d / "serial").write_text("01\n")
    cnf = str(d / "ts.cnf")
    _run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.crt",
         "-days", "30", "-config", cnf, "-extensions", "v3_ca", "-subj", f"/CN={name} Root", cwd=d)
    _run("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", "tsa.key", "-out", "tsa.csr",
         "-config", cnf, "-subj", f"/CN={name}", cwd=d)
    _run("openssl", "x509", "-req", "-in", "tsa.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial",
         "-out", "tsa.crt", "-days", "30", "-extfile", cnf, "-extensions", "v3_tsa", cwd=d)

    def timestamper(data: bytes) -> bytes:
        (d / "data.txt").write_bytes(data)
        _run("openssl", "ts", "-query", "-data", "data.txt", "-sha256", "-cert", "-out", "req.tsq", cwd=d)
        _run("openssl", "ts", "-reply", "-config", cnf, "-queryfile", "req.tsq", "-token_out",
             "-out", "token.der", cwd=d)
        return (d / "token.der").read_bytes()

    return timestamper, str(d / "ca.crt")


@pytest.fixture
def local_tsa(tmp_path):
    if not shutil.which("openssl"):
        pytest.skip("openssl CLI not available")
    return make_tsa(tmp_path / "tsa")


@pytest.fixture
def rogue_tsa(tmp_path):
    """A second, untrusted TSA: tokens are valid but signed by the wrong CA."""
    if not shutil.which("openssl"):
        pytest.skip("openssl CLI not available")
    return make_tsa(tmp_path / "rogue", "Rogue TSA")
