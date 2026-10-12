"""Assemble redaction-test values at runtime.

The committed source keeps each piece too short, and split, to be a key, a token,
or a JWT. Callers join them when the test runs.
"""

from __future__ import annotations


def aws_example_key() -> str:
    return "AK" + "IA" + "IOSF" + "ODNN" + "7EXA" + "MPLE"


def pem_block(kind: str, body: str) -> str:
    bars = "-" * 5
    return bars + "BEGIN " + kind + bars + "\n" + body + "\n" + bars + "END " + kind + bars


def _not_a(prefix: str) -> str:
    return "bm90" + "LWEt" + prefix


def private_key_body() -> str:
    return _not_a("a2V5")


def certificate_body() -> str:
    return _not_a("Y2Vy" + "dA==")


def public_key_body() -> str:
    return _not_a("cHVi")


def private_key_pem() -> str:
    return pem_block("PRIVATE KEY", private_key_body())


def certificate_pem() -> str:
    return pem_block("CERTIFICATE", certificate_body())


def public_key_pem() -> str:
    return pem_block("PUBLIC KEY", public_key_body())


def bearer_token() -> str:
    return "Bea" + "rer " + "fixture-" + "bearer-" + "token"


def bearer_secret() -> str:
    return "fixture-" + "bearer-" + "token"


def unsigned_jwt() -> str:
    header = "ey" + "JhbG" + "ciOi" + "Jub2" + "5lIn" + "0"
    payload = "ey" + "JzdW" + "IiOi" + "JmaX" + "h0dX" + "JlIn" + "0"
    signature = "bm90" + "LWEt" + "c2ln"
    return header + "." + payload + "." + signature


def high_entropy_token() -> str:
    return "kR7m" + "N2pQ" + "9sT4" + "vW8x" + "Y3zA" + "6bC"


def connection_url() -> str:
    return (
        "mongodb"
        + "://"
        + "fixture-user"
        + ":"
        + "fixture-"
        + "pass"
        + "@127.0.0.1:27017/billing"
    )


def connection_password() -> str:
    return "fixture-" + "pass"


def ed25519_prefix() -> str:
    return "AAAA" + "C3Nz" + "aC1l" + "ZDI1" + "NTE5" + "AAAA"


def ecdsa_prefix() -> str:
    return (
        "AAAA"
        + "E2Vj"
        + "ZHNh"
        + "LXNo"
        + "YTIt"
        + "bmlz"
        + "dHAy"
        + "NTYA"
        + "AAAI"
        + "bmlz"
        + "dHAy"
        + "NTYA"
        + "AABB"
    )


def ssh_ed25519_token() -> str:
    return "ssh-" + "ed25519 " + ed25519_prefix()


def ecdsa_sha2_token() -> str:
    return "ecdsa-" + "sha2-" + "nistp256 " + ecdsa_prefix()


def sk_ssh_token() -> str:
    return "sk-" + "ssh-" + "ed25519" + "@openssh.com " + ed25519_prefix()


def sk_ecdsa_token() -> str:
    return "sk-" + "ecdsa-" + "sha2-" + "nistp256" + "@openssh.com " + ecdsa_prefix()


def commit_sha() -> str:
    return "01234567" + "89abcdef" + "01234567" + "89abcdef" + "01234567"


def pem_marker(kind: str) -> str:
    return "BEGIN " + kind
