"""Certificate paths, the small way: who issued whom, and does it lead to a root.

EUDI certificates are all EC, so only ECDSA issuers are handled.
"""

from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec


def issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    """`issuer` signed `cert`."""
    if cert.issuer != issuer.subject:
        return False
    try:
        issuer.public_key().verify(cert.signature, cert.tbs_certificate_bytes,
                                   ec.ECDSA(cert.signature_hash_algorithm))
        return True
    except Exception:
        return False


def chain_problem(chain: list[x509.Certificate], roots: list[x509.Certificate],
                  now: datetime.datetime) -> str | None:
    """Why `chain` (leaf first) does not lead to one of `roots`, or None.
    Every certificate on the way, and the root, must be valid at `now`."""
    if not chain:
        return "no certificate"
    for cert in chain:
        if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
            return f"{cert.subject.rfc4514_string()} is not valid now"
    for lower, upper in zip(chain, chain[1:]):
        if not issued_by(lower, upper):
            return f"{lower.subject.rfc4514_string()} is not issued by the next certificate"
    top = chain[-1]
    for root in roots:
        if top == root or issued_by(top, root):
            if not root.not_valid_before_utc <= now <= root.not_valid_after_utc:
                return f"the root {root.subject.rfc4514_string()} is not valid now"
            return None
    return f"{top.issuer.rfc4514_string()} is not a trusted root"


def root_name(chain: list[x509.Certificate], roots: list[x509.Certificate]) -> str:
    top = chain[-1]
    return next((r.subject.rfc4514_string() for r in roots if top == r or top.issuer == r.subject), "?")
