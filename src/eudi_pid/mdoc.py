"""CBOR and COSE, as an mdoc (ISO/IEC 18013-5) uses them.

A DeviceResponse holds documents; each has

    issuerSigned.nameSpaces   the disclosed elements, each tag 24 around its CBOR
    issuerSigned.issuerAuth   COSE_Sign1 by the Document Signer over the MSO
                              (x5chain in the unprotected header)
    deviceSigned.deviceAuth   COSE_Sign1 by the device key the MSO binds,
                              over DeviceAuthentication (detached)

The MSO (Mobile Security Object) holds a digest of each element's tag-24
bytes, the device key, validity dates and a status list entry.
"""

from __future__ import annotations

import datetime

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from eudi_pid.jose import raw_to_der

PID_DOCTYPE = "eu.europa.ec.eudi.pid.1"      # also the PID's namespace

# COSE labels, RFC 9052.
COSE_ALG, COSE_X5CHAIN = 1, 33
COSE_CURVES = {1: ec.SECP256R1, 2: ec.SECP384R1, 3: ec.SECP521R1}
COSE_ALGS = {-7: "ES256", -35: "ES384", -36: "ES512", -8: "EdDSA"}


def cose_parts(sign1) -> tuple[dict, dict, bytes, bytes, bytes]:
    """protected map, unprotected map, raw protected bytes, payload, signature."""
    if isinstance(sign1, cbor2.CBORTag):          # tag 18 = COSE_Sign1
        sign1 = sign1.value
    protected_raw, unprotected, payload, signature = sign1
    protected = cbor2.loads(protected_raw) if protected_raw else {}
    return protected, unprotected, protected_raw, payload, signature


def cose_verify(public_key, alg: int, protected_raw: bytes, payload: bytes,
                signature: bytes, external_aad: bytes = b"") -> None:
    """Check a COSE_Sign1 over RFC 9052's Sig_structure; raises if it doesn't hold.

    The signed bytes are never the payload alone, but
    ["Signature1", protected, external_aad, payload] re-encoded.
    """
    signed = cbor2.dumps(["Signature1", protected_raw, external_aad, payload])
    if alg == -8:
        public_key.verify(signature, signed)
        return
    sizes = {-7: hashes.SHA256(), -35: hashes.SHA384(), -36: hashes.SHA512()}
    public_key.verify(raw_to_der(signature), signed, ec.ECDSA(sizes.get(alg, hashes.SHA256())))


def cose_key(key: dict):
    """A COSE_Key map (the device key in the MSO) as a public key."""
    kty = key.get(1)
    if kty == 2:                                   # EC2
        curve = COSE_CURVES.get(key.get(-1), ec.SECP256R1)()
        return ec.EllipticCurvePublicNumbers(int.from_bytes(key[-2], "big"),
                                             int.from_bytes(key[-3], "big"), curve).public_key()
    if kty == 1:                                   # OKP
        return ed25519.Ed25519PublicKey.from_public_bytes(key[-2])
    raise ValueError(f"unsupported COSE key type {kty}")


def mso_of(issuer_auth) -> dict:
    """The Mobile Security Object inside issuerAuth (tag 24, possibly nested)."""
    _, _, _, payload, _ = cose_parts(issuer_auth)
    mso = cbor2.loads(payload.value if isinstance(payload, cbor2.CBORTag) else payload)
    if isinstance(mso, cbor2.CBORTag):
        mso = cbor2.loads(mso.value)
    return mso


def x5chain(unprotected: dict) -> list[bytes]:
    """x5chain as a list of DER certificates (one certificate may come bare)."""
    chain = unprotected.get(COSE_X5CHAIN) or []
    return [chain] if isinstance(chain, bytes) else list(chain)


def tdate(value) -> datetime.datetime | None:
    """An MSO tdate: cbor2 may hand over a datetime, or tag 0 around text."""
    if isinstance(value, cbor2.CBORTag):
        value = value.value
    if isinstance(value, str):
        value = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if isinstance(value, datetime.datetime):
        return value if value.tzinfo else value.replace(tzinfo=datetime.timezone.utc)
    return None


def plain(value):
    """CBOR values as JSON-friendly Python: dates as ISO text, bytes as hex."""
    if isinstance(value, cbor2.CBORTag):
        return plain(value.value)
    if isinstance(value, (datetime.date, datetime.datetime)):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {k: plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [plain(v) for v in value]
    return value


def device_authentication(session_transcript: list, doctype: str, device_namespaces) -> bytes:
    """The detached payload a device signature covers (ISO 18013-5 9.1.3.4)."""
    return cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(
        ["DeviceAuthentication", session_transcript, doctype, device_namespaces])))
