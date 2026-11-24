"""The small JOSE pieces everything else uses: base64url, compact JWTs, raw ECDSA.

JOSE and COSE both carry ECDSA signatures as r||s (32 bytes each for P-256);
`cryptography` speaks DER. The two conversions here are the ones everybody
gets wrong once.
"""

from __future__ import annotations

import base64
import hashlib
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def json_compact(value) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


def jwt_parts(token: str) -> tuple[dict, dict]:
    """Header and payload of a compact JWS, NOT checked."""
    head, payload, _ = token.strip().split(".")
    return json.loads(unb64u(head)), json.loads(unb64u(payload))


def raw_ecdsa(key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    """ES256 as JOSE and COSE carry it: r||s, 32 bytes each."""
    r, s = decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def raw_to_der(signature: bytes) -> bytes:
    half = len(signature) // 2
    return encode_dss_signature(int.from_bytes(signature[:half], "big"), int.from_bytes(signature[half:], "big"))


def verify_raw(public_key, alg: str, signed: str, signature: str) -> None:
    """Verify a JWS signature (base64url r||s, or EdDSA); raises if it doesn't hold."""
    raw = unb64u(signature)
    if alg == "EdDSA":
        public_key.verify(raw, signed.encode())
        return
    sizes = {"ES256": hashes.SHA256(), "ES384": hashes.SHA384(), "ES512": hashes.SHA512()}
    public_key.verify(raw_to_der(raw), signed.encode(), ec.ECDSA(sizes.get(alg, hashes.SHA256())))


def verify_es256_jwt(token: str, public_key) -> tuple[dict, dict]:
    """Check a compact ES256 JWS against `public_key`; returns header and payload.
    ValueError if it doesn't verify."""
    try:
        header_b64, payload_b64, signature_b64 = token.strip().split(".")
        header, payload = json.loads(unb64u(header_b64)), json.loads(unb64u(payload_b64))
    except Exception as error:
        raise ValueError(f"not a compact JWS: {error}") from None
    if header.get("alg") != "ES256":
        raise ValueError(f"alg {header.get('alg')!r}, expected ES256")
    try:
        public_key.verify(raw_to_der(unb64u(signature_b64)), f"{header_b64}.{payload_b64}".encode(),
                          ec.ECDSA(hashes.SHA256()))
    except Exception:
        raise ValueError("the signature does not verify") from None
    return header, payload


def jwk_thumbprint(public_jwk: dict) -> bytes:
    """RFC 7638 SHA-256 thumbprint of an EC public JWK, as raw bytes.

    OpenID4VP's handover takes the RAW digest, not its base64url form: that
    one detail decides whether a device signature verifies.
    """
    if public_jwk.get("kty") != "EC":
        raise ValueError(f"only EC keys, not {public_jwk.get('kty')}")
    canonical = {k: public_jwk[k] for k in ("crv", "kty", "x", "y")}
    return hashlib.sha256(json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode()).digest()
