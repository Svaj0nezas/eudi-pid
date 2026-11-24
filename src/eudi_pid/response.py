"""The wallet's answer: what it signed over, and how to open it.

With `response_mode=direct_post.jwt` the wallet POSTs a form with one field,
`response`: a compact JWE (ECDH-ES, A128CBC-HS256) to the key the request
named. Inside, `vp_token` maps the DCQL query id to a list of presentations;
for an mdoc each is a base64url DeviceResponse.

The device signature covers a SessionTranscript built from the Handover
below (OpenID4VP 1.0, Appendix B.2.6.1). Whoever checks the presentation
needs those four values: keep them with it.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from urllib.parse import parse_qs

import cbor2
from jwcrypto import jwe, jwk

from eudi_pid.jose import unb64u


@dataclass(frozen=True)
class Handover:
    """OpenID4VP 1.0's handover: what the German wallet signs over."""
    client_id: str
    nonce: str
    jwk_thumbprint: bytes          # RFC 7638 SHA-256 of the response encryption key, raw
    response_uri: str

    def info(self) -> bytes:
        return cbor2.dumps([self.client_id, self.nonce, self.jwk_thumbprint, self.response_uri])

    def session_transcript(self) -> list:
        return [None, None, ["OpenID4VPHandover", hashlib.sha256(self.info()).digest()]]


@dataclass
class Answer:
    """An opened response."""
    device_response: bytes         # CBOR, as the wallet made it
    state: str | None
    jwe_header: dict               # apu / apv, for diagnostics
    payload: dict                  # the whole decrypted response


def jwe_from_post(body: bytes | str) -> str:
    """The `response` field of the wallet's POST (a form, or JSON)."""
    text = body.decode() if isinstance(body, bytes) else body
    try:
        response = (json.loads(text)["response"] if text.lstrip().startswith("{")
                    else parse_qs(text)["response"][0])
    except (KeyError, IndexError, ValueError):
        raise ValueError("the POST carries no `response`") from None
    if response.count(".") != 4:
        raise ValueError("the response is not a compact JWE")
    return response


def jwe_header(token: str) -> dict:
    return json.loads(unb64u(token.split(".")[0]))


def device_response_of(payload: dict, query_id: str = "pid") -> bytes:
    """The DeviceResponse bytes from a decrypted response's vp_token."""
    presented = payload["vp_token"]
    if isinstance(presented, dict):
        presented = presented.get(query_id) or next(iter(presented.values()))
    if isinstance(presented, list):
        presented = presented[0]
    if isinstance(presented, bytes):
        return presented
    return base64.urlsafe_b64decode(presented + "=" * (-len(presented) % 4))


def open_response(token: str, private_key: jwk.JWK, query_id: str = "pid") -> Answer:
    """Decrypt the wallet's JWE with the response key's private half."""
    sealed = jwe.JWE()
    sealed.deserialize(token, key=private_key)
    payload = json.loads(sealed.payload)
    return Answer(device_response_of(payload, query_id), payload.get("state"), jwe_header(token), payload)
