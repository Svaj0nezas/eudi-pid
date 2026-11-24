"""The request a wallet scans: OpenID4VP 1.0, signed, mdoc PID, direct_post.jwt.

    request = rp.request("https://you.example/response/abc",
                         ["given_name", "family_name", "birth_date"])
    request.wallet_url("https://you.example/request/abc")   → openid4vp://?client_id=…&request_uri=…
    request.signed()            the request object, served at request_uri
    answer = request.open(post_body)               the wallet's POST to response_uri, decrypted
    pid = request.verify(post_body, trust)         … and checked

Three things are yours to choose:

    nonce          random by default; pass your own to bind the presentation to
                   something (a passkey, an operation hash): the device
                   signature covers it
    response key   made here by default (`request.response_key`, private);
                   pass `response_jwk=` a public P-256 JWK to have the wallet
                   encrypt to a key held elsewhere, e.g. the user's browser.
                   The request's signature covers it, the wallet shows only
                   who asks: use it to deliver to the user, not to a third party
    claims         must be within your registration certificate, or the
                   wallet refuses ("you need a valid credential")
"""

from __future__ import annotations

import json
import secrets
import time
import urllib.parse
from dataclasses import dataclass

from jwcrypto import jwk

from eudi_pid.jose import jwk_thumbprint
from eudi_pid.mdoc import PID_DOCTYPE
from eudi_pid.party import RelyingParty
from eudi_pid.response import Answer, Handover, jwe_from_post, open_response

REQUEST_LIFETIME = 300


def pid_dcql(claims, doctype: str = PID_DOCTYPE, query_id: str = "pid", namespace: str | None = None) -> dict:
    """A DCQL query for one mdoc: claims as [namespace, element] paths."""
    namespace = namespace or doctype
    return {"credentials": [{
        "id": query_id, "format": "mso_mdoc", "meta": {"doctype_value": doctype},
        "claims": [{"id": c, "path": [namespace, c]} for c in claims]}]}


def registered_dcql(party: RelyingParty, query_id: str = "pid") -> dict:
    """Everything the registration certificate allows, in its own shape."""
    wanted = party.registered_credential
    return {"credentials": [{
        "id": query_id, "format": wanted["format"], "meta": wanted["meta"],
        "claims": [{"id": f"c{i}", "path": c["path"]} for i, c in enumerate(wanted["claim"])]}]}


def request_object(party: RelyingParty, *, nonce: str, state: str, response_uri: str,
                   response_jwk: dict, dcql: dict, now: int | None = None,
                   lifetime: int = REQUEST_LIFETIME) -> str:
    """The signed request object (typ oauth-authz-req+jwt, x5c = the access certificate chain)."""
    now = int(time.time()) if now is None else now
    payload = {
        "iat": now, "exp": now + lifetime, "aud": "https://self-issued.me/v2",
        "client_id": party.client_id, "state": state, "nonce": nonce,
        "response_type": "vp_token", "response_mode": "direct_post.jwt",
        "response_uri": response_uri,
        "client_metadata": {
            "jwks": {"keys": [response_jwk]},
            "authorization_encrypted_response_alg": "ECDH-ES",
            "authorization_encrypted_response_enc": "A128CBC-HS256",
            "vp_formats_supported": {"mso_mdoc": {"alg": ["ES256", "ES384", "EdDSA"]}},
        },
        "dcql_query": dcql,
    }
    if party.rc:
        payload["verifier_info"] = [{"format": "registration_cert", "data": party.rc}]
    return party.sign({"alg": party.alg, "typ": "oauth-authz-req+jwt", "x5c": party.x5c}, payload)


def wallet_url(party: RelyingParty, request_uri: str, scheme: str = "openid4vp://") -> str:
    """What the QR code (or a same-device link) carries."""
    return scheme + "?" + urllib.parse.urlencode({
        "client_id": party.client_id, "request_uri": request_uri, "request_uri_method": "get"})


def public_encryption_jwk(key: dict) -> dict:
    """A public P-256 JWK, as the request names it (kid, use and alg added)."""
    if key.get("kty") != "EC" or key.get("crv") != "P-256" or "d" in key or not key.get("x") or not key.get("y"):
        raise ValueError("the encryption key must be a public P-256 JWK")
    return {"kty": "EC", "crv": "P-256", "x": key["x"], "y": key["y"],
            "use": "enc", "alg": "ECDH-ES", "kid": key.get("kid") or secrets.token_urlsafe(8)}


@dataclass
class PresentationRequest:
    party: RelyingParty
    response_uri: str
    claims: tuple[str, ...]
    nonce: str
    state: str
    response_jwk: dict                     # public, as the request names it
    response_key: jwk.JWK | None = None    # private, when this request made it
    doctype: str = PID_DOCTYPE
    query_id: str = "pid"

    @classmethod
    def new(cls, party: RelyingParty, response_uri: str, claims, *, nonce: str | None = None,
            response_jwk: dict | None = None, doctype: str = PID_DOCTYPE, query_id: str = "pid",
            check_claims: bool = True) -> "PresentationRequest":
        claims = tuple(claims)
        if not claims:
            raise ValueError("ask for at least one claim")
        if check_claims:
            if not party.rc:
                raise ValueError("no registration certificate: a wallet refuses the request")
            missing = [c for c in claims if (doctype, c) not in party.allowed_claims]
            if missing:
                raise ValueError(f"the registration certificate doesn't allow {missing}")
        private = None
        if response_jwk is None:
            private = jwk.JWK.generate(kty="EC", crv="P-256", use="enc", alg="ECDH-ES",
                                       kid=secrets.token_urlsafe(8))
            response_jwk = json.loads(private.export_public())
        return cls(party=party, response_uri=response_uri, claims=claims,
                   nonce=nonce or secrets.token_urlsafe(32), state=secrets.token_urlsafe(16),
                   response_jwk=public_encryption_jwk(response_jwk), response_key=private,
                   doctype=doctype, query_id=query_id)

    @property
    def handover(self) -> Handover:
        """What the wallet's device signature will cover: keep it with the presentation."""
        return Handover(self.party.client_id, self.nonce, jwk_thumbprint(self.response_jwk), self.response_uri)

    @property
    def dcql(self) -> dict:
        return pid_dcql(self.claims, self.doctype, self.query_id)

    def signed(self, now: int | None = None) -> str:
        return request_object(self.party, nonce=self.nonce, state=self.state, response_uri=self.response_uri,
                              response_jwk=self.response_jwk, dcql=self.dcql, now=now)

    def wallet_url(self, request_uri: str, scheme: str = "openid4vp://") -> str:
        return wallet_url(self.party, request_uri, scheme)

    def open(self, post_body: bytes | str) -> Answer:
        """The wallet's POST, decrypted. ValueError if the state isn't ours."""
        if self.response_key is None:
            raise ValueError("the response is encrypted to a key held elsewhere (response_jwk)")
        answer = open_response(jwe_from_post(post_body), self.response_key, self.query_id)
        if answer.state != self.state:
            raise ValueError("the response's state is not this request's")
        return answer

    def verify(self, post_body: bytes | str, trust, now=None):
        """Open the POST and run every check: a VerifiedPid."""
        from eudi_pid.verify import verify_pid
        return verify_pid(self.open(post_body).device_response, self.handover, trust, now, doctype=self.doctype)
