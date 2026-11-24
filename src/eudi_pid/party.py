"""The relying party: its key, its access certificate, its registration certificate.

These three files are what the German sandbox hands a participant (the key is
the one you generated for your CSR). Nothing here talks to the sandbox: the
wallet checks the access certificate against the registrar's CA, and the
registration certificate tells it what you may ask for.

    rp = RelyingParty.from_files("access-private.key", "access-chain.pem",
                                 "registration-certificate.jwt")
    rp.client_id           x509_hash:<b64u sha256 of the leaf>
    rp.allowed_claims      {("eu.europa.ec.eudi.pid.1", "given_name"), ...}
    rp.registration_status()   "valid" / "REVOKED" / "unknown (...)"

The registration certificate must be the one for the format you ask in: the
German sandbox issues separate ones for mdoc and SD-JWT VC, and a wallet
answers "you need a valid credential" to a mismatch, as it does to a revoked
registration certificate or an expired PID.
"""

from __future__ import annotations

import base64
import hashlib
import json
import urllib.request
import zlib

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from jwcrypto import jwk

from eudi_pid.jose import b64u, json_compact, jwt_parts, raw_ecdsa, unb64u

# ETSI EN 319 412-1 puts the registered organisation identifier here.
ORG_ID_OID = x509.ObjectIdentifier("2.5.4.97")


def _pem_chain(pem: bytes) -> list[x509.Certificate]:
    marker = b"-----BEGIN CERTIFICATE-----"
    return [x509.load_pem_x509_certificate(marker + block) for block in pem.split(marker)[1:]]


class RelyingParty:
    """`Party(key_path, chain_path, rc_path)` keeps the old positional form;
    `from_files` and `from_pem` are the clearer ones."""

    def __init__(self, key_path: str, ac_path: str, rc_path: str | None = None):
        with open(key_path, "rb") as handle:
            key_pem = handle.read()
        with open(ac_path, "rb") as handle:
            chain_pem = handle.read()
        rc = None
        if rc_path:
            with open(rc_path) as handle:
                rc = handle.read()
        self._load(key_pem, chain_pem, rc)

    @classmethod
    def from_files(cls, key: str, chain: str, registration: str | None = None) -> "RelyingParty":
        return cls(str(key), str(chain), str(registration) if registration else None)

    @classmethod
    def from_pem(cls, key_pem: bytes, chain_pem: bytes, registration: str | None = None) -> "RelyingParty":
        party = cls.__new__(cls)
        party._load(key_pem, chain_pem, registration)
        return party

    def _load(self, key_pem: bytes, chain_pem: bytes, registration: str | None) -> None:
        self.key = serialization.load_pem_private_key(key_pem, password=None)
        self.chain = _pem_chain(chain_pem)
        if not self.chain:
            raise ValueError("the access certificate file holds no certificate")
        if self.key.public_key().public_bytes(serialization.Encoding.DER,
                                              serialization.PublicFormat.SubjectPublicKeyInfo) != \
                self.chain[0].public_key().public_bytes(serialization.Encoding.DER,
                                                        serialization.PublicFormat.SubjectPublicKeyInfo):
            raise ValueError("the private key is not the access certificate's key")
        self.x5c = [base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode() for c in self.chain]

        self.rc = registration.strip() if registration else None
        self.rc_claims = jwt_parts(self.rc)[1] if self.rc else {}

        leaf = self.chain[0].public_bytes(serialization.Encoding.DER)
        # The wallet pins the certificate itself: the client identifier IS its
        # hash, so no one without this private key can act under this name.
        self.client_id = "x509_hash:" + b64u(hashlib.sha256(leaf).digest())
        self.alg = "EdDSA" if isinstance(self.key, ed25519.Ed25519PrivateKey) else "ES256"

        registered = self.chain[0].subject.get_attributes_for_oid(ORG_ID_OID)
        self.registry_id = registered[0].value if registered else None
        if self.rc and self.registry_id != self.rc_claims.get("sub"):
            raise ValueError(f"the certificate is issued to {self.registry_id} but the "
                             f"registration certificate names {self.rc_claims.get('sub')}")

    # -- what the registration certificate allows -------------------------- #

    @property
    def name(self) -> str:
        return self.rc_claims.get("name") or self.chain[0].subject.rfc4514_string().split(",")[0]

    @property
    def registered_credential(self) -> dict:
        """The first credential the registration certificate is about:
        {"format": "mso_mdoc", "meta": {"doctype_value": ...}, "claim": [{"path": [...]}, ...]}."""
        credentials = self.rc_claims.get("credentials") or []
        if not credentials:
            raise ValueError("no registration certificate, or it names no credential")
        return credentials[0]

    @property
    def allowed_claims(self) -> set[tuple[str, ...]]:
        """Every claim path the registration certificate allows, across its credentials."""
        return {tuple(c["path"]) for cred in self.rc_claims.get("credentials") or []
                for c in cred.get("claim") or []}

    def registration_status(self, timeout: float = 10) -> str:
        """Is the registration certificate still valid? "valid", "REVOKED", or
        "unknown (...)". A wallet checks this, and a revoked one fails every
        request with "you need a valid credential", which names no cause."""
        from eudi_pid.status import entry
        status = (self.rc_claims.get("status") or {}).get("status_list") or {}
        if "uri" not in status:
            return "unknown (it names no status list)"
        try:
            request = urllib.request.Request(status["uri"], headers={"Accept": "application/statuslist+jwt"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                token = response.read().decode()
            body = json.loads(unb64u(token.split(".")[1]))
            lst = zlib.decompress(unb64u(body["status_list"]["lst"]))
            revoked = entry(lst, status["idx"], body["status_list"]["bits"]) != 0
        except Exception as error:                         # offline: say so, don't block
            return f"unknown (could not fetch its status list: {error})"
        return "REVOKED" if revoked else "valid"

    def request(self, response_uri: str, claims, **options):
        """A PresentationRequest (see eudi_pid.request) from this party."""
        from eudi_pid.request import PresentationRequest
        return PresentationRequest.new(self, response_uri, claims, **options)

    # -- signing ------------------------------------------------------------ #

    def sign(self, header: dict, payload: dict) -> str:
        """A compact JWS with the access certificate's key."""
        signing_input = f"{b64u(json_compact(header))}.{b64u(json_compact(payload))}".encode()
        if isinstance(self.key, ed25519.Ed25519PrivateKey):
            signature = self.key.sign(signing_input)
        else:
            signature = raw_ecdsa(self.key, signing_input)
        return f"{signing_input.decode()}.{b64u(signature)}"

    # -- the public parts --------------------------------------------------- #

    @property
    def public_jwk(self) -> dict:
        pem = self.key.public_key().public_bytes(serialization.Encoding.PEM,
                                                 serialization.PublicFormat.SubjectPublicKeyInfo)
        return json.loads(jwk.JWK.from_pem(pem).export_public())

    @property
    def chain_pem(self) -> str:
        return "".join(c.public_bytes(serialization.Encoding.PEM).decode() for c in self.chain)

    @property
    def thumbprint(self) -> str:
        """base64url SHA-256 of the leaf, as `x5t#S256` carries it."""
        return b64u(hashlib.sha256(self.chain[0].public_bytes(serialization.Encoding.DER)).digest())

    def __repr__(self) -> str:
        return f"RelyingParty({self.name!r}, {self.client_id})"

