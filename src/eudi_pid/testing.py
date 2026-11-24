"""A PID provider and an EUDI wallet in software: for tests, and for demos with
no phone at hand.

The provider issues an mdoc PID the way the German sandbox does: doctype and
namespace `eu.europa.ec.eudi.pid.1`, each element tag-24 wrapped with its own
salt, an MSO signed by a Document Signer that chains to the provider's root,
and an entry in a status list. The wallet presents it over OpenID4VP 1.0: a
DeviceResponse whose device signature covers the handover, inside a JWE
(ECDH-ES, A128CBC-HS256) with apu/apv, as the German wallet does.

    provider, wallet = SimulatedPidProvider(), SimulatedWallet()
    pid = provider.issue({"given_name": "Erika", "family_name": "Mustermann"}, wallet.public_jwk)
    response_uri, body = wallet.answer(request.signed(), pid)    # POST body for response_uri
    trust = Trust([provider.root], provider.is_revoked)

Nothing real trusts this provider's root, and nothing should.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import secrets
import urllib.parse
import zlib
from pathlib import Path

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from jwcrypto import jwe, jwk

from eudi_pid.jose import b64u, json_compact, jwk_thumbprint, raw_ecdsa, unb64u
from eudi_pid.mdoc import COSE_X5CHAIN, PID_DOCTYPE, device_authentication

# ISO/IEC 18013-5 Annex B: id-mdl-kp-mdlDS, the Document Signer's key purpose.
MDOC_DS_EKU = x509.ObjectIdentifier("1.0.18013.5.1.2")


def _certificate(subject: str, key, issuer_name: x509.Name, issuer_key, days: int, ca: bool):
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder()
               .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
               .issuer_name(issuer_name)
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(minutes=5))
               .not_valid_after(now + datetime.timedelta(days=days))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True))
    if ca:
        builder = builder.add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
            encipher_only=False, decipher_only=False), critical=True)
    else:
        builder = builder.add_extension(x509.ExtendedKeyUsage([MDOC_DS_EKU]), critical=True)
    return builder.sign(issuer_key, hashes.SHA256())


def _tdate(moment: datetime.datetime) -> cbor2.CBORTag:
    """ISO 18013-5 `tdate`: tag 0, whole seconds, UTC with a Z."""
    return cbor2.CBORTag(0, moment.strftime("%Y-%m-%dT%H:%M:%SZ"))


def _cose_device_key(holder_jwk: dict) -> dict:
    if holder_jwk.get("kty") != "EC" or holder_jwk.get("crv") != "P-256":
        raise ValueError(f"only P-256 device keys, got {holder_jwk.get('crv')}")
    return {1: 2, -1: 1, -2: unb64u(holder_jwk["x"]), -3: unb64u(holder_jwk["y"])}


def issue_mdoc(signer_key, signer_der: bytes, doctype: str, claims: dict, holder_jwk: dict, status: dict,
               valid_from: datetime.datetime, valid_until: datetime.datetime,
               namespace: str | None = None) -> dict:
    """One mdoc copy (IssuerSigned, as a CBOR-ready dict) signed by a Document Signer."""
    namespace = namespace or doctype
    items, digests = [], {}
    for digest_id, (name, value) in enumerate(claims.items()):
        item = cbor2.CBORTag(24, cbor2.dumps({"digestID": digest_id, "random": secrets.token_bytes(16),
                                              "elementIdentifier": name, "elementValue": value}))
        items.append(item)
        digests[digest_id] = hashlib.sha256(cbor2.dumps(item)).digest()
    mso = {
        "version": "1.0", "digestAlgorithm": "SHA-256",
        "valueDigests": {namespace: digests},
        "deviceKeyInfo": {"deviceKey": _cose_device_key(holder_jwk)},
        "docType": doctype,
        "validityInfo": {"signed": _tdate(valid_from), "validFrom": _tdate(valid_from),
                         "validUntil": _tdate(valid_until)},
        "status": {"status_list": status},
    }
    protected = cbor2.dumps({1: -7})                       # ES256
    payload = cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(mso)))
    signature = raw_ecdsa(signer_key, cbor2.dumps(["Signature1", protected, b"", payload]))
    return {"nameSpaces": {namespace: items},
            "issuerAuth": [protected, {COSE_X5CHAIN: signer_der}, payload, signature]}


class SimulatedPidProvider:
    """A root CA, a Document Signer under it, and a status list.

    In memory by default. `persistent(folder, status_uri)` keeps the keys in
    `folder`, so a separately running verifier can trust `root.pem` across
    restarts.
    """

    def __init__(self, name: str = "Simulated PID Provider",
                 status_uri: str = "https://pid-provider.invalid/status/1", _keys=None):
        if _keys:
            root_key, self.root, self.key, self.certificate = _keys
        else:
            root_key = ec.generate_private_key(ec.SECP256R1())
            root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{name} Root CA")])
            self.root = _certificate(f"{name} Root CA", root_key, root_name, root_key, days=3650, ca=True)
            self.key = ec.generate_private_key(ec.SECP256R1())          # the Document Signer's
            self.certificate = _certificate(f"{name} Document Signer", self.key, self.root.subject,
                                            root_key, days=365, ca=False)
        self._root_key = root_key
        self.der = self.certificate.public_bytes(serialization.Encoding.DER)
        self.status_uri = status_uri
        self.revoked: set[int] = set()
        self._next_index = 1000

    @classmethod
    def persistent(cls, folder, status_uri: str) -> "SimulatedPidProvider":
        """Made once in `folder` (root.pem is what a verifier trusts), then reused."""
        folder = Path(folder)
        files = {name: folder / f"{name}.pem" for name in ("root-key", "root", "signer-key", "signer")}
        if not all(f.exists() for f in files.values()):
            fresh = cls(status_uri=status_uri)
            folder.mkdir(parents=True, exist_ok=True)
            pem_key = lambda k: k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                serialization.NoEncryption())
            files["root-key"].write_bytes(pem_key(fresh._root_key))
            files["signer-key"].write_bytes(pem_key(fresh.key))
            files["root"].write_bytes(fresh.root.public_bytes(serialization.Encoding.PEM))
            files["signer"].write_bytes(fresh.certificate.public_bytes(serialization.Encoding.PEM))
        load_key = lambda f: serialization.load_pem_private_key(f.read_bytes(), password=None)
        provider = cls(status_uri=status_uri, _keys=(
            load_key(files["root-key"]), x509.load_pem_x509_certificate(files["root"].read_bytes()),
            load_key(files["signer-key"]), x509.load_pem_x509_certificate(files["signer"].read_bytes())))
        # Indices never repeat across restarts: start after a time-based counter.
        provider._next_index = 1000 + int(datetime.datetime.now().timestamp()) % 100_000 * 10
        return provider

    def status_list(self, entries: int = 1 << 20, ttl: int = 0) -> str:
        """The signed status list (1 bit per entry) to serve at `status_uri`.
        ttl 0 by default: a revocation shows at once."""
        bits = bytearray(entries // 8)
        for index in self.revoked:
            bits[index // 8] |= 1 << (index % 8)
        header = {"alg": "ES256", "typ": "statuslist+jwt", "x5c": [base64.b64encode(self.der).decode()]}
        now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        payload = {"sub": self.status_uri, "iat": now, "exp": now + 3600, "ttl": ttl,
                   "status_list": {"bits": 1, "lst": b64u(zlib.compress(bytes(bits), 9))}}
        signing_input = f"{b64u(json_compact(header))}.{b64u(json_compact(payload))}"
        return f"{signing_input}.{b64u(raw_ecdsa(self.key, signing_input.encode()))}"

    def issue(self, claims: dict, device_public_jwk: dict, valid_days: int = 14,
              valid_from: datetime.datetime | None = None, doctype: str = PID_DOCTYPE) -> dict:
        """One PID copy (IssuerSigned) bound to the wallet's device key."""
        start = valid_from or datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
        index, self._next_index = self._next_index, self._next_index + 1
        return issue_mdoc(self.key, self.der, doctype, claims, device_public_jwk,
                          {"idx": index, "uri": self.status_uri}, start, start + datetime.timedelta(days=valid_days))

    def revoke(self, issuer_signed: dict) -> int:
        """Revoke one issued copy; returns its status index."""
        from eudi_pid.mdoc import mso_of
        index = mso_of(issuer_signed["issuerAuth"])["status"]["status_list"]["idx"]
        self.revoked.add(index)
        return index

    def is_revoked(self, uri: str, index: int) -> bool:
        """A status lookup for Trust: is entry `index` of `uri` revoked?"""
        if uri != self.status_uri:
            raise LookupError(f"unknown status list {uri}")
        return index in self.revoked


class SimulatedWallet:
    """A device key, and presentations signed with it."""

    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.public_jwk = json.loads(jwk.JWK.from_pyca(self.key.public_key()).export_public())

    def present(self, issuer_signed: dict, *, client_id: str, nonce: str, jwk_thumbprint: bytes,
                response_uri: str, disclose: set[str] | None = None, doctype: str = PID_DOCTYPE) -> bytes:
        """A DeviceResponse, device-signed over the OpenID4VP 1.0 handover.
        `disclose` keeps only those element identifiers; None keeps all."""
        issuer_signed = dict(issuer_signed)
        if disclose is not None:
            issuer_signed["nameSpaces"] = {
                namespace: [item for item in items if cbor2.loads(item.value)["elementIdentifier"] in disclose]
                for namespace, items in issuer_signed["nameSpaces"].items()}
        info = cbor2.dumps([client_id, nonce, jwk_thumbprint, response_uri])
        transcript = [None, None, ["OpenID4VPHandover", hashlib.sha256(info).digest()]]
        device_namespaces = cbor2.CBORTag(24, cbor2.dumps({}))
        protected = cbor2.dumps({1: -7})
        signature = raw_ecdsa(self.key, cbor2.dumps(
            ["Signature1", protected, b"", device_authentication(transcript, doctype, device_namespaces)]))
        document = {"docType": doctype, "issuerSigned": issuer_signed,
                    "deviceSigned": {"nameSpaces": device_namespaces,
                                     "deviceAuth": {"deviceSignature": [protected, {}, None, signature]}}}
        return cbor2.dumps({"version": "1.0", "documents": [document], "status": 0})

    def answer(self, request_jwt: str, issuer_signed: dict, disclose: set[str] | None = None) -> tuple[str, bytes]:
        """Answer a request object as the German wallet does (direct_post.jwt).
        Returns (response_uri, the form body to POST there). The request's
        signature is NOT checked: a real wallet checks it against the
        registrar's CA."""
        request = json.loads(unb64u(request_jwt.split(".")[1]))
        key = request["client_metadata"]["jwks"]["keys"][0]
        query = request["dcql_query"]["credentials"][0]
        wanted = {claim["path"][-1] for claim in query["claims"]}
        doctype = (query.get("meta") or {}).get("doctype_value", PID_DOCTYPE)
        response = self.present(issuer_signed, client_id=request["client_id"], nonce=request["nonce"],
                                jwk_thumbprint=jwk_thumbprint(key), response_uri=request["response_uri"],
                                disclose=wanted if disclose is None else disclose & wanted, doctype=doctype)
        payload = {"vp_token": {query["id"]: [b64u(response)]}, "state": request["state"]}
        protected = {"alg": "ECDH-ES", "enc": "A128CBC-HS256", "kid": key.get("kid"),
                     "apu": b64u(secrets.token_urlsafe(16).encode()), "apv": b64u(request["nonce"].encode())}
        token = jwe.JWE(json.dumps(payload).encode(), protected=json.dumps(protected))
        token.add_recipient(jwk.JWK(**{k: key[k] for k in ("kty", "crv", "x", "y")}))
        return request["response_uri"], urllib.parse.urlencode({"response": token.serialize(compact=True)}).encode()


def fake_party(name: str = "Test Relying Party", claims=("given_name", "family_name", "birth_date"),
               doctype: str = PID_DOCTYPE):
    """A RelyingParty with a self-made certificate and registration certificate.
    No wallet trusts it; SimulatedWallet doesn't check."""
    from eudi_pid.party import ORG_ID_OID, RelyingParty
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name),
                         x509.NameAttribute(ORG_ID_OID, "TEST-0001")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=30))
            .sign(key, hashes.SHA256()))
    rc_payload = {"sub": "TEST-0001", "name": name,
                  "credentials": [{"format": "mso_mdoc", "meta": {"doctype_value": doctype},
                                   "claim": [{"path": [doctype, c]} for c in claims]}]}
    rc_head = b64u(json_compact({"alg": "ES256", "typ": "rc-rp+jwt"}))
    rc_body = b64u(json_compact(rc_payload))
    rc = f"{rc_head}.{rc_body}.{b64u(raw_ecdsa(key, f'{rc_head}.{rc_body}'.encode()))}"
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    return RelyingParty.from_pem(key_pem, cert.public_bytes(serialization.Encoding.PEM), rc)
