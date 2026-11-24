"""Is this PID presentation genuine, current, and made for this request?

    pid = verify_pid(device_response, handover, trust)
    pid.ok             every check passed
    pid.claims         {"given_name": "ERIKA", ...}: only issuer-signed values
    pid.checks         [Check(name, ok, detail), ...], in this order:

    IS_PID          one document of the expected doctype, an MSO for it
    DIGESTS         every disclosed element is what the issuer signed
    ISSUER_SIGNED   the issuer's signature over the MSO is valid
    TRUSTED_ISSUER  its certificate chains to a trusted PID provider
    VALID_NOW       now is within the MSO's validity dates
    NOT_REVOKED     its status list entry is not set (no answer: fails)
    HOLDER_SIGNED   the device signature covers the handover: made for this
                    request (client_id, nonce, response key, response_uri)

If IS_PID fails, it is the only check. Otherwise every check runs, so a
failure shows all its causes at once. Nothing here touches the network
except `trust.is_revoked`, which you supply.

Your own checks (the name matches, the nonce means what you meant) go on
top: `pid.checks.append(Check(...))`.
"""

from __future__ import annotations

import datetime
import hashlib
from dataclasses import dataclass, field

import cbor2
from cryptography import x509

from eudi_pid.certs import chain_problem, root_name
from eudi_pid.mdoc import (COSE_ALG, PID_DOCTYPE, cose_key, cose_parts, cose_verify, device_authentication,
                           mso_of, plain, tdate, x5chain)
from eudi_pid.response import Handover
from eudi_pid.trust import Trust

IS_PID = "it holds a PID"
DIGESTS = "every attribute is what the issuer signed"
ISSUER_SIGNED = "the issuer's signature is valid"
TRUSTED_ISSUER = "the issuer is a trusted PID provider"
VALID_NOW = "the PID is within its validity dates"
NOT_REVOKED = "the PID is not revoked"
HOLDER_SIGNED = "the PID's holder signed this presentation"
CHECKS = (IS_PID, DIGESTS, ISSUER_SIGNED, TRUSTED_ISSUER, VALID_NOW, NOT_REVOKED, HOLDER_SIGNED)


@dataclass
class Check:
    name: str
    ok: bool
    detail: str


@dataclass
class VerifiedPid:
    checks: list[Check] = field(default_factory=list)
    claims: dict = field(default_factory=dict)            # element identifier -> value, issuer-signed
    doctype: str | None = None
    issuer: str | None = None                             # the Document Signer's subject
    valid_from: datetime.datetime | None = None
    valid_until: datetime.datetime | None = None
    status: dict | None = None                            # {"uri", "idx"}
    mso: dict | None = None

    @property
    def ok(self) -> bool:
        return bool(self.checks) and all(c.ok for c in self.checks)

    @property
    def failed(self) -> list[Check]:
        return [c for c in self.checks if not c.ok]

    def check(self, name: str) -> Check | None:
        return next((c for c in self.checks if c.name == name), None)


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def verify_pid(device_response: bytes, handover: Handover, trust: Trust,
               now: datetime.datetime | None = None, *, doctype: str = PID_DOCTYPE,
               namespace: str | None = None) -> VerifiedPid:
    """Every check above on one DeviceResponse. `handover` is anything with
    `session_transcript()` (and ideally `client_id`); `namespace` defaults to
    the doctype, which is where a PID keeps its elements."""
    now = now or datetime.datetime.now(datetime.timezone.utc)
    namespace = namespace or doctype
    result = VerifiedPid(doctype=doctype)

    def check(name: str, ok, detail: str) -> bool:
        result.checks.append(Check(name, bool(ok), detail))
        return bool(ok)

    try:
        documents = cbor2.loads(device_response)["documents"]
        if len(documents) != 1 or documents[0]["docType"] != doctype:
            raise ValueError(f"{len(documents)} document(s): {[d.get('docType') for d in documents]}")
        document = documents[0]
        issuer_signed = document["issuerSigned"]
        protected, unprotected, protected_raw, payload, signature = cose_parts(issuer_signed["issuerAuth"])
        mso = mso_of(issuer_signed["issuerAuth"])
        if mso.get("docType") != doctype:
            raise ValueError(f"the MSO is for {mso.get('docType')}")
    except Exception as error:
        check(IS_PID, False, f"{type(error).__name__}: {error}")
        return result
    result.mso = mso
    check(IS_PID, True, doctype)

    # Each disclosed element, hashed as its tag-24 bytes, is a digest in the MSO.
    digests = mso.get("valueDigests") or {}
    bad = []
    for ns, items in (issuer_signed.get("nameSpaces") or {}).items():
        for item in items:
            element = cbor2.loads(item.value)
            committed = (digests.get(ns) or {}).get(element.get("digestID"))
            if committed != _sha256(cbor2.dumps(item)):
                bad.append(element.get("elementIdentifier"))
            elif ns == namespace:
                result.claims[element["elementIdentifier"]] = plain(element["elementValue"])
    check(DIGESTS, not bad and result.claims,
          f"not matching: {', '.join(map(str, bad))}" if bad
          else f"{len(result.claims)} attributes: {', '.join(result.claims)}")

    # The issuer's signature, and where its certificate leads.
    chain = [x509.load_der_x509_certificate(der) for der in x5chain(unprotected)]
    try:
        if not chain:
            raise ValueError("no certificate in x5chain")
        cose_verify(chain[0].public_key(), protected.get(COSE_ALG), protected_raw, payload, signature)
        result.issuer = chain[0].subject.rfc4514_string()
        check(ISSUER_SIGNED, True, f"by {result.issuer}")
    except Exception as error:
        check(ISSUER_SIGNED, False, f"{type(error).__name__}: {error}")
    problem = chain_problem(chain, trust.pid_roots, now)
    if problem and problem.endswith("is not a trusted root"):
        problem = problem.replace("is not a trusted root", "is not a trusted PID provider")
    stale = trust.freshness(now) if trust.freshness else None
    check(TRUSTED_ISSUER, problem is None,
          (problem or f"chains to {root_name(chain, trust.pid_roots)}") + (f"; {stale}" if stale else ""))

    # Validity and status: as of `now`, not as of the presentation.
    validity = mso.get("validityInfo") or {}
    result.valid_from, result.valid_until = tdate(validity.get("validFrom")), tdate(validity.get("validUntil"))
    vf, vu = result.valid_from, result.valid_until
    check(VALID_NOW, vf is not None and vu is not None and vf <= now < vu,
          f"valid {vf:%Y-%m-%d %H:%M} to {vu:%Y-%m-%d %H:%M} UTC" if vf and vu else "no validity dates")
    status = (mso.get("status") or {}).get("status_list") or {}
    result.status = status or None
    try:
        if "uri" not in status or "idx" not in status:
            raise ValueError("the PID names no status list")
        revoked = trust.is_revoked(status["uri"], status["idx"])
        check(NOT_REVOKED, not revoked, f"entry {status['idx']} of {status['uri']}: "
                                        f"{'revoked' if revoked else 'not set'}")
    except Exception as error:                                # can't tell: refuse
        check(NOT_REVOKED, False, f"could not check: {error}")

    # Holder binding: the device key the MSO binds signed over our handover.
    try:
        device_signed = document["deviceSigned"]
        d_protected, _, d_protected_raw, _, d_signature = cose_parts(device_signed["deviceAuth"]["deviceSignature"])
        authentication = device_authentication(handover.session_transcript(), doctype, device_signed["nameSpaces"])
        cose_verify(cose_key(mso["deviceKeyInfo"]["deviceKey"]), d_protected.get(COSE_ALG),
                    d_protected_raw, authentication, d_signature)
        check(HOLDER_SIGNED, True, f"over the request of {getattr(handover, 'client_id', '?')}")
    except Exception as error:
        check(HOLDER_SIGNED, False, f"{type(error).__name__}: {error}" if str(error)
              else "the device signature does not cover this handover")
    return result
