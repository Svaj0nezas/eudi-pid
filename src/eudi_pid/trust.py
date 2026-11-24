"""Which PID providers to trust, and the `Trust` a verification is given.

The German sandbox publishes mock trust lists (ETSI TS 119 602 "List of
Trusted Entities", a signed JWT) at GERMAN_SANDBOX_LIST, signed by the "LoTE
Signer" certificate published next to it. That certificate ships with this
package (data/german-sandbox-lote-signer.pem) and is pinned.

Each trusted entity lists services with their CA certificates:

    .../SvcType/PID/Issuance     CAs that sign PID Document Signers
    .../SvcType/PID/Revocation   CAs that sign status lists

The list says when the next one is due (NextUpdate, about daily). A stale
list is still used, and verification says so in its detail: keep a cached
copy (`refresh(path)` daily, `load(path)` at start) so you can run offline.

    trust = Trust.from_trust_list(load("pid-provider-trust-list.jwt"))
    trust = Trust.from_trust_list(fetch())                 # no cache
"""

from __future__ import annotations

import base64
import datetime
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

from cryptography import x509

from eudi_pid.jose import verify_es256_jwt

GERMAN_SANDBOX_LIST = "https://bmi.usercontent.opencode.de/eudi-wallet/test-trust-lists/pid-provider.jwt"
ISSUANCE = "http://uri.etsi.org/19602/SvcType/PID/Issuance"
REVOCATION = "http://uri.etsi.org/19602/SvcType/PID/Revocation"


def bundled(name: str) -> x509.Certificate:
    """A certificate shipped in eudi_pid/data: "german-sandbox-lote-signer.pem",
    "german-registrar-ca.pem"."""
    return x509.load_pem_x509_certificate(resources.files("eudi_pid.data").joinpath(name).read_bytes())


def german_sandbox_signer() -> x509.Certificate:
    return bundled("german-sandbox-lote-signer.pem")


def german_registrar_ca() -> x509.Certificate:
    """The CA that issues access certificates in the German sandbox: what a
    wallet checks a relying party against."""
    return bundled("german-registrar-ca.pem")


@dataclass
class PidTrustList:
    issuance: list[x509.Certificate] = field(default_factory=list)
    revocation: list[x509.Certificate] = field(default_factory=list)
    issued: datetime.datetime | None = None
    next_update: datetime.datetime | None = None

    def staleness(self, now: datetime.datetime) -> str | None:
        """None while fresh; otherwise how stale, for a check's detail."""
        if self.next_update and now > self.next_update:
            return f"trust list due for update since {self.next_update:%Y-%m-%d %H:%M} UTC"
        return None


def _time(text: str | None) -> datetime.datetime | None:
    return datetime.datetime.fromisoformat(text.replace("Z", "+00:00")) if text else None


def read_trust_list(token: str, signer: x509.Certificate | None = None) -> PidTrustList:
    """Check the list's signature against `signer` (default: the bundled German
    sandbox LoTE Signer) and read its CAs. ValueError if anything is off."""
    signer = signer or german_sandbox_signer()
    try:
        _, body = verify_es256_jwt(token, signer.public_key())
    except ValueError as error:
        if "signature" in str(error):
            raise ValueError("the trust list is not signed by the pinned LoTE signer") from None
        raise ValueError(f"not a trust list: {error}") from None
    try:
        lote = body["LoTE"]
        info = lote["ListAndSchemeInformation"]
    except (KeyError, TypeError):
        raise ValueError("not a trust list: no LoTE") from None
    found = PidTrustList(issued=_time(info.get("ListIssueDateTime")), next_update=_time(info.get("NextUpdate")))
    for entity in lote.get("TrustedEntitiesList", []):
        for service in entity.get("TrustedEntityServices", []):
            si = service["ServiceInformation"]
            target = {ISSUANCE: found.issuance, REVOCATION: found.revocation}.get(si.get("ServiceTypeIdentifier"))
            if target is None:
                continue
            for item in si.get("ServiceDigitalIdentity", {}).get("X509Certificates", []):
                cert = x509.load_der_x509_certificate(base64.b64decode(item["val"]))
                if cert not in target:
                    target.append(cert)
    return found


def _signer(signer_path: Path | str | None) -> x509.Certificate:
    return x509.load_pem_x509_certificate(Path(signer_path).read_bytes()) if signer_path else german_sandbox_signer()


def load(path: Path | str, signer_path: Path | str | None = None) -> PidTrustList:
    """A cached list, checked again."""
    return read_trust_list(Path(path).read_text(), _signer(signer_path))


def fetch(url: str = GERMAN_SANDBOX_LIST, signer_path: Path | str | None = None) -> tuple[PidTrustList, str]:
    """The current list, checked: (list, the token as fetched)."""
    with urllib.request.urlopen(url, timeout=20) as response:
        token = response.read().decode()
    return read_trust_list(token, _signer(signer_path)), token


def refresh(path: Path | str, url: str = GERMAN_SANDBOX_LIST, signer_path: Path | str | None = None) -> PidTrustList:
    """Fetch, check, and keep the list at `path` (only if it checks out)."""
    found, token = fetch(url, signer_path)
    Path(path).write_text(token.strip() + "\n")
    return found


# (status list uri, index) -> revoked? Raises if it can't tell.
StatusLookup = Callable[[str, int], bool]


@dataclass
class Trust:
    """What a verification trusts: PID provider roots and a status lookup.

    `freshness(now)` returns a note when the roots' source is out of date (a
    trust list past NextUpdate); it is shown, not failed.
    """
    pid_roots: list[x509.Certificate]
    is_revoked: StatusLookup
    freshness: Callable[[datetime.datetime], str | None] | None = None

    @classmethod
    def from_trust_list(cls, trust_list: PidTrustList, extra_roots: list[x509.Certificate] = (),
                        fetch=None) -> "Trust":
        """Issuance CAs as roots; status lists checked against the revocation CAs.
        `extra_roots` are trusted for both (e.g. a test PID provider)."""
        from eudi_pid.status import StatusLists
        extra = list(extra_roots)
        return cls(trust_list.issuance + extra, StatusLists(trust_list.revocation + extra, fetch).is_revoked,
                   freshness=trust_list.staleness)
