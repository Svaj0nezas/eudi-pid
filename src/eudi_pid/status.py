"""Is a PID revoked? The IETF Token Status List, as the German sandbox serves it.

A PID's MSO names its entry: {"status_list": {"uri": ..., "idx": ...}}. The
uri serves a JWT (Accept: application/statuslist+jwt):

    header   {"alg": "ES256", "typ": "statuslist+jwt", "x5c": [signer, ...]}
    payload  {"sub": uri, "iat", "exp"?, "ttl"?, "status_list": {"bits": 1, "lst": b64u(zlib(bytes))}}

Entry i holds `bits` bits, starting at bit (i * bits) of the decompressed
bytes, counted from the least significant bit of each byte. 0 is valid;
anything else (1 revoked, 2 suspended, ...) is not.

The signer must chain to a CA the trust list names for PID revocation.
Answers are cached for the list's ttl (5 minutes if it gives none).
"""

from __future__ import annotations

import base64
import threading
import time
import urllib.request
import zlib

from cryptography import x509

from eudi_pid.certs import issued_by
from eudi_pid.jose import unb64u, verify_es256_jwt, jwt_parts

DEFAULT_TTL = 300


def entry(lst: bytes, index: int, bits: int) -> int:
    """The value of entry `index` in decompressed status bytes."""
    if bits not in (1, 2, 4, 8):
        raise ValueError(f"bits must be 1, 2, 4 or 8, not {bits}")
    position = index * bits
    if index < 0 or position // 8 >= len(lst):
        raise ValueError(f"index {index} is outside the list ({len(lst) * 8 // bits} entries)")
    return (lst[position // 8] >> (position % 8)) & ((1 << bits) - 1)


def read_status_list(token: str, uri: str, trusted: list[x509.Certificate], now: float | None = None) -> dict:
    """Check the token; returns {"bits", "lst" (decompressed), "ttl"}. ValueError if off."""
    now = now if now is not None else time.time()
    try:
        header, _ = jwt_parts(token)
        chain = [x509.load_der_x509_certificate(base64.b64decode(c)) for c in header.get("x5c", [])]
    except Exception as error:
        raise ValueError(f"not a status list token: {error}") from None
    if header.get("typ") != "statuslist+jwt" or header.get("alg") != "ES256":
        raise ValueError(f"typ {header.get('typ')!r}, alg {header.get('alg')!r}")
    if not chain:
        raise ValueError("the status list carries no certificate")
    try:
        _, payload = verify_es256_jwt(token, chain[0].public_key())
    except ValueError:
        raise ValueError("the status list's signature does not verify") from None
    path_ok = all(issued_by(lower, upper) for lower, upper in zip(chain, chain[1:]))
    if not path_ok or not any(chain[-1] == ca or issued_by(chain[-1], ca) for ca in trusted):
        raise ValueError(f"the status list is signed by {chain[0].subject.rfc4514_string()}, "
                         "which no trusted PID revocation CA issued")
    if payload.get("sub") != uri:
        raise ValueError(f"the token is for {payload.get('sub')}, not {uri}")
    if "exp" in payload and now >= payload["exp"]:
        raise ValueError("the status list has expired")
    status = payload["status_list"]
    return {"bits": status["bits"], "lst": zlib.decompress(unb64u(status["lst"])),
            "ttl": int(payload.get("ttl", DEFAULT_TTL))}


class StatusLists:
    """A status lookup: (uri, index) → revoked? Fetches, checks and caches.

    `trusted` are the CAs allowed to sign status lists (a trust list's
    revocation CAs). `fetch(uri) -> token` can be replaced, e.g. in tests.
    """

    def __init__(self, trusted: list[x509.Certificate], fetch=None):
        self.trusted = trusted
        self.fetch = fetch or self._fetch
        self.cache: dict[str, tuple[float, dict]] = {}
        self.lock = threading.Lock()

    @staticmethod
    def _fetch(uri: str) -> str:
        request = urllib.request.Request(uri, headers={"Accept": "application/statuslist+jwt"})
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.read().decode()

    def is_revoked(self, uri: str, index: int) -> bool:
        with self.lock:
            cached = self.cache.get(uri)
            if not cached or time.time() >= cached[0]:
                found = read_status_list(self.fetch(uri), uri, self.trusted)
                cached = (time.time() + found["ttl"], found)
                self.cache[uri] = cached
        found = cached[1]
        return entry(found["lst"], index, found["bits"]) != 0

    __call__ = is_revoked
