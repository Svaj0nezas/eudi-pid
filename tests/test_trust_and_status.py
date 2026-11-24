"""The German sandbox's PID trust list (a snapshot) and status list checks."""

from __future__ import annotations

import base64
import datetime
import json
import time
import unittest
import zlib
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from eudi_pid import trust_list
from eudi_pid.jose import b64u, raw_ecdsa
from eudi_pid.status import StatusLists, entry, read_status_list
from eudi_pid.testing import SimulatedPidProvider

SNAPSHOT = Path(__file__).parent / "data" / "pid-provider-trust-list.jwt"
URI = "https://pid-provider.invalid/status/7"


def status_token(provider: SimulatedPidProvider, statuses: list[int], bits: int = 1, sub: str = URI, **extra) -> str:
    raw = bytearray((len(statuses) * bits + 7) // 8)
    for i, value in enumerate(statuses):
        raw[i * bits // 8] |= value << (i * bits % 8)
    header = {"alg": "ES256", "typ": "statuslist+jwt",
              "x5c": [base64.b64encode(provider.certificate.public_bytes(serialization.Encoding.DER)).decode()]}
    payload = {"sub": sub, "iat": int(time.time()),
               "status_list": {"bits": bits, "lst": b64u(zlib.compress(bytes(raw)))}, **extra}
    signing_input = f"{b64u(json.dumps(header).encode())}.{b64u(json.dumps(payload).encode())}"
    return f"{signing_input}.{b64u(raw_ecdsa(provider.key, signing_input.encode()))}"


class TrustList(unittest.TestCase):
    def test_the_snapshot_names_the_german_pid_providers(self):
        found = trust_list.load(SNAPSHOT)                 # checked against the bundled signer
        names = {c.subject.rfc4514_string() for c in found.issuance}
        self.assertTrue(any("PIDP Preprod CA" in n and "Bundesdruckerei" in n for n in names), names)
        self.assertTrue(found.revocation)

    def test_a_changed_list_is_refused(self):
        header, payload, signature = SNAPSHOT.read_text().strip().split(".")
        body = json.loads(base64.urlsafe_b64decode(payload + "=="))
        body["LoTE"]["TrustedEntitiesList"] = []
        forged = ".".join([header, b64u(json.dumps(body).encode()), signature])
        with self.assertRaisesRegex(ValueError, "pinned"):
            trust_list.read_trust_list(forged)

    def test_another_signer_is_refused(self):
        stranger = SimulatedPidProvider().root
        with self.assertRaisesRegex(ValueError, "pinned"):
            trust_list.read_trust_list(SNAPSHOT.read_text(), stranger)

    def test_staleness(self):
        found = trust_list.load(SNAPSHOT)
        self.assertIsNone(found.staleness(found.issued))
        self.assertIn("due for update", found.staleness(found.next_update + datetime.timedelta(minutes=1)))

    def test_bundled_certificates(self):
        self.assertIn("LoTE Signer", trust_list.german_sandbox_signer().subject.rfc4514_string())
        self.assertTrue(trust_list.german_registrar_ca().subject.rfc4514_string())

    def test_trust_from_the_list(self):
        found = trust_list.load(SNAPSHOT)
        extra = SimulatedPidProvider().root
        trust = trust_list.Trust.from_trust_list(found, [extra])
        self.assertEqual(trust.pid_roots, found.issuance + [extra])
        self.assertIsNone(trust.freshness(found.issued))


class StatusList(unittest.TestCase):
    def test_bit_layout_from_the_draft(self):
        # draft-ietf-oauth-status-list, 1-bit example: statuses 1,0,0,1,1,1,0,1,1,1,0,0,0,1,0,1 → b9 a3
        lst = bytes([0xB9, 0xA3])
        self.assertEqual([entry(lst, i, 1) for i in range(16)], [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1])
        self.assertEqual([entry(bytes([0b11_10_01_00]), i, 2) for i in range(4)], [0, 1, 2, 3])
        with self.assertRaises(ValueError):
            entry(lst, 16, 1)

    def test_a_signed_list(self):
        provider = SimulatedPidProvider()
        lists = StatusLists([provider.root], fetch=lambda uri: status_token(provider, [0, 1, 0, 0, 2], bits=2))
        self.assertEqual([lists.is_revoked(URI, i) for i in range(5)], [False, True, False, False, True])

    def test_the_providers_own_list(self):
        provider = SimulatedPidProvider(status_uri=URI)
        provider.revoked.add(5)
        lists = StatusLists([provider.root], fetch=lambda uri: provider.status_list(entries=64))
        self.assertEqual([lists(URI, i) for i in (4, 5)], [False, True])

    def test_refused_tokens(self):
        provider, stranger = SimulatedPidProvider(), SimulatedPidProvider()
        cases = {
            "signed by an untrusted CA": (status_token(stranger, [0]), "no trusted"),
            "for another list": (status_token(provider, [0], sub="https://other"), "not " + URI),
            "expired": (status_token(provider, [0], exp=int(time.time()) - 1), "expired"),
        }
        for name, (token, message) in cases.items():
            with self.subTest(case=name), self.assertRaisesRegex(ValueError, message):
                read_status_list(token, URI, [provider.root])


if __name__ == "__main__":
    unittest.main()
