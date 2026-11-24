"""The whole round: a request, a (simulated) wallet's answer, every check."""

from __future__ import annotations

import contextlib
import datetime
import io
import json
import unittest

from jwcrypto import jwk

from eudi_pid import (CHECKS, DIGESTS, HOLDER_SIGNED, IS_PID, NOT_REVOKED, PID_DOCTYPE, TRUSTED_ISSUER,
                      VALID_NOW, Handover, Trust, jwe_from_post, open_response, verify_pid)
from eudi_pid.diagnose import verify_mdoc
from eudi_pid.jose import jwt_parts
from eudi_pid.testing import SimulatedPidProvider, SimulatedWallet, fake_party

CLAIMS = {"given_name": "Erika", "family_name": "Mustermann", "birth_date": "1964-08-12",
          "resident_city": "Berlin"}
ASK = ["given_name", "family_name", "birth_date"]
RESPONSE_URI = "https://rp.invalid/response/1"
NOW = datetime.datetime.now(datetime.timezone.utc)


class Round:
    def __init__(self, **issue):
        self.party = fake_party()
        self.provider, self.wallet = SimulatedPidProvider(), SimulatedWallet()
        self.pid = self.provider.issue(CLAIMS, self.wallet.public_jwk, **issue)
        self.trust = Trust([self.provider.root], self.provider.is_revoked)
        self.request = self.party.request(RESPONSE_URI, ASK)

    def answer(self, **kw) -> bytes:
        uri, body = self.wallet.answer(self.request.signed(), self.pid, **kw)
        assert uri == RESPONSE_URI
        return body


def failed(pid) -> set[str]:
    return {c.name for c in pid.failed}


class TheRequest(unittest.TestCase):
    def test_what_the_wallet_is_shown(self):
        r = Round()
        header, body = jwt_parts(r.request.signed())
        self.assertEqual(header["typ"], "oauth-authz-req+jwt")
        self.assertEqual(len(header["x5c"]), 1)
        self.assertEqual(body["client_id"], r.party.client_id)
        self.assertEqual(body["response_mode"], "direct_post.jwt")
        self.assertEqual(body["dcql_query"]["credentials"][0]["meta"], {"doctype_value": PID_DOCTYPE})
        self.assertEqual([c["path"] for c in body["dcql_query"]["credentials"][0]["claims"]],
                         [[PID_DOCTYPE, c] for c in ASK])
        self.assertEqual(body["verifier_info"][0]["data"], r.party.rc)
        self.assertNotIn("d", body["client_metadata"]["jwks"]["keys"][0])
        self.assertTrue(r.request.wallet_url("https://rp.invalid/request/1").startswith("openid4vp://?client_id="))

    def test_claims_outside_the_registration_are_refused(self):
        with self.assertRaisesRegex(ValueError, "doesn't allow"):
            fake_party().request(RESPONSE_URI, ["given_name", "nationality"])

    def test_a_chosen_nonce(self):
        request = fake_party().request(RESPONSE_URI, ASK, nonce="my-nonce")
        self.assertEqual(jwt_parts(request.signed())[1]["nonce"], "my-nonce")
        self.assertEqual(request.handover.nonce, "my-nonce")


class AGoodAnswer(unittest.TestCase):
    def test_every_check_passes(self):
        r = Round()
        pid = r.request.verify(r.answer(), r.trust, NOW)
        self.assertEqual([c.name for c in pid.checks], list(CHECKS))
        self.assertTrue(pid.ok, pid.failed)
        self.assertEqual(pid.claims, {k: CLAIMS[k] for k in ASK})     # only what was asked: selective
        self.assertIn("Simulated PID Provider Document Signer", pid.issuer)
        self.assertIn("idx", pid.status)

    def test_the_diagnostic_agrees(self):
        r = Round()
        answer = r.request.open(r.answer())
        with contextlib.redirect_stdout(io.StringIO()):
            found = verify_mdoc(answer.device_response, {"1.0": r.request.handover.session_transcript()})
        document = found["documents"][0]
        self.assertEqual(document["issuer signature"], "VALID")
        self.assertTrue(document["device signature"].startswith("VALID"))

    def test_a_key_held_elsewhere(self):
        """The browser case: the request names a public key; whoever holds the
        private half decrypts, and anyone with the handover verifies."""
        r = Round()
        browser = jwk.JWK.generate(kty="EC", crv="P-256")
        r.request = r.party.request(RESPONSE_URI, ASK, response_jwk=json.loads(browser.export_public()))
        body = r.answer()
        with self.assertRaisesRegex(ValueError, "held elsewhere"):
            r.request.open(body)
        answer = open_response(jwe_from_post(body), browser)
        self.assertTrue(verify_pid(answer.device_response, r.request.handover, r.trust, NOW).ok)


class RefusedAnswers(unittest.TestCase):
    def test_another_requests_state(self):
        r = Round()
        body = r.answer()
        r.request.state = "someone-else"
        with self.assertRaisesRegex(ValueError, "state"):
            r.request.open(body)

    def test_made_for_another_request(self):
        r = Round()
        device_response = r.request.open(r.answer()).device_response
        h = r.request.handover
        for other in (Handover(h.client_id, "another nonce", h.jwk_thumbprint, h.response_uri),
                      Handover("x509_hash:other", h.nonce, h.jwk_thumbprint, h.response_uri),
                      Handover(h.client_id, h.nonce, bytes(32), h.response_uri),
                      Handover(h.client_id, h.nonce, h.jwk_thumbprint, "https://elsewhere")):
            with self.subTest(other=other):
                self.assertEqual(failed(verify_pid(device_response, other, r.trust, NOW)), {HOLDER_SIGNED})

    def test_an_untrusted_provider(self):
        r = Round()
        stranger = Trust([SimulatedPidProvider().root], r.provider.is_revoked)
        self.assertEqual(failed(r.request.verify(r.answer(), stranger, NOW)), {TRUSTED_ISSUER})

    def test_revoked(self):
        r = Round()
        r.provider.revoke(r.pid)
        self.assertEqual(failed(r.request.verify(r.answer(), r.trust, NOW)), {NOT_REVOKED})

    def test_status_unknown_is_a_refusal(self):
        r = Round()
        def offline(uri, index):
            raise OSError("no network")
        pid = r.request.verify(r.answer(), Trust([r.provider.root], offline), NOW)
        self.assertEqual(failed(pid), {NOT_REVOKED})
        self.assertIn("could not check", pid.check(NOT_REVOKED).detail)

    def test_expired(self):
        r = Round(valid_days=14, valid_from=NOW - datetime.timedelta(days=15))
        self.assertEqual(failed(r.request.verify(r.answer(), r.trust, NOW)), {VALID_NOW})

    def test_a_changed_value(self):
        import cbor2
        r = Round()
        device_response = r.request.open(r.answer()).device_response
        response = cbor2.loads(device_response)
        items = response["documents"][0]["issuerSigned"]["nameSpaces"][PID_DOCTYPE]
        element = cbor2.loads(items[1].value)
        element["elementValue"] = "Musterfrau"
        items[1] = cbor2.CBORTag(24, cbor2.dumps(element))
        pid = verify_pid(cbor2.dumps(response), r.request.handover, r.trust, NOW)
        self.assertEqual(failed(pid), {DIGESTS})

    def test_not_an_mdoc(self):
        r = Round()
        pid = verify_pid(b"\xa0", r.request.handover, r.trust, NOW)
        self.assertEqual([c.name for c in pid.checks], [IS_PID])
        self.assertFalse(pid.ok)


if __name__ == "__main__":
    unittest.main()
