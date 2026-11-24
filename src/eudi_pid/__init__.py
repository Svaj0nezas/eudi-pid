"""eudi-pid: request and verify a German EUDI PID (mdoc) over OpenID4VP 1.0.

    from eudi_pid import RelyingParty, Trust, trust_list, verify_pid

    rp = RelyingParty.from_files("access-private.key", "access-chain.pem", "registration-certificate.jwt")
    request = rp.request(response_uri, ["given_name", "family_name"])
    # serve request.signed() at request_uri; show request.wallet_url(request_uri) as a QR code
    trust = Trust.from_trust_list(trust_list.load("pid-provider-trust-list.jwt"))
    pid = request.verify(post_body, trust)       # the wallet's POST to response_uri
    pid.ok, pid.claims, pid.checks

See README.md for the parts and what each check means.
"""

from eudi_pid import trust as trust_list
from eudi_pid.jose import jwk_thumbprint
from eudi_pid.mdoc import PID_DOCTYPE
from eudi_pid.party import RelyingParty
from eudi_pid.request import PresentationRequest, pid_dcql, request_object, wallet_url
from eudi_pid.response import Answer, Handover, jwe_from_post, open_response
from eudi_pid.status import StatusLists
from eudi_pid.trust import PidTrustList, Trust, german_registrar_ca, german_sandbox_signer
from eudi_pid.verify import (CHECKS, DIGESTS, HOLDER_SIGNED, IS_PID, ISSUER_SIGNED, NOT_REVOKED, TRUSTED_ISSUER,
                             VALID_NOW, Check, VerifiedPid, verify_pid)

__version__ = "0.1.0"

__all__ = [
    "Answer", "CHECKS", "Check", "DIGESTS", "HOLDER_SIGNED", "Handover", "IS_PID", "ISSUER_SIGNED",
    "NOT_REVOKED", "PID_DOCTYPE", "PidTrustList", "PresentationRequest", "RelyingParty", "StatusLists",
    "TRUSTED_ISSUER", "Trust", "VALID_NOW", "VerifiedPid", "german_registrar_ca", "german_sandbox_signer",
    "jwe_from_post", "jwk_thumbprint", "open_response", "pid_dcql", "request_object", "trust_list",
    "verify_pid", "wallet_url",
]
