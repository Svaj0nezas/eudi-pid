# eudi-pid

Request and verify a German EUDI **PID** (mdoc, `eu.europa.ec.eudi.pid.1`) over **OpenID4VP 1.0**, as a registered relying party in the German EUDI wallet sandbox.

It covers both sides:
- **request:** a signed request object, a DCQL query, `direct_post.jwt`;
- **verify:** issuer signature, trust list, validity, revocation, digests and device signature.

It was tested against the German sandbox's iPhone wallet. It includes a simulated PID provider and wallet, so you can test without a phone.

Its dependencies are `cryptography`, `jwcrypto` and `cbor2`, plus `qrcode` with the `[qr]` extra. It doesn't use a web framework or touch the chain.

## Install

```bash
pip install -e ../eudi-pid                       # while developing alongside
pip install "eudi-pid[qr] @ git+https://github.com/<you>/eudi-pid@v0.1.0"   # pinned, once pushed
```

## Quick start

```python
from eudi_pid import RelyingParty, Trust, trust_list

rp = RelyingParty.from_files("access-private.key", "access-certificate-chain.pem",
                             "registration-certificate.jwt")
print(rp.registration_status())                  # "valid"; "REVOKED" breaks every request

request = rp.request("https://you.example/response/42", ["given_name", "family_name", "birth_date"])
request.wallet_url("https://you.example/request/42")   # → QR code / link for the wallet
request.signed()                                  # serve this at the request URI

trust = Trust.from_trust_list(trust_list.load("pid-provider-trust-list.jwt"))   # or trust_list.fetch()[0]
pid = request.verify(post_body, trust)            # the wallet's POST to the response URI
if pid.ok:
    pid.claims                                    # {"given_name": "ERIKA", ...}: issuer-signed only
for check in pid.checks:
    print(check.ok, check.name, check.detail)
```

[examples/verifier_server.py](examples/verifier_server.py) is the same flow as a working server of about 90 lines.

## The parts

| Module | What it does |
|---|---|
| `party` | `RelyingParty`: your key, access certificate chain and registration certificate; `client_id` (`x509_hash:`); the claims you may ask for; the registration certificate's revocation status |
| `request` | `PresentationRequest`: nonce, state, response key, DCQL, the signed request object, the wallet URL |
| `response` | `Handover` (what the device signature covers); open the wallet's JWE |
| `verify` | `verify_pid(device_response, handover, trust, now)` → `VerifiedPid` |
| `trust` | the German sandbox PID trust list (ETSI LoTE JWT), checked against the bundled LoTE Signer; `Trust` |
| `status` | IETF Token Status List: fetch, check, cache, look up an entry |
| `mdoc`, `certs`, `jose` | COSE_Sign1, MSO, tdate; certificate paths; base64url, ES256, the RFC 7638 thumbprint |
| `testing` | `SimulatedPidProvider`, `SimulatedWallet`, `fake_party()`: for tests and demos with no phone |
| `diagnose` | `python -m eudi_pid.diagnose …`: a verifier that prints everything, for "why does the wallet disagree?" |
| `http` | a dual-stack stdlib server and `qr_svg` |

`data/` bundles two public certificates: the sandbox's **LoTE Signer**, pinned for the trust list, and the **German Registrar CA**, which issues access certificates.

## The checks

| Check | Meaning |
|---|---|
| `it holds a PID` | one document of the expected doctype, with an MSO for it (if this fails, it's the only check) |
| `every attribute is what the issuer signed` | each disclosed element's tag-24 bytes hash to its digest in the MSO |
| `the issuer's signature is valid` | the COSE_Sign1 over the MSO, by the `x5chain` leaf |
| `the issuer is a trusted PID provider` | that leaf chains to an issuance CA on the trust list; a stale list is noted, not failed |
| `the PID is within its validity dates` | `validFrom ≤ now < validUntil` |
| `the PID is not revoked` | its status-list entry is 0. If the status can't be checked, this fails |
| `the PID's holder signed this presentation` | the device key bound in the MSO signed this request's handover: `client_id`, `nonce`, the response key's thumbprint and `response_uri` |

Your own checks go on top as `pid.checks.append(Check(name, ok, detail))`. For example, a name matching a payee, or a nonce that commits to something.

## Choosing the nonce and the response key

- **`nonce=`:** pass your own value to bind the presentation to something. The device signature covers it. *Verify the Receiver* uses it to commit to a passkey. Otherwise it's 32 random bytes.
- **`response_jwk=`:** a public P-256 JWK. The wallet then encrypts its answer to *that* key, not one made here. *Verify the Receiver* uses this so that only the user's browser can read the PID, while the server only relays it. After that, `request.open()` refuses to decrypt, because it doesn't have the key. Whoever holds the key calls `open_response(jwe, key)`, and `verify_pid(…, request.handover, …)` still works. The wallet shows the user who is asking, not where the answer goes. So use this to deliver to the user themselves, not to a third party.

Keep `request.handover` with the presentation if anyone will check it again later. The device signature can't be verified without it.

## What the German sandbox taught us

All of these were found the hard way:

1. **"You need a valid credential"** has at least three causes:
   - the PID copies on the phone have expired (sandbox mdoc PIDs last **14 days**: request a new PID);
   - the registration certificate is revoked (`rp.registration_status()`);
   - the registration certificate is for the wrong format (**mdoc** and **SD-JWT VC** have separate ones).
2. **The request URI must be reachable from the phone.** A `localhost` URL inside it times out in the wallet ("this took too long"). Use a tunnel and pass its URL.
3. **The thumbprint in the handover is the raw SHA-256,** not its base64url form.
4. **The German wallet uses a new device key for each presentation.** It holds a batch of copies, so 13 presentations gave 13 different keys. Don't use the device key as a stable user identifier.
5. **A status-list `ttl` of 0 means "don't cache".** It doesn't mean "missing".

## Not covered

- SD-JWT VC PIDs: mdoc only, for now.
- Other Member States' trust lists. `Trust` accepts any roots, but only the German sandbox list's format and signer are built in.
- The ISO 18013-7 handover. `diagnose` recognises it; `verify_pid` checks OpenID4VP 1.0 only.

## Tests

```bash
python -m unittest discover -s tests -v
```

`tests/data/pid-provider-trust-list.jwt` is a public snapshot of the sandbox's trust list.
