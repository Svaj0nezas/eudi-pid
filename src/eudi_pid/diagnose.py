"""A diagnostic PID verifier for the German sandbox: every step printed.

Every step prints what it saw: the request object decoded, the JWE header, the
decrypted response, the whole DeviceResponse, the Mobile Security Object, each
certificate, each signature and each digest. An interop failure then shows
where it failed, not just that it did. For the decision itself use
eudi_pid.verify_pid; this is for finding out why a wallet disagrees.

    python -m eudi_pid.diagnose --key access-private.key --ac access-chain.pem \
        --rc registration-certificate.jwt --public-url https://<tunnel> [--log presentations.jsonl]

`verify_mdoc` tries several SessionTranscript shapes and reports the one the
device signature covers: OpenID4VP 1.0 (what the German wallet signs, checked
2026-10-25) and the older ISO 18013-7 one.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import secrets
import threading
import time
import urllib.parse
from urllib.parse import parse_qs

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from jwcrypto import jwe, jwk

from eudi_pid.http import Handler, Server, qr_svg
from eudi_pid.jose import jwk_thumbprint, jwt_parts, unb64u
from eudi_pid.mdoc import COSE_ALG, COSE_ALGS, COSE_X5CHAIN, cose_key, cose_parts, cose_verify
from eudi_pid.party import RelyingParty
from eudi_pid.request import registered_dcql, request_object, wallet_url
from eudi_pid.response import Handover


def show(title: str, value=None, indent: int = 0) -> None:
    pad = "  " * indent
    if value is None:
        print(f"\n{pad}\033[1m{title}\033[0m", flush=True)
    else:
        print(f"{pad}{title:<34} {value}", flush=True)


def dump(label: str, value, indent: int = 1) -> None:
    """Whatever it is, printed so a person can read it."""
    text = json.dumps(value, indent=2, default=_plain, ensure_ascii=False)
    pad = "  " * indent
    print(f"{pad}{label}:", flush=True)
    for line in text.splitlines():
        print(f"{pad}  {line}", flush=True)


def _plain(o):
    """CBOR carries bytes, tags and dates that JSON will not take."""
    if isinstance(o, bytes):
        return f"<{len(o)} bytes> {o[:24].hex()}…" if len(o) > 24 else f"<hex> {o.hex()}"
    if isinstance(o, cbor2.CBORTag):
        return {f"tag({o.tag})": o.value}
    if hasattr(o, "isoformat"):
        return o.isoformat()
    if isinstance(o, set):
        return sorted(o, key=str)
    return str(o)


# -- the mdoc ---------------------------------------------------------------- #

def describe_certificate(der: bytes, indent: int = 2) -> x509.Certificate:
    cert = x509.load_der_x509_certificate(der)
    pad = "  " * indent
    print(f"{pad}subject   {cert.subject.rfc4514_string()}", flush=True)
    print(f"{pad}issuer    {cert.issuer.rfc4514_string()}", flush=True)
    print(f"{pad}serial    {cert.serial_number:x}", flush=True)
    print(f"{pad}validity  {cert.not_valid_before_utc:%Y-%m-%d} .. "
          f"{cert.not_valid_after_utc:%Y-%m-%d}", flush=True)
    for name, getter in (("key usage", x509.KeyUsage),
                         ("ext key usage", x509.ExtendedKeyUsage)):
        try:
            value = cert.extensions.get_extension_for_class(getter).value
            if name == "ext key usage":
                value = [o.dotted_string for o in value]
            else:
                value = [f for f in ("digital_signature", "key_agreement",
                                     "key_cert_sign", "crl_sign")
                         if getattr(value, f, False)]
            print(f"{pad}{name:9s} {value}", flush=True)
        except x509.ExtensionNotFound:
            print(f"{pad}{name:9s} (absent)", flush=True)
    return cert


def verify_mdoc(device_response: bytes, transcripts: dict) -> dict:
    """Walk a DeviceResponse, checking and printing everything in it.

    `transcripts` maps a name to a candidate SessionTranscript. The device
    signature covers one of them, and which one depends on the OpenID4VP draft
    the wallet implements -- so every candidate is tried and the one that
    verifies is reported. That is the single most version-sensitive thing in
    mdoc-over-OpenID4VP, and guessing silently is how interop testing wastes a
    day.
    """
    findings: dict = {"documents": []}
    response = cbor2.loads(device_response)

    show("DeviceResponse")
    show("version", response.get("version"), 1)
    show("status", response.get("status"), 1)
    show("documents", len(response.get("documents") or []), 1)

    for document in response.get("documents") or []:
        doc: dict = {}
        doctype = document.get("docType")
        show(f"document: {doctype}")

        issuer_signed = document["issuerSigned"]
        protected, unprotected, protected_raw, payload, signature = cose_parts(
            issuer_signed["issuerAuth"])
        alg = protected.get(COSE_ALG)
        show("issuerAuth alg", f"{alg} ({COSE_ALGS.get(alg, '?')})", 1)

        # -- the document signer, and where it chains ----------------------- #
        chain = unprotected.get(COSE_X5CHAIN) or []
        chain = [chain] if isinstance(chain, bytes) else list(chain)
        show("x5chain", f"{len(chain)} certificate(s)", 1)
        signer = None
        for i, der in enumerate(chain):
            print(f"    [{i}]", flush=True)
            cert = describe_certificate(der, 3)
            signer = signer or cert
        doc["signer"] = signer.subject.rfc4514_string() if signer else None

        # -- the Mobile Security Object ------------------------------------- #
        mso_bytes = payload.value if isinstance(payload, cbor2.CBORTag) else payload
        mso = cbor2.loads(mso_bytes)
        if isinstance(mso, cbor2.CBORTag):
            mso = cbor2.loads(mso.value)
        show("Mobile Security Object")
        show("version", mso.get("version"), 1)
        show("digest algorithm", mso.get("digestAlgorithm"), 1)
        show("docType", mso.get("docType"), 1)
        dump("validityInfo", mso.get("validityInfo"))

        try:
            cose_verify(signer.public_key(), alg, protected_raw, payload, signature)
            doc["issuer signature"] = "VALID"
        except Exception as exc:                               # noqa: BLE001
            doc["issuer signature"] = f"INVALID ({exc})"
        show("issuer signature over the MSO", doc["issuer signature"], 1)

        # -- the disclosed values, each checked against its digest ---------- #
        digest_alg = {"SHA-256": hashlib.sha256, "SHA-384": hashlib.sha384,
                      "SHA-512": hashlib.sha512}.get(
                          mso.get("digestAlgorithm", "SHA-256"), hashlib.sha256)
        value_digests = mso.get("valueDigests") or {}
        claims: dict = {}
        show("disclosed elements")
        for namespace, items in (issuer_signed.get("nameSpaces") or {}).items():
            for item in items:
                raw = cbor2.dumps(item)        # the tagged bytes ARE the input
                entry = cbor2.loads(item.value) if isinstance(item, cbor2.CBORTag) else item
                digest_id = entry.get("digestID")
                committed = (value_digests.get(namespace) or {}).get(digest_id)
                ours = digest_alg(raw).digest()
                ok = committed == ours
                name = entry.get("elementIdentifier")
                value = entry.get("elementValue")
                claims[f"{namespace}/{name}"] = {
                    "value": _plain(value) if isinstance(value, (bytes, cbor2.CBORTag))
                             else value,
                    "issuer-signed": ok,
                }
                mark = "ok " if ok else "BAD"
                shown = str(claims[f"{namespace}/{name}"]["value"])[:48]
                print(f"    [{mark}] {namespace}/{name:24s} {shown}", flush=True)
        doc["claims"] = claims
        doc["elements not matching their digest"] = [
            k for k, v in claims.items() if not v["issuer-signed"]]

        # -- holder binding -------------------------------------------------- #
        device_key = ((mso.get("deviceKeyInfo") or {}).get("deviceKey"))
        device_signed = document.get("deviceSigned") or {}
        device_auth = device_signed.get("deviceAuth") or {}
        show("device authentication")
        show("method", "signature" if "deviceSignature" in device_auth
             else "MAC" if "deviceMac" in device_auth else "none", 1)

        if device_key and "deviceSignature" in device_auth:
            d_prot, _d_unprot, d_prot_raw, _d_payload, d_sig = cose_parts(
                device_auth["deviceSignature"])
            d_alg = d_prot.get(COSE_ALG)
            ns_bytes = device_signed.get("nameSpaces")
            matched = None
            for label, transcript in transcripts.items():
                # DeviceAuthentication is the detached payload: the signature
                # covers it, it is never carried in the response.
                authentication = cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(
                    ["DeviceAuthentication", transcript, doctype, ns_bytes])))
                try:
                    cose_verify(cose_key(device_key), d_alg, d_prot_raw,
                                authentication, d_sig)
                    matched = label
                    break
                except Exception:                              # noqa: BLE001
                    continue
            doc["device signature"] = (f"VALID (session transcript: {matched})"
                                       if matched else
                                       "could not be verified with any known "
                                       "session transcript shape")
        else:
            doc["device signature"] = "not a signature (MAC, or absent)"
        show("result", doc["device signature"], 1)

        findings["documents"].append(doc)
    return findings


# -- is the wallet reusing one credential, or a batch? ----------------------- #

LOG: str | None = None      # where remember() appends; None: nowhere


def fingerprint(document: dict) -> dict:
    """What identifies this particular copy of the credential.

    The device key is bound INTO the MSO at issuance and covered by the
    issuer's signature, so it cannot change within one copy. If it changes
    between presentations, the wallet is holding a batch of separately issued
    copies and spending a fresh one each time -- which is what stops two
    verifiers recognising the same holder. If it never changes, every verifier
    the holder visits sees the same key, and they can collude.
    """
    _, _, _, payload, signature = cose_parts(document["issuerSigned"]["issuerAuth"])
    mso = cbor2.loads(payload.value if isinstance(payload, cbor2.CBORTag) else payload)
    if isinstance(mso, cbor2.CBORTag):
        mso = cbor2.loads(mso.value)
    key = mso["deviceKeyInfo"]["deviceKey"]
    status = (mso.get("status") or {}).get("status_list") or {}
    first_salt = None
    for items in (document["issuerSigned"].get("nameSpaces") or {}).values():
        entry = cbor2.loads(items[0].value) if isinstance(items[0], cbor2.CBORTag) else items[0]
        first_salt = entry.get("random", b"").hex()
        break
    return {
        "at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "device_key": hashlib.sha256(key[-2] + key[-3]).hexdigest(),
        "status_index": status.get("idx"),
        "mso_signed": str(mso["validityInfo"]["signed"]),
        "issuer_signature": signature.hex()[:32],
        "first_salt": first_salt,
    }


def remember(mark: dict, log: str | None = None) -> None:
    log = log or LOG
    if not log:
        return
    with open(log, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(mark) + "\n")


def history(log: str | None = None) -> None:
    """What every presentation so far says about key reuse."""
    log = log or LOG
    if not log:
        return
    try:
        marks = [json.loads(line) for line in open(log, encoding="utf-8") if line.strip()]
    except FileNotFoundError:
        return
    if not marks:
        return
    keys = {m["device_key"] for m in marks}
    indices = {m["status_index"] for m in marks}
    show("presentations seen so far")
    for m in marks:
        show(m["at"], f'key {m["device_key"][:16]}…  status idx {m["status_index"]}', 1)
    show("distinct device keys", f"{len(keys)} of {len(marks)}", 1)
    show("distinct status indices", f"{len(indices)} of {len(marks)}", 1)
    if len(marks) < 2:
        show("verdict", "scan again to compare", 1)
    elif len(keys) == 1:
        show("verdict", "STATIC -- one key across presentations, so any two "
                        "verifiers can link this holder", 1)
    elif len(keys) == len(marks):
        show("verdict", "ROTATING -- a fresh key each time, from a batch of "
                        "issued copies", 1)
    else:
        show("verdict", f"{len(keys)} keys over {len(marks)} presentations -- "
                        "a batch, being reused once exhausted", 1)


# -- the request ------------------------------------------------------------- #

class Session:
    """One presentation, and everything needed to check the answer."""

    def __init__(self, party: RelyingParty, public_url: str):
        self.party = party
        self.public_url = public_url.rstrip("/")
        self.id = secrets.token_urlsafe(8)
        self.nonce = secrets.token_urlsafe(24)
        self.state = secrets.token_urlsafe(12)
        # mdoc over OpenID4VP binds the device signature to this as well as to
        # the nonce, so it has to be remembered to check the answer.
        self.mdoc_nonce = secrets.token_urlsafe(16)
        self.enc_key = jwk.JWK.generate(kty="EC", crv="P-256", use="enc",
                                        alg="ECDH-ES", kid=secrets.token_urlsafe(8))
        self.result: dict | None = None

    @property
    def credential(self) -> dict:
        return self.party.registered_credential

    def dcql(self) -> dict:
        """Exactly what the registration certificate allows, in its own shape."""
        return registered_dcql(self.party)

    def request_object(self) -> str:
        return request_object(self.party, nonce=self.nonce, state=self.state,
                              response_uri=f"{self.public_url}/response",
                              response_jwk=json.loads(self.enc_key.export_public()), dcql=self.dcql())

    def wallet_url(self) -> str:
        return wallet_url(self.party, f"{self.public_url}/request/{self.id}")

    def handover_info(self, response_uri: str) -> bytes:
        """`OpenID4VPHandoverInfo`, as OpenID4VP 1.0 defines it.

        [client_id, nonce, jwk_thumbprint, response_uri] -- and the thumbprint
        is the RAW SHA-256 of the verifier's encryption key (RFC 7638), not
        its base64url form. That detail is the whole difference between a
        device signature that verifies and one that does not.
        """
        return Handover(self.party.client_id, self.nonce,
                        jwk_thumbprint(json.loads(self.enc_key.export_public())), response_uri).info()

    def transcripts(self, mdoc_nonce: str | None = None) -> dict:
        """Candidate SessionTranscripts, newest first.

        Confirmed against the German wallet on 2026-10-25: it signs over the
        OpenID4VP 1.0 handover, a hash of `OpenID4VPHandoverInfo`. The older
        ISO 18013-7 shape -- two hashes salted with a wallet-chosen nonce
        carried in the JWE's `apu` -- is kept because a wallet on an earlier
        draft produces that instead, and knowing WHICH one a wallet used is
        the useful finding.
        """
        response_uri = f"{self.public_url}/response"
        out = {
            "OpenID4VP 1.0 OpenID4VPHandover":
                [None, None, ["OpenID4VPHandover",
                              hashlib.sha256(self.handover_info(response_uri)).digest()]],
        }
        if mdoc_nonce:
            ch = hashlib.sha256(cbor2.dumps([self.party.client_id, mdoc_nonce])).digest()
            rh = hashlib.sha256(cbor2.dumps([response_uri, mdoc_nonce])).digest()
            out["ISO 18013-7 OID4VPHandover (apu as mdoc nonce)"] = [
                None, None, [ch, rh, self.nonce]]
        return out


# -- the page and the server ------------------------------------------------- #

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PID check — German sandbox</title><style>
 :root {{ color-scheme: light dark; }}
 body {{ margin:0; font:16px/1.55 ui-sans-serif,-apple-system,Segoe UI,sans-serif; }}
 main {{ max-width:40rem; margin:0 auto; padding:2.5rem 1.25rem 4rem; }}
 h1 {{ font-size:1.4rem; margin:0 0 .25rem; }}
 p.sub {{ opacity:.7; margin:0 0 1.5rem; }}
 .card {{ border:1px solid rgba(127,127,127,.35); border-radius:14px;
          padding:1.25rem; margin-bottom:1.25rem; }}
 dl {{ display:grid; grid-template-columns:10rem 1fr; gap:.35rem 1rem; margin:0; }}
 dt {{ opacity:.65; }} dd {{ margin:0; word-break:break-word; }}
 .qr {{ display:flex; justify-content:center; padding:1rem 0; }}
 .qr svg {{ width:min(16rem,75vw); height:auto; background:#fff;
            padding:12px; border-radius:12px; }}
 code {{ font-size:.85em; }} pre {{ overflow-x:auto; font-size:.8rem;
         background:rgba(127,127,127,.12); padding:1rem; border-radius:10px; }}
</style></head><body><main>
<h1>{name}</h1><p class="sub">{registry} · German sandbox</p>
<div class="card">
 <dl><dt>Purpose</dt><dd>{purpose}</dd>
     <dt>Document</dt><dd><code>{doctype}</code></dd>
     <dt>Asking for</dt><dd>{claims}</dd>
     <dt>client_id</dt><dd><code>{client_id}</code></dd></dl>
</div>
<div class="card"><div class="qr">{qr}</div>
 <p style="text-align:center"><a href="{wallet}">Open your wallet</a></p></div>
<div class="card"><h2 style="font-size:1rem;margin:0 0 .5rem">Result</h2>
 <pre id="out">waiting for the wallet…</pre></div>
<script>
setInterval(async () => {{
  const r = await (await fetch('/result')).json();
  document.getElementById('out').textContent = JSON.stringify(r, null, 2);
}}, 1500);
</script></main></body></html>"""


def page(session: Session) -> bytes:
    wanted = session.credential
    return PAGE.format(
        name=html.escape(session.party.rc_claims.get("name", "Relying party")),
        registry=html.escape(session.party.registry_id or "?"),
        purpose=html.escape(session.party.rc_claims.get("purpose", [{}])[0]
                            .get("value", "—")),
        doctype=html.escape(str(wanted["meta"])),
        claims=html.escape(", ".join("/".join(c["path"]) for c in wanted["claim"])),
        client_id=html.escape(session.party.client_id),
        qr=qr_svg(session.wallet_url()),
        wallet=html.escape(session.wallet_url()),
    ).encode()


def serve(session: Session, port: int, bind: str = "::") -> Server:
    class DeHandler(Handler):
        def do_GET(self):
            path = urllib.parse.urlparse(self.path).path
            if path in ("/", "/index.html"):
                return self.reply(page(session), "text/html; charset=utf-8")
            if path == "/result":
                return self.reply_json(session.result or {"state": "waiting"})
            if path == f"/request/{session.id}":
                request = session.request_object()
                head, body = jwt_parts(request)
                show("the wallet fetched the request object")
                dump("header", {k: (f"[{len(v)} certs]" if k == "x5c" else v)
                                for k, v in head.items()})
                dump("payload", body)
                return self.reply(request.encode(),
                                  "application/oauth-authz-req+jwt")
            self.reply(b"not found", "text/plain", 404)

        def do_POST(self):
            raw = self.read_body().decode()
            show("the wallet posted its answer")
            show("bytes", len(raw), 1)

            encrypted = (json.loads(raw)["response"] if raw.lstrip().startswith("{")
                         else parse_qs(raw)["response"][0])
            head = json.loads(unb64u(encrypted.split(".")[0]))
            dump("JWE header", head)
            # ISO 18013-7 carries the wallet's own mdoc nonce in `apu` and
            # echoes our nonce in `apv`; both matter for the transcript.
            mdoc_nonce = (unb64u(head["apu"]).decode() if head.get("apu") else None)
            if mdoc_nonce:
                show("apu (the wallet's mdoc nonce)", mdoc_nonce, 1)
            if head.get("apv"):
                echoed = unb64u(head["apv"]).decode()
                show("apv echoes our nonce", echoed == session.nonce, 1)

            token = jwe.JWE()
            token.deserialize(encrypted, key=session.enc_key)
            answer = json.loads(token.payload)
            dump("decrypted response", {k: (f"<{len(v)} chars>"
                                            if k == "vp_token" and isinstance(v, str)
                                            else v)
                                        for k, v in answer.items()})
            show("state matches ours", answer.get("state") == session.state, 1)

            presented = answer["vp_token"]
            if isinstance(presented, dict):
                presented = presented.get("pid") or next(iter(presented.values()))
            if isinstance(presented, list):
                presented = presented[0]

            device_response = (presented if isinstance(presented, bytes)
                               else base64.urlsafe_b64decode(
                                   presented + "=" * (-len(presented) % 4)))
            show("DeviceResponse", f"{len(device_response)} bytes CBOR", 1)

            try:
                findings = verify_mdoc(device_response, session.transcripts(mdoc_nonce))
            except Exception as exc:                            # noqa: BLE001
                import traceback
                traceback.print_exc()
                findings = {"error": f"{type(exc).__name__}: {exc}"}

            for document in (cbor2.loads(device_response).get("documents") or []):
                mark = fingerprint(document)
                remember(mark)
                findings.setdefault("fingerprint", mark)
            history()
            findings["state matches"] = answer.get("state") == session.state
            # CBOR hands back dates, bytes and tags; the page polls this over
            # JSON, and `json.dumps` takes none of them.
            session.result = json.loads(json.dumps(findings, default=_plain))
            show("summary")
            print(json.dumps(findings, indent=2, default=_plain), flush=True)
            self.reply(b"{}", "application/json")

    server = Server((bind, port), DeHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--key", required=True, help="the access certificate's private key (PEM)")
    ap.add_argument("--ac", required=True, help="the access certificate chain (PEM)")
    ap.add_argument("--rc", required=True, help="the registration certificate (JWT)")
    ap.add_argument("--log", help="append each presentation's fingerprint here (JSON lines)")
    ap.add_argument("--public-url", required=True)
    ap.add_argument("--port", type=int, default=8482)
    ap.add_argument("--bind", default="::")
    args = ap.parse_args()
    global LOG
    LOG = args.log

    party = RelyingParty(args.key, args.ac, args.rc)
    session = Session(party, args.public_url)
    serve(session, args.port, args.bind)

    wanted = session.credential
    show("relying party")
    show("name", party.rc_claims.get("name"), 1)
    show("registered as", party.registry_id, 1)
    show("entitlements", [e.rsplit("/", 1)[-1]
                          for e in party.rc_claims.get("entitlements", [])], 1)
    show("asking for")
    show("format", wanted["format"], 1)
    show("doctype", wanted["meta"], 1)
    for claim in wanted["claim"]:
        show("", "/".join(claim["path"]), 1)
    show("our certificate")
    describe_certificate(party.chain[0].public_bytes(serialization.Encoding.DER), 1)
    show("client_id", party.client_id, 1)
    show("nonce", session.nonce, 1)
    show("mdoc nonce", session.mdoc_nonce, 1)
    history()
    print(f"\n  open {args.public_url} and scan\n", flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
