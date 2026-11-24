"""The smallest real PID verifier: a page with a QR code, and the verdict.

    python examples/verifier_server.py --key access-private.key --ac access-chain.pem \
        --rc registration-certificate.jwt --public-url https://<your tunnel> [--port 8490]

The wallet must reach --public-url (a tunnel: cloudflared tunnel --url http://localhost:8490).
Each page load makes a new request; the page polls until the wallet answers.
"""

from __future__ import annotations

import argparse
import html
import json
import secrets
import threading
import urllib.parse

from eudi_pid import RelyingParty, Trust, trust_list
from eudi_pid.http import Handler, Server, qr_svg

CLAIMS = ["given_name", "family_name", "birth_date"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", required=True)
    ap.add_argument("--ac", required=True)
    ap.add_argument("--rc", required=True)
    ap.add_argument("--public-url", required=True)
    ap.add_argument("--trust-list", help="a cached trust list (default: fetch the sandbox's)")
    ap.add_argument("--port", type=int, default=8490)
    args = ap.parse_args()

    rp = RelyingParty.from_files(args.key, args.ac, args.rc)
    print(f"{rp.name}: registration certificate {rp.registration_status()}")
    found = trust_list.load(args.trust_list) if args.trust_list else trust_list.fetch()[0]
    trust = Trust.from_trust_list(found)
    base = args.public_url.rstrip("/")
    requests, results, lock = {}, {}, threading.Lock()

    class Verifier(Handler):
        def do_GET(self):
            path = urllib.parse.urlparse(self.path).path
            if path == "/":
                rid = secrets.token_urlsafe(9)
                request = rp.request(f"{base}/response/{rid}", CLAIMS)
                with lock:
                    requests[rid] = request
                url = request.wallet_url(f"{base}/request/{rid}")
                page = (f"<!doctype html><meta name=viewport content='width=device-width'>"
                        f"<h1>{html.escape(rp.name)}</h1><div style='max-width:18rem'>{qr_svg(url)}</div>"
                        f"<p><a href='{html.escape(url)}'>Open your wallet</a></p><pre id=out>waiting…</pre>"
                        f"<script>setInterval(async()=>{{const r=await fetch('/result/{rid}');"
                        f"if(r.ok)document.getElementById('out').textContent=JSON.stringify(await r.json(),null,2)}},1500)"
                        f"</script>")
                return self.reply(page.encode(), "text/html; charset=utf-8")
            if path.startswith("/request/") and path[9:] in requests:
                return self.reply(requests[path[9:]].signed().encode(), "application/oauth-authz-req+jwt")
            if path.startswith("/result/") and path[8:] in results:
                return self.reply_json(results[path[8:]])
            self.reply(b"not found", "text/plain", 404)

        def do_POST(self):
            path = urllib.parse.urlparse(self.path).path
            rid = path.removeprefix("/response/")
            request = requests.get(rid)
            if request is None:
                return self.reply(b"unknown request", "text/plain", 404)
            try:
                pid = request.verify(self.read_body(), trust)
                results[rid] = {"ok": pid.ok, "claims": pid.claims,
                                "checks": [{"ok": c.ok, "check": c.name, "detail": c.detail} for c in pid.checks]}
            except ValueError as error:
                results[rid] = {"ok": False, "error": str(error)}
            print(json.dumps(results[rid], indent=1, ensure_ascii=False), flush=True)
            self.reply_json({})

    print(f"open {base} (serving on :{args.port})")
    Server(("::", args.port), Verifier).serve_forever()


if __name__ == "__main__":
    main()
