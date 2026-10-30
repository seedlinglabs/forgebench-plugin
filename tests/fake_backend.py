"""A stdlib fake Forgebench control plane covering exactly the routes the plugin helper calls.

Every request is recorded as (method, path, who) where ``who`` labels the bearer without exposing it.
Behaviour switches live on the instance so each test states the backend it assumes."""

from __future__ import annotations

import base64
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

REPORT_KEY = "sk_fake_REPORTING_0123456789abcdef"
INFER_KEY = "sk_fake_INFERENCE_0123456789abcdef"
SECRETS = (REPORT_KEY, INFER_KEY, "RCODE-secret-code", "ICODE-secret-code")


def s256(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


class Fake:
    def __init__(self):
        self.requests: list[tuple[str, str, str]] = []
        self.meta_bodies: list[dict] = []
        self.logins: list[dict] = []
        self.exchanges: list[dict] = []
        self.declarations: list[dict] = []
        self.revoked: list[str] = []
        self.challenges: dict[str, tuple[str, str | None]] = {}
        # behaviour
        self.plugin_contract = True       # the single-journey continuation (backend A)
        self.inference_error: str | None = None
        self.deny_login = False
        self.capture_policy: dict | None = {"effective": {"mode": "otel", "revision": 3}}  # None -> 404
        self.meta_status = 200
        self.meta_contract = True         # answers capture_contract:1 (backend B)
        self.delivery: dict | None = None  # None -> 404 (backend D)
        self.tasks_status = 200            # 403 = builder key refused (backend B)
        self.revoke_status = 200
        self.whoami_inference_tenant = "t-1"
        self.acks: list[dict] = []
        self.server: ThreadingHTTPServer | None = None

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def count(self, method: str, prefix: str) -> int:
        return sum(1 for m, p, _ in self.requests if m == method and p.startswith(prefix))

    def start(self) -> "Fake":
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                return

            def who(self) -> str:
                auth = self.headers.get("Authorization", "")
                return {f"Bearer {REPORT_KEY}": "reporting", f"Bearer {INFER_KEY}": "inference"}.get(
                    auth, "anonymous" if not auth else "other")

            def reply(self, status, body=None, headers=None):
                raw = json.dumps(body).encode() if body is not None else b""
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(raw)

            def body(self):
                length = int(self.headers.get("Content-Length") or 0)
                return json.loads(self.rfile.read(length) or b"{}")

            def do_GET(self):  # noqa: N802
                url = urlsplit(self.path)
                fake.requests.append(("GET", url.path, self.who()))
                q = {k: v[-1] for k, v in parse_qs(url.query).items()}
                if url.path == "/v1/auth/oidc/login":
                    fake.logins.append(q)
                    if fake.deny_login:
                        return self.redirect(q["redirect"], {"error": "access_denied"})
                    fake.challenges["RCODE-secret-code"] = (q["cli_challenge"], q.get("inference_challenge"))
                    out = {"code": "RCODE-secret-code"}
                    if fake.plugin_contract and q.get("plugin_client") == "claude_code":
                        out["plugin_contract"] = "1"
                        if fake.inference_error:
                            out["inference_error"] = fake.inference_error
                        else:
                            out["inference_code"] = "ICODE-secret-code"
                    return self.redirect(q["redirect"], out)
                if url.path == "/v1/auth/whoami":
                    who = self.who()
                    if who == "reporting":
                        return self.reply(200, {"tenant_id": "t-1", "identity_id": "i-1", "email": "dev@example.test",
                                                "role": "builder"})
                    if who == "inference":
                        return self.reply(200, {"tenant_id": fake.whoami_inference_tenant, "identity_id": "i-1"})
                    return self.reply(401, {"detail": {"error": "invalid_api_key"}})
                if url.path == "/v1/sessions/capture-policy":
                    if fake.capture_policy is None:
                        return self.reply(404, {"detail": "not found"})
                    return self.reply(200, fake.capture_policy)
                if url.path == "/v1/sessions/usage/telemetry/delivery":
                    if fake.delivery is None:
                        return self.reply(404, {"detail": "not found"})
                    return self.reply(200, fake.delivery)
                if url.path == "/v1/sessions/value/task-options":
                    if fake.tasks_status != 200:
                        return self.reply(fake.tasks_status, {"detail": {"error": "forbidden"}})
                    return self.reply(200, {"connections": [{"id": "c-1", "name": "Jira", "provider": "jira"}],
                                            "tasks": [{"id": "o-1", "connection_id": "c-1", "key": "ENG-1",
                                                       "title": "Fix it", "status": "open"}]})
                self.reply(404, {"detail": "not found"})

            def redirect(self, base, params):
                self.send_response(302)
                self.send_header("Location", base + ("&" if "?" in base else "?") + urlencode(params))
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_POST(self):  # noqa: N802
                path = urlsplit(self.path).path
                fake.requests.append(("POST", path, self.who()))
                body = self.body()
                if path == "/v1/auth/cli/exchange":
                    fake.exchanges.append(body)
                    want = fake.challenges.get(body.get("code"))
                    if not want or s256(body.get("verifier", "")) != want[0]:
                        return self.reply(400, {"detail": {"error": "invalid_grant"}})
                    return self.reply(200, {"id": "k-r", "prefix": "sk_fake_R", "scopes": ["sessions:write"],
                                            "api_key": REPORT_KEY, "owner_identity_id": "i-1"})
                if path == "/v1/auth/cli/inference/redeem":
                    want = fake.challenges.get("RCODE-secret-code")
                    if body.get("code") != "ICODE-secret-code" or not want or s256(body.get("verifier", "")) != want[1]:
                        return self.reply(400, {"detail": {"error": "invalid_grant"}})
                    return self.reply(200, {"id": "k-i", "prefix": "sk_fake_I", "scopes": ["chat:write"],
                                            "api_key": INFER_KEY})
                if path == "/v1/auth/cli/revoke":
                    fake.revoked.append(self.who())
                    return self.reply(fake.revoke_status, {"revoked": True})
                if path == "/v1/sessions/meta":
                    if self.who() != "reporting":
                        return self.reply(401, {"detail": {"error": "invalid_api_key"}})
                    fake.meta_bodies.append(body)
                    if fake.meta_status != 200:
                        return self.reply(fake.meta_status, {"detail": {"error": "x"}}, {"Retry-After": "7"})
                    out = {"accepted": len(body.get("sessions", [])), "with_branch": 0}
                    if fake.meta_contract:
                        out["capture_contract"] = 1
                    return self.reply(200, out)
                if path == "/v1/sessions/capture-policy/ack":
                    fake.acks.append(body)
                    return self.reply(200, {"ok": True})
                if path == "/v1/sessions/value/task-validation":
                    if fake.tasks_status != 200:
                        return self.reply(fake.tasks_status, {"detail": {"error": "forbidden"}})
                    ok = body.get("task_id") == "ENG-1"
                    return self.reply(200, {"valid": ok, "task_id": body.get("task_id"), "provider": "jira"})
                if path == "/v1/sessions/value/task-declarations":
                    fake.declarations.append(body)
                    return self.reply(200, {"review_status": "pending", "link_id": "l-1"})
                self.reply(404, {"detail": "not found"})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return self

    def stop(self) -> None:
        if self.server:
            self.server.shutdown()
            self.server.server_close()
