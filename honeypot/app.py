"""
Web honeypot: a fake corporate operations portal designed to maximize OSINT yield.

Captures every request as a structured JSON line (source IP + full forwarded chain,
user-agent, headers, attempted credentials, locale, cookies) and plants self-hosted
beacon tokens inside fake "leaked" files. When an attacker's tooling fetches a leaked
config and later hits the baked-in beacon URL, we capture their real egress IP.

Defensive use only: deploy on infrastructure you own. It observes and logs; it never
calls back out to, scans, or attacks any client.
"""
import json
import os
import re
import uuid
from datetime import datetime, timezone

from flask import Flask, request, redirect, make_response, Response

app = Flask(__name__)

LOG_PATH = os.environ.get("HONEYPOT_LOG", "/data/events.jsonl")
BRAND = os.environ.get("HONEYPOT_BRAND", "Northgate Logistics")

# Planted beacon tokens: token -> {planted_in, planted_at, planted_src}
PLANTED = {}

# Paths scanners probe for unprotected secrets/admin surfaces.
SENSITIVE_PATHS = {
    "/.env", "/.env.local", "/.env.backup",
    "/.aws/credentials", "/.git/config",
    "/config.php", "/config.json", "/api/v1/config",
    "/backup.sql", "/backup.zip", "/db.sql", "/dump.sql",
    "/wp-config.php", "/.ssh/id_rsa", "/credentials.json",
    "/actuator/env", "/server-status", "/phpinfo.php",
}


def client_chain():
    """Resolve the apparent source IP and the full forwarded chain."""
    xff = request.headers.get("X-Forwarded-For", "")
    chain = [p.strip() for p in xff.split(",") if p.strip()]
    return {
        "remote_addr": request.remote_addr,
        "x_forwarded_for": chain,
        "x_real_ip": request.headers.get("X-Real-IP"),
        "cf_connecting_ip": request.headers.get("CF-Connecting-IP"),
        # Best guess at the true origin: first XFF hop, else the socket peer.
        "source_ip": chain[0] if chain else request.remote_addr,
    }


def log_event(tag, extra=None):
    body = request.get_data(as_text=True) or ""
    event = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "req_id": str(uuid.uuid4()),
        "tag": tag,
        **client_chain(),
        "method": request.method,
        "path": request.full_path.rstrip("?"),
        "host": request.headers.get("Host"),
        "user_agent": request.headers.get("User-Agent"),
        "referer": request.headers.get("Referer"),
        "accept_language": request.headers.get("Accept-Language"),
        "headers": {k: v for k, v in request.headers.items()},
        "cookies": {k: v for k, v in request.cookies.items()},
        "body": body[:4096],
        "form": {k: v[:512] for k, v in request.form.items()},
    }
    if extra:
        event.update(extra)
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(event) + "\n")
    return event


def beacon_url():
    token = uuid.uuid4().hex
    PLANTED[token] = {
        "planted_at": datetime.now(timezone.utc).isoformat(),
        "planted_src": client_chain()["source_ip"],
    }
    host = request.headers.get("Host", "portal.internal")
    return f"http://{host}/t/{token}", token


LOGIN_HTML = """<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>{brand} — Operations Portal</title>
<style>
body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0f1724;color:#e6edf3;
display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:2.5rem;width:340px;
box-shadow:0 8px 30px rgba(0,0,0,.4)}}
h1{{font-size:1.15rem;margin:0 0 .35rem}} .sub{{color:#8b949e;font-size:.8rem;margin:0 0 1.5rem}}
label{{display:block;font-size:.78rem;color:#8b949e;margin:.9rem 0 .3rem}}
input{{width:100%;box-sizing:border-box;padding:.6rem;background:#0d1117;border:1px solid #30363d;
border-radius:6px;color:#e6edf3}}
button{{width:100%;margin-top:1.4rem;padding:.6rem;background:#1f6feb;border:0;border-radius:6px;
color:#fff;font-weight:600;cursor:pointer}}
.err{{background:#3d1418;border:1px solid #8b2c34;color:#ffb3b8;padding:.5rem .7rem;border-radius:6px;
font-size:.8rem;margin-bottom:1rem}}
.foot{{color:#6e7681;font-size:.7rem;text-align:center;margin-top:1.4rem}}
</style></head><body>
<form class=card method=post action=/login>
<h1>{brand}</h1><p class=sub>Internal Operations Portal</p>
{error}
<label>Username</label><input name=username autocomplete=username autofocus>
<label>Password</label><input name=password type=password autocomplete=current-password>
<button type=submit>Sign in</button>
<p class=foot>Authorized personnel only · v3.2.1</p>
</form></body></html>"""


@app.route("/")
def index():
    log_event("root")
    return redirect("/login", code=302)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        log_event("login_attempt", {
            "cred_username": request.form.get("username"),
            "cred_password": request.form.get("password"),
        })
        err = '<div class=err>Invalid credentials. Access attempt logged.</div>'
        return make_response(LOGIN_HTML.format(brand=BRAND, error=err), 401)
    log_event("login_view")
    return LOGIN_HTML.format(brand=BRAND, error="")


@app.route("/t/<token>")
def beacon(token):
    log_event("beacon_hit", {
        "beacon_token": token,
        "beacon_known": token in PLANTED,
        "beacon_plant": PLANTED.get(token),
    })
    # 1x1 gif so embedding it anywhere renders cleanly.
    gif = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!"
           b"\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")
    return Response(gif, mimetype="image/gif")


def _planted_env():
    url, _ = beacon_url()
    return (
        "APP_ENV=production\n"
        "DB_HOST=10.20.4.11\nDB_USER=ng_app\nDB_PASSWORD=Pr0d-Ng8te!2024\n"
        "REDIS_URL=redis://10.20.4.12:6379/0\n"
        "AWS_ACCESS_KEY_ID=AKIA2OGN7EXAMPLE4QZ\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        f"INTERNAL_WEBHOOK_URL={url}\n"
        "SECRET_KEY=8f3c1a9e4b7d2056e1c9a0f4\n"
    )


@app.before_request
def catch_sensitive():
    path = request.path
    if path in SENSITIVE_PATHS or path == "/login" or path == "/" or path.startswith("/t/"):
        return None  # handled by explicit routes / let through
    return None


@app.route("/<path:anypath>")
def catch_all(anypath):
    path = "/" + anypath
    if path in SENSITIVE_PATHS:
        if path.endswith((".env", ".env.local", ".env.backup")):
            ev = _planted_env()
            log_event("sensitive_probe", {"probed": path, "served": "env_canary"})
            return Response(ev, mimetype="text/plain")
        if path == "/.aws/credentials":
            url, _ = beacon_url()
            body = ("[default]\naws_access_key_id = AKIA2OGN7EXAMPLE4QZ\n"
                    "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
                    f"# metadata sync: {url}\n")
            log_event("sensitive_probe", {"probed": path, "served": "aws_canary"})
            return Response(body, mimetype="text/plain")
        if path in ("/config.json", "/api/v1/config", "/credentials.json"):
            url, _ = beacon_url()
            body = json.dumps({
                "db": {"host": "10.20.4.11", "user": "ng_app", "pass": "Pr0d-Ng8te!2024"},
                "callback_url": url,
                "api_key": "ng_live_8f3c1a9e4b7d2056e1c9a0f4",
            }, indent=2)
            log_event("sensitive_probe", {"probed": path, "served": "json_canary"})
            return Response(body, mimetype="application/json")
        log_event("sensitive_probe", {"probed": path, "served": "none"})
        return Response("Not Found", 404)
    log_event("scanner_path", {"probed": path})
    return Response("Not Found", 404)


@app.errorhandler(404)
def nf(e):
    log_event("notfound_404")
    return Response("Not Found", 404)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
