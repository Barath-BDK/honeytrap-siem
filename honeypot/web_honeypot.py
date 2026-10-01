"""
web_honeypot.py, HTTP honeypot (port 8080) for the HONEYTRAP SIEM project.

Serves believable decoy pages for a fictional corporate portal and logs every
request to logs/web.json. Enhancement over the original: a payload-inspection
layer scans each request (query string, form body, path, headers) for common
web-attack signatures, SQLi, XSS, command injection, path traversal/LFI, and
scanner fingerprints. Detections are layered ON TOP of the route-based event
type (Option A): the base `type` is preserved and `attack_indicators`,
`category`, `trap_triggered`, and `mitre_technique` are enriched when a payload
is seen. This keeps "a brute-force POST that ALSO carried SQLi" faithfully in
one event.

SAFETY: this is a honeypot. No request ever touches a real database, shell, or
filesystem path. All "vulnerable" responses are canned. Any attacker input that
is reflected back into a page is HTML-escaped, so the decoy never becomes a
genuinely exploitable app.
"""

from flask import Flask, request, Response
from markupsafe import escape
import json
import os
import re
import urllib.parse
from datetime import datetime

app = Flask(__name__)

LOG_PATH = "logs/web.json"
os.makedirs("logs", exist_ok=True)

# Credential-like fields we always capture from POST bodies (feeds the SIEM's
# credential IOC extraction).
CAPTURE_FIELDS = {"username", "user", "log", "pwd", "password", "pass", "email", "uname"}

# Route-based event type -> MITRE technique (the "what was hit" baseline).
MITRE_MAP = {
    "web_admin_probe":      "T1110.003",  # login panels
    "web_env_probe":        "T1552.001",  # unsecured creds in files
    "web_git_probe":        "T1552.001",  # exposed source / secrets
    "web_backup_probe":     "T1552.001",  # exposed backups
    "web_phpmyadmin_probe": "T1190",      # exploit public-facing app
    "web_api_probe":        "T1190",      # api / search endpoints
    "web_robots_probe":     "T1595.002",  # vulnerability scanning
    "web_404_probe":        "T1595.001",  # path enumeration
    "web_registry_probe":   "T1195",      # rogue/internal package registry enumeration
}

# Attack category (payload-based) -> MITRE technique. When a payload is
# detected, the most severe category's technique overrides the route baseline.
ATTACK_MITRE = {
    "sqli":      "T1190",   # exploit public-facing application
    "cmdi":      "T1059",   # command & scripting interpreter
    "xss":       "T1059",
    "traversal": "T1083",   # file & directory discovery
    "lfi":       "T1083",
}

# Ordered most-severe-first so the "primary" category is deterministic.
ATTACK_PRIORITY = ["cmdi", "sqli", "lfi", "traversal", "xss"]

# ---------------------------------------------------------------------------
# Attack signatures (compiled once). Kept readable and explainable, every
# pattern maps to a well-known probe class you can point to in your report.
# ---------------------------------------------------------------------------

SIGNATURES = {
    "sqli": [
        r"union\s+select", r"or\s+1\s*=\s*1", r"'\s*or\s*'", r"'\s*or\s+1",
        r"--\s", r"--$", r"/\*.*\*/", r"\bsleep\s*\(", r"\bbenchmark\s*\(",
        r"waitfor\s+delay", r"information_schema", r";\s*drop\s+table",
        r"xp_cmdshell", r"'\s*;\s*", r"\bunion\b.*\bselect\b",
    ],
    "xss": [
        r"<\s*script", r"<\s*/\s*script", r"onerror\s*=", r"onload\s*=",
        r"onmouseover\s*=", r"javascript:", r"<\s*img[^>]*src",
        r"<\s*svg", r"\balert\s*\(", r"document\.cookie", r"fromcharcode",
    ],
    "cmdi": [
        r";\s*(id|ls|cat|whoami|uname|pwd|nc|curl|wget)\b",
        r"\|\s*(nc|bash|sh|curl|wget)\b", r"\$\(", r"`[^`]+`",
        r"&&\s*\w", r"\bwget\s+https?://", r"\bcurl\s+https?://",
        r"/bin/(ba)?sh", r"\bnc\s+-e",
    ],
    "traversal": [
        r"\.\./", r"\.\.\\", r"%2e%2e", r"\.\.%2f", r"boot\.ini", r"win\.ini",
    ],
    "lfi": [
        r"/etc/passwd", r"/etc/shadow", r"php://", r"file://",
        r"expect://", r"data://", r"/proc/self/environ",
    ],
}
COMPILED = {cat: [re.compile(p, re.IGNORECASE) for p in pats]
            for cat, pats in SIGNATURES.items()}

# Scanner / tool fingerprints in the User-Agent.
SCANNER_UAS = [
    "sqlmap", "nikto", "nmap", "masscan", "hydra", "gobuster", "dirbuster",
    "dirb", "wpscan", "nuclei", "acunetix", "nessus", "openvas",
    "python-requests", "curl", "wget", "go-http-client", "zgrab", "httpx",
    "feroxbuster", "wfuzz",
]

URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)


def inspect(text):
    """Return the set of attack categories whose signatures match `text`."""
    if not text:
        return set()
    hits = set()
    for cat, patterns in COMPILED.items():
        for pat in patterns:
            if pat.search(text):
                hits.add(cat)
                break
    return hits


def scan_request():
    """Aggregate query string, path, and form values; return detected
    indicators, a truncated evidence sample, and any embedded URL."""
    parts = []

    # URL-decode query string and path so encoded payloads are caught.
    raw_qs = request.query_string.decode("utf-8", "replace")
    if raw_qs:
        parts.append(urllib.parse.unquote_plus(raw_qs))
    parts.append(urllib.parse.unquote_plus(request.path))
    for k, v in request.form.items():
        parts.append(f"{k}={v}")

    blob = " ".join(parts)

    indicators = set()
    for chunk in parts:
        indicators |= inspect(chunk)

    # Primary (most severe) category drives category/mitre/severity.
    primary = next((c for c in ATTACK_PRIORITY if c in indicators), None)

    url_match = URL_RE.search(blob)
    sample = None
    if indicators:
        # Truncated evidence for the raw log / SIEM (treated as hostile
        # downstream, escaped before any DOM rendering by the dashboard).
        sample = blob.strip()[:300]

    return {
        "indicators": sorted(indicators),
        "primary": primary,
        "sample": sample,
        "url": url_match.group(0) if url_match else None,
    }


def detect_scanner():
    ua = request.headers.get("User-Agent", "").lower()
    for sig in SCANNER_UAS:
        if sig in ua:
            return sig
    return None


def log_web(event_type):
    """Build and append one enriched event. Route type is preserved; payload
    findings are layered on top."""
    scan = scan_request()
    scanner = detect_scanner()

    entry = {
        "type":            event_type,
        "ip":              request.remote_addr,
        "method":          request.method,
        "path":            request.path,
        "user_agent":      request.headers.get("User-Agent", ""),
        "mitre_technique": MITRE_MAP.get(event_type),
        "timestamp":       datetime.utcnow().isoformat() + "Z",
    }

    # Credential capture (unchanged behaviour).
    post_data = {}
    if request.method == "POST":
        post_data = {
            k: v for k, v in request.form.items()
            if k.lower() in CAPTURE_FIELDS
        }

    # ---- Option A enrichment: layer attack findings on top of route type ----
    if scan["indicators"]:
        entry["attack_indicators"] = scan["indicators"]
        entry["category"] = scan["primary"]                 # reuses SSH field
        entry["trap_triggered"] = True                      # reuses SSH mechanism
        entry["mitre_technique"] = ATTACK_MITRE.get(scan["primary"]) or entry["mitre_technique"]
        entry["matched_payload"] = scan["sample"]
        # Surface evidence through post_data so it reaches siem.db and shows
        # as "submitted data captured" in the feed.
        post_data["_attack_sample"] = scan["sample"]
        if request.query_string:
            post_data["_query_string"] = request.query_string.decode("utf-8", "replace")[:300]

    if scan["url"]:
        entry["extracted_url"] = scan["url"]
    if scanner:
        entry["scanner"] = scanner

    if post_data:
        entry["post_data"] = post_data

    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")


# ===========================================================================
# Decoy site, believable generic corporate portal. Distinct from the SIEM.
# ===========================================================================

BASE_CSS = """
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
    background:#f4f6f9;color:#1f2a37;font-size:14px;line-height:1.5}
  .topbar{background:#1e3a5f;color:#fff;padding:0 24px;height:52px;display:flex;
    align-items:center;box-shadow:0 1px 3px rgba(0,0,0,.15)}
  .topbar .logo{font-weight:700;font-size:16px;letter-spacing:.3px}
  .topbar .logo span{color:#7cb3e8}
  .topbar nav{margin-left:auto;display:flex;gap:22px}
  .topbar nav a{color:#cfe0f2;text-decoration:none;font-size:13px}
  .topbar nav a:hover{color:#fff}
  .wrap{max-width:960px;margin:40px auto;padding:0 24px}
  .card{background:#fff;border:1px solid #e2e8f0;border-radius:8px;
    box-shadow:0 1px 2px rgba(0,0,0,.04)}
  .login-wrap{max-width:380px;margin:64px auto;padding:0 20px}
  .login-card{background:#fff;border:1px solid #e2e8f0;border-radius:8px;
    box-shadow:0 4px 14px rgba(0,0,0,.06);padding:32px 30px}
  .login-card h1{font-size:19px;margin-bottom:4px;color:#1e3a5f}
  .login-card p.sub{color:#6b7684;font-size:13px;margin-bottom:22px}
  label{display:block;font-size:12px;font-weight:600;color:#3d4a5c;
    margin:14px 0 5px;text-transform:uppercase;letter-spacing:.4px}
  input[type=text],input[type=password],input[type=email],input[type=search]{
    width:100%;padding:10px 12px;border:1px solid #cbd5e1;border-radius:5px;
    font-size:14px;color:#1f2a37}
  input:focus{outline:none;border-color:#2563eb;box-shadow:0 0 0 3px rgba(37,99,235,.12)}
  button,.btn{width:100%;margin-top:20px;padding:11px;background:#2563eb;color:#fff;
    border:none;border-radius:5px;font-size:14px;font-weight:600;cursor:pointer}
  button:hover,.btn:hover{background:#1d4ed8}
  .err{background:#fef2f2;border:1px solid #fecaca;color:#b91c1c;padding:9px 12px;
    border-radius:5px;font-size:13px;margin-top:14px}
  .hint{margin-top:18px;text-align:center;font-size:12px;color:#94a3b8}
  h2.section{font-size:16px;color:#1e3a5f;margin-bottom:14px}
  .grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-top:8px}
  .tile{background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:18px}
  .tile h3{font-size:14px;color:#1e3a5f;margin-bottom:6px}
  .tile p{font-size:13px;color:#6b7684}
  .foot{margin-top:40px;text-align:center;color:#94a3b8;font-size:12px}
  pre{background:#0f172a;color:#cbd5e1;padding:16px;border-radius:6px;
    font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;
    overflow:auto;line-height:1.6}
"""

def page(title, body, show_nav=True):
    nav = ("<nav><a href='/'>Home</a><a href='/portal'>Portal</a>"
           "<a href='/support'>Support</a><a href='/admin'>Admin</a></nav>"
           if show_nav else "")
    return (f"<!doctype html><html><head><meta charset=utf-8>"
            f"<title>{title}</title><meta name=viewport "
            f"content='width=device-width,initial-scale=1'>"
            f"<style>{BASE_CSS}</style></head><body>"
            f"<div class=topbar><div class=logo>HARLOW<span>SYS</span></div>{nav}</div>"
            f"{body}<div class=foot>Harlow Systems Ltd · Internal Web Services · "
            f"powered by Apache/2.4.41 (Ubuntu)</div></body></html>")


def login_card(action, title, sub, error=False):
    err = "<div class=err>Invalid username or password.</div>" if error else ""
    return page(title, (
        f"<div class=login-wrap><div class=login-card>"
        f"<h1>{title}</h1><p class=sub>{sub}</p>"
        f"<form method=POST action='{action}'>"
        f"<label>Username</label><input type=text name=username autocomplete=off>"
        f"<label>Password</label><input type=password name=password>"
        f"<button type=submit>Sign in</button></form>{err}"
        f"<div class=hint>Authorised personnel only. Access is logged.</div>"
        f"</div></div>"), show_nav=False)


# ---- landing / marketing pages -------------------------------------------

@app.route("/")
def home():
    log_web("web_404_probe") if request.path != "/" else None
    body = ("<div class=wrap><div class=card style='padding:28px'>"
            "<h2 class=section>Harlow Systems Internal Portal</h2>"
            "<p style='color:#6b7684'>Employee resources, service tickets, and "
            "administrative tools for Harlow Systems staff.</p>"
            "<div class=grid>"
            "<div class=tile><h3>Service Portal</h3><p>Raise and track IT "
            "tickets.</p></div>"
            "<div class=tile><h3>HR Self-Service</h3><p>Payslips, leave, and "
            "benefits.</p></div>"
            "<div class=tile><h3>Admin Console</h3><p>Restricted "
            "administrative access.</p></div>"
            "</div></div></div>")
    # home itself isn't an attack probe; only log if query carries a payload
    scan = scan_request()
    if scan["indicators"]:
        log_web("web_api_probe")
    return page("Harlow Systems | Portal", body)


@app.route("/portal")
@app.route("/support")
def portal():
    log_web("web_404_probe")
    return page("Harlow Systems", "<div class=wrap><div class=card "
                "style='padding:28px'><h2 class=section>Sign in required</h2>"
                "<p style='color:#6b7684'>Please <a href='/login'>sign in</a> "
                "to continue.</p></div></div>")


# ---- login panels (web_admin_probe) --------------------------------------

@app.route("/admin",        methods=["GET", "POST"])
@app.route("/wp-admin",     methods=["GET", "POST"])
@app.route("/wp-login.php", methods=["GET", "POST"])
@app.route("/login",        methods=["GET", "POST"])
@app.route("/administrator",methods=["GET", "POST"])
def fake_admin():
    log_web("web_admin_probe")
    if request.method == "POST":
        return Response(login_card(request.path, "Administrator Sign-in",
                        "Harlow Systems admin console.", error=True), status=401)
    return login_card(request.path, "Administrator Sign-in",
                      "Harlow Systems admin console.")


# ---- phpMyAdmin (web_phpmyadmin_probe) -----------------------------------

@app.route("/phpmyadmin",   methods=["GET", "POST"])
@app.route("/pma",          methods=["GET", "POST"])
@app.route("/dbadmin",      methods=["GET", "POST"])
def fake_phpmyadmin():
    log_web("web_phpmyadmin_probe")
    if request.method == "POST":
        return Response(login_card(request.path, "phpMyAdmin",
                        "Database administration.", error=True), status=401)
    body = ("<div class=login-wrap><div class=login-card>"
            "<h1 style='color:#d35400'>phpMyAdmin</h1>"
            "<p class=sub>Welcome to phpMyAdmin 5.1.1</p>"
            "<form method=POST><label>Username</label>"
            "<input type=text name=username value=root autocomplete=off>"
            "<label>Password</label><input type=password name=password>"
            "<button type=submit>Go</button></form>"
            "<div class=hint>Server: localhost via TCP/IP · MySQL 8.0.27</div>"
            "</div></div>")
    return page("phpMyAdmin", body, show_nav=False)


# ---- "vulnerable" search / API endpoints (web_api_probe) -----------------
# These look injectable and return a CANNED fake SQL error when SQLi is seen,
# so an attacker believes they've found a live injection point and keeps going.
# Reflected input is ESCAPED, the decoy is never actually exploitable.

@app.route("/search")
@app.route("/api/products")
@app.route("/api/users")
def fake_search():
    log_web("web_api_probe")
    q = request.args.get("q") or request.args.get("id") or request.args.get("search") or ""
    scan = scan_request()
    if "sqli" in scan["indicators"]:
        # Canned MySQL-style error, no real query, input not reflected raw.
        return Response(
            "<pre>SQL syntax error near '" + str(escape(q))[:60] +
            "' at line 1\n[HY000] You have an error in your SQL syntax; check "
            "the manual that corresponds to your MySQL server version.</pre>",
            status=500, mimetype="text/html")
    safe_q = escape(q)
    return page("Search, Harlow Systems",
                f"<div class=wrap><div class=card style='padding:24px'>"
                f"<h2 class=section>Search results</h2>"
                f"<p style='color:#6b7684'>No results found for "
                f"\"{safe_q}\".</p></div></div>")


# ---- leaky files (honeytokens) -------------------------------------------

@app.route("/.env")
def fake_env():
    log_web("web_env_probe")
    return Response(
        "APP_ENV=production\nAPP_DEBUG=false\n"
        "DB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_PORT=3306\n"
        "DB_DATABASE=harlow_prod\nDB_USERNAME=harlow_app\n"
        "DB_PASSWORD=J9#kLmP2$xQ8vTr\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "MAIL_HOST=smtp.harlowsys.local\n",
        mimetype="text/plain")


@app.route("/.git/config")
@app.route("/.git/HEAD")
def fake_git():
    log_web("web_git_probe")
    if request.path.endswith("HEAD"):
        return Response("ref: refs/heads/main\n", mimetype="text/plain")
    return Response(
        "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n"
        "[remote \"origin\"]\n"
        "\turl = https://git.harlowsys.local/ops/portal.git\n"
        "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
        "[user]\n\temail = deploy@harlowsys.local\n",
        mimetype="text/plain")


@app.route("/backup.zip")
@app.route("/backup.sql")
@app.route("/db.sql")
@app.route("/dump.sql")
def fake_backup():
    log_web("web_backup_probe")
    # Serve a small believable teaser rather than a real archive.
    return Response(
        "-- Harlow Systems DB dump\n-- MySQL dump 10.13  Distrib 8.0.27\n"
        "-- Host: localhost    Database: harlow_prod\n"
        "-- ------------------------------------------------------\n",
        mimetype="text/plain")


@app.route("/robots.txt")
def robots():
    log_web("web_robots_probe")
    return Response(
        "User-agent: *\nDisallow: /admin\nDisallow: /wp-admin\n"
        "Disallow: /phpmyadmin\nDisallow: /.env\nDisallow: /.git\n"
        "Disallow: /backup\nDisallow: /api\n", mimetype="text/plain")


# ---- fake package-registry endpoints (web_registry_probe) ----------------
# Mimic a private PyPI / npm / container registry. Clients or scanners probing
# for internal package names (dependency-confusion reconnaissance) are logged.
# Reflected package names are ESCAPED so the decoy is never itself exploitable.

@app.route("/simple/")
@app.route("/simple/<pkg>/")
def fake_pypi(pkg=None):
    log_web("web_registry_probe")
    if pkg:
        p = escape(pkg)
        return Response(
            f"<!DOCTYPE html><html><head><title>Links for {p}</title></head>"
            f"<body><h1>Links for {p}</h1>"
            f"<a href='{p}-1.0.2.tar.gz'>{p}-1.0.2.tar.gz</a><br>"
            f"<a href='{p}-1.0.2-py3-none-any.whl'>{p}-1.0.2-py3-none-any.whl</a><br>"
            f"</body></html>", mimetype="text/html")
    return Response(
        "<!DOCTYPE html><html><head><title>Simple Index</title></head>"
        "<body><h1>Simple Index</h1>"
        "<a href='harlow-internal-utils/'>harlow-internal-utils</a><br>"
        "<a href='harlow-auth/'>harlow-auth</a><br>"
        "<a href='harlow-billing/'>harlow-billing</a><br>"
        "</body></html>", mimetype="text/html")


@app.route("/npm/<path:pkg>")
@app.route("/-/v1/search")
def fake_npm(pkg=None):
    log_web("web_registry_probe")
    name = escape(pkg) if pkg else "harlow-ui"
    return Response(
        '{"name":"' + str(name) + '","dist-tags":{"latest":"2.1.0"},'
        '"versions":{"2.1.0":{"name":"' + str(name) + '","version":"2.1.0",'
        '"dist":{"tarball":"https://npm.harlowsys.local/' + str(name) + '/-/'
        + str(name) + '-2.1.0.tgz"}}}}',
        mimetype="application/json")


@app.route("/v2/")
@app.route("/v2/<path:image>/manifests/<tag>")
def fake_registry_v2(image=None, tag=None):
    # Docker Registry v2 API surface.
    log_web("web_registry_probe")
    if image is None:
        return Response("{}", mimetype="application/json",
                        headers={"Docker-Distribution-Api-Version": "registry/2.0"})
    return Response(
        '{"schemaVersion":2,"mediaType":'
        '"application/vnd.docker.distribution.manifest.v2+json",'
        '"config":{"digest":"sha256:5e2f3a...harlow"}}',
        mimetype="application/json")


@app.errorhandler(404)
def catch_all(e):
    log_web("web_404_probe")
    return page("404 Not Found",
                "<div class=wrap><div class=card style='padding:28px'>"
                "<h2 class=section>404 Not Found</h2>"
                "<p style='color:#6b7684'>The requested URL was not found on "
                "this server.</p></div></div>"), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("HONEYPOT_WEB_PORT", "8080")))