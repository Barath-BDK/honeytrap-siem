from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import hmac
import sqlite3
import json
from datetime import datetime, timezone, timedelta

import config

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

DB_PATH = config.DB_PATH
DASHBOARD_USERNAME = config.DASHBOARD_USERNAME
DASHBOARD_PASSWORD = config.DASHBOARD_PASSWORD
config.warn_placeholders(["DASHBOARD_USERNAME", "DASHBOARD_PASSWORD"])

CASE_STATUSES = ("new", "investigating", "resolved")

# Synthetic session id for web activity. Web events have no session_id, so we
# treat all web events from one IP as a "web session" addressed as web:<ip>.
WEB_SESSION_PREFIX = "web:"


# =========================================================================
# ATT&CK technique catalog
# =========================================================================
ATTACK_TACTICS = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Command & Control",
]

ATTACK_TECHNIQUES = [
    ("T1595.001", "Active Scanning: IP Blocks",            "Reconnaissance"),
    ("T1595.002", "Active Scanning: Vulnerability",        "Reconnaissance"),
    ("T1190",     "Exploit Public-Facing Application",     "Initial Access"),
    ("T1059",     "Command & Scripting Interpreter",       "Execution"),
    ("T1053",     "Scheduled Task/Job",                    "Persistence"),
    ("T1136",     "Create Account",                        "Persistence"),
    ("T1070",     "Indicator Removal",                     "Defense Evasion"),
    ("T1027",     "Obfuscated Files or Information",       "Defense Evasion"),
    ("T1222",     "File/Directory Permissions Mod.",       "Defense Evasion"),
    ("T1548",     "Abuse Elevation Control Mechanism",     "Defense Evasion"),
    ("T1110",     "Brute Force",                           "Credential Access"),
    ("T1110.003", "Brute Force: Password Spraying",        "Credential Access"),
    ("T1552.001", "Credentials In Files",                  "Credential Access"),
    ("T1082",     "System Information Discovery",          "Discovery"),
    ("T1105",     "Ingress Tool Transfer",                 "Command & Control"),
    ("T1083",     "File & Directory Discovery",            "Discovery"),
    ("T1203",     "Exploitation for Client Execution",     "Execution"),
    ("T1098.004", "SSH Authorized Keys",                   "Persistence"),
    ("T1195",     "Supply Chain Compromise",              "Initial Access"),
    ("T1195.001", "Compromise Software Dependencies",     "Initial Access"),
    ("T1195.002", "Compromise Software Supply Chain",     "Initial Access"),
]


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_reports_table():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            ip TEXT,
            generated_at TEXT,
            first_seen TEXT,
            last_seen TEXT,
            event_count INTEGER,
            max_severity_label TEXT,
            mitre_techniques TEXT,
            summary_text TEXT,
            recommended_action TEXT,
            status TEXT DEFAULT 'ready'
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_reports_session ON reports(session_id)")
    conn.commit()
    conn.close()


def init_core_tables():
    """Create events / detections / rules if pipeline.py has not run yet, so a
    fresh install opens to an empty console instead of server errors."""
    try:
        import pipeline
        pipeline.init_db()
    except Exception as exc:   # never block the dashboard on this
        print(f"[app] could not pre-create tables: {exc}")


init_core_tables()
init_reports_table()


def score_to_label(score):
    if score is None: return "info"
    if score >= 9: return "critical"
    if score >= 7: return "high"
    if score >= 4: return "medium"
    if score >= 2: return "low"
    return "info"


def format_details(row):
    t = row["type"]
    if t == "ssh_auth_attempt":
        return f"Login attempt: {row['username']}:{row['password']}"
    if t == "ssh_brute_force_confirmed":
        return f"Brute force confirmed, {row['total_attempts']} attempts"
    if t == "ssh_command":
        extra = f" [{row['category']}]" if row["category"] else ""
        return f"Command: {row['command']}{extra}"
    if t == "ssh_connect":
        return "New SSH connection"
    if t and t.startswith("web_"):
        path = row["path"] or ""
        if row["trap_triggered"] and row["category"]:
            return f"{row['category'].upper()} attempt on {path}"
        if row["post_data"]:
            return f"{path}, submitted data captured"
        return f"Probed: {path}"
    return t or "Unknown event"


def login_required(view):
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    wrapped.__name__ = view.__name__
    return wrapped


# =========================================================================
# Session helpers, unify SSH sessions (by session_id) and web sessions
# (by IP, addressed web:<ip>) behind one interface.
# =========================================================================

def _is_web_session(session_id):
    return bool(session_id) and session_id.startswith(WEB_SESSION_PREFIX)


def _web_ip(session_id):
    return session_id[len(WEB_SESSION_PREFIX):]


def _fetch_session_rows(conn, session_id):
    """All events for a session, oldest-first. Web sessions resolve to all
    sessionless web_* events from that IP; SSH sessions to the session_id."""
    if _is_web_session(session_id):
        return conn.execute(
            "SELECT * FROM events "
            "WHERE ip = ? AND type LIKE 'web_%' "
            "AND (session_id IS NULL OR session_id = '') "
            "ORDER BY id ASC",
            (_web_ip(session_id),)
        ).fetchall()
    return conn.execute(
        "SELECT * FROM events WHERE session_id = ? ORDER BY id ASC",
        (session_id,)
    ).fetchall()


def _summary_from_rows(session_id, rows):
    times = [r["timestamp"] for r in rows if r["timestamp"]]
    max_score = max((r["severity_score"] or 0) for r in rows)
    return {
        "session_id":         session_id,
        "ip":                 rows[0]["ip"],
        "first_seen":         min(times) if times else None,
        "last_seen":          max(times) if times else None,
        "event_count":        len(rows),
        "max_severity_label": score_to_label(max_score),
        "alert_status":       rows[0]["alert_status"] or "new",
        "trap_hit":           any(bool(r["trap_triggered"]) for r in rows),
    }


# =========================================================================
# Deterministic report generation (no AI/LLM)
# =========================================================================

RECOMMENDED_ACTIONS = {
    "critical": "Recommend immediate credential rotation, firewall rule review for this source IP, and inspection of any referenced payload URLs in a sandboxed environment.",
    "high":     "Recommend immediate credential rotation and firewall rule review for this source IP.",
    "medium":   "Recommend continued monitoring of this source IP and periodic review of related sessions.",
    "low":      "No immediate action required; retain for pattern analysis.",
    "info":     "No immediate action required; retain for pattern analysis.",
}

SEVERE_CATEGORY_SENTENCES = {
    "malware_download":      "The session included at least one attempted malware download via an ingress tool transfer.",
    "reverse_shell_attempt": "An attempted reverse shell connection back to attacker-controlled infrastructure was observed.",
    "persistence_attempt":   "The attacker attempted to establish persistence on the host.",
    "log_tampering":         "Log tampering activity consistent with indicator removal was observed.",
    "account_creation":      "The attacker attempted to create a new local account.",
    "obfuscated_payload":    "Obfuscated or encoded payload activity was observed.",
}

WEB_CATEGORY_SENTENCES = {
    "sqli":      "SQL injection payloads were detected, consistent with an attempt to exploit a public-facing application (T1190).",
    "cmdi":      "Command-injection payloads were detected, indicating an attempt at remote command execution.",
    "lfi":       "Local file inclusion payloads targeting sensitive system files were detected.",
    "traversal": "Directory-traversal sequences were detected, consistent with attempts to read files outside the web root.",
    "xss":       "Cross-site scripting payloads were detected in submitted parameters.",
}

WEB_SCANNERS = ["sqlmap", "nikto", "nmap", "masscan", "hydra", "gobuster",
                "dirbuster", "wpscan", "nuclei", "acunetix", "nessus",
                "python-requests", "curl", "wget"]


def _fmt_ts(ts):
    if not ts:
        return "unknown time"
    s = str(ts).replace("T", " ").rstrip("Z")
    if "." in s:
        s = s.split(".")[0]
    return s + " UTC"


def _report_iocs(rows):
    """SSH-oriented IOC extraction: credentials, commands, paths."""
    ip = None
    credentials, commands, paths = [], [], []
    seen_cred, seen_cmd, seen_path = set(), set(), set()
    for r in rows:
        if ip is None and r["ip"]:
            ip = r["ip"]
        if r["type"] == "ssh_auth_attempt" and (r["username"] or r["password"]):
            pair = f"{r['username'] or ''}:{r['password'] or ''}"
            if pair not in seen_cred:
                seen_cred.add(pair); credentials.append(pair)
        if r["type"] == "ssh_command" and r["command"]:
            if r["command"] not in seen_cmd:
                seen_cmd.add(r["command"]); commands.append(r["command"])
        if r["path"]:
            if r["path"] not in seen_path:
                seen_path.add(r["path"]); paths.append(r["path"])
    return {"ip": ip, "credentials": credentials, "commands": commands, "paths": paths}


def _web_iocs(rows):
    """Web-oriented IOC extraction. Reuses the report template's three IOC
    slots: credentials (login creds harvested), commands (attack payloads
    captured), paths (paths probed)."""
    ip = None
    creds, payloads, paths = [], [], []
    seen_c, seen_pl, seen_p = set(), set(), set()
    for r in rows:
        if ip is None and r["ip"]:
            ip = r["ip"]
        if r["path"] and r["path"] not in seen_p:
            seen_p.add(r["path"]); paths.append(r["path"])
        pd = r["post_data"]
        if pd:
            try:
                d = json.loads(pd)
            except (ValueError, TypeError):
                d = {}
            sample = d.get("_attack_sample")
            if sample and sample not in seen_pl:
                seen_pl.add(sample); payloads.append(sample)
            # Login credentials submitted to the fake admin forms.
            user = next((d[k] for k in ("username", "user", "log", "uname", "email") if k in d), None)
            pw   = next((d[k] for k in ("password", "pass", "pwd") if k in d), None)
            if user is not None or pw is not None:
                pair = f"{user or ''}:{pw or ''}"
                if pair not in seen_c:
                    seen_c.add(pair); creds.append(pair)
    return {"ip": ip, "credentials": creds, "commands": payloads, "paths": paths}


def _report_techniques(rows):
    counts = {}
    for r in rows:
        t = r["mitre_technique"]
        if t:
            counts[t] = counts.get(t, 0) + 1
    return [{"id": tid, "count": c}
            for tid, c in sorted(counts.items(), key=lambda x: -x[1])]


def _detect_scanners(rows):
    found = set()
    for r in rows:
        ua = (r["user_agent"] or "").lower()
        for s in WEB_SCANNERS:
            if s in ua:
                found.add(s)
    return sorted(found)


def _build_summary_text(rows, iocs):
    ip = iocs["ip"] or "an unknown source"
    first_seen = _fmt_ts(rows[0]["timestamp"])
    last_seen = _fmt_ts(rows[-1]["timestamp"])
    n = len(rows)

    connects = [r for r in rows if r["type"] == "ssh_connect"]
    auths = [r for r in rows if r["type"] == "ssh_auth_attempt"]
    bf = [r for r in rows if r["type"] == "ssh_brute_force_confirmed"]
    cmds = [r for r in rows if r["type"] == "ssh_command"]
    traps = [r for r in rows if r["trap_triggered"]]

    categories = {}
    for r in traps:
        if r["category"]:
            categories[r["category"]] = categories.get(r["category"], 0) + 1

    sentences = []
    conn_n = len(connects) or 1
    sentences.append(
        f"Attacker at {ip} initiated {conn_n} SSH connection(s) to the honeypot "
        f"between {first_seen} and {last_seen}, generating {n} logged event(s)."
    )
    if bf:
        attempts = max((r["total_attempts"] or 0) for r in bf)
        sentences.append(
            f"A brute-force attack was confirmed after {attempts} authentication "
            f"attempt(s); {len(iocs['credentials'])} unique credential pair(s) were captured."
        )
    elif auths:
        sentences.append(
            f"{len(auths)} authentication attempt(s) were recorded using "
            f"{len(iocs['credentials'])} unique credential pair(s), below the "
            f"brute-force confirmation threshold."
        )
    if traps:
        cat_list = ", ".join(sorted(categories.keys()))
        sentences.append(
            f"Following the simulated compromise, {len(cmds)} post-exploitation "
            f"command(s) were captured, triggering honeypot traps in the following "
            f"categorie(s): {cat_list}."
        )
        for cat in SEVERE_CATEGORY_SENTENCES:
            if cat in categories:
                sentences.append(SEVERE_CATEGORY_SENTENCES[cat])
    elif cmds:
        sentences.append(
            f"{len(cmds)} interactive shell command(s) were captured; none "
            f"triggered a high-severity trap."
        )
    if "recon" in categories or (cmds and not traps):
        sentences.append(
            "Reconnaissance activity, including system and environment discovery "
            "commands, was observed during the session."
        )
    return " ".join(sentences)


def _build_web_summary_text(rows, iocs):
    ip = iocs["ip"] or "an unknown source"
    times = [r["timestamp"] for r in rows if r["timestamp"]]
    first_seen = _fmt_ts(min(times)) if times else "unknown time"
    last_seen = _fmt_ts(max(times)) if times else "unknown time"
    n = len(rows)

    categories = {}
    login_probes = 0
    scanned_paths = set()
    for r in rows:
        if r["path"]:
            scanned_paths.add(r["path"])
        if r["type"] == "web_admin_probe":
            login_probes += 1
        if r["trap_triggered"] and r["category"]:
            categories[r["category"]] = categories.get(r["category"], 0) + 1

    scanners = _detect_scanners(rows)
    sentences = []
    sentences.append(
        f"Source {ip} generated {n} HTTP request(s) against the web honeypot "
        f"between {first_seen} and {last_seen}, touching {len(scanned_paths)} "
        f"distinct path(s)."
    )
    if scanners:
        sentences.append(
            f"Traffic carried the fingerprint of known tooling: {', '.join(scanners)}."
        )
    if categories:
        total_payload = sum(categories.values())
        cat_list = ", ".join(sorted(categories.keys()))
        sentences.append(
            f"Web-application attack payloads were detected in {total_payload} "
            f"request(s), spanning the following categorie(s): {cat_list}."
        )
        for cat in ["cmdi", "sqli", "lfi", "traversal", "xss"]:
            if cat in categories:
                sentences.append(WEB_CATEGORY_SENTENCES[cat])
    if login_probes:
        sentences.append(
            f"{login_probes} request(s) targeted administrative or authentication "
            f"endpoints, consistent with credential-based probing of the exposed "
            f"login interface."
        )
    if not categories and not login_probes:
        sentences.append(
            "Activity was limited to reconnaissance-style path enumeration; no "
            "attack payloads were captured."
        )
    return " ".join(sentences)


def generate_report(session_id):
    """Deterministic incident report for one session (SSH or web)."""
    conn = get_db()
    rows = _fetch_session_rows(conn, session_id)
    if not rows:
        conn.close()
        return None

    if _is_web_session(session_id):
        iocs = _web_iocs(rows)
        summary_text = _build_web_summary_text(rows, iocs)
    else:
        iocs = _report_iocs(rows)
        summary_text = _build_summary_text(rows, iocs)

    techniques = _report_techniques(rows)
    max_score = max((r["severity_score"] or 0) for r in rows)
    label = score_to_label(max_score)
    recommended = RECOMMENDED_ACTIONS[label]
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    cur = conn.execute("""
        INSERT INTO reports (
            session_id, ip, generated_at, first_seen, last_seen,
            event_count, max_severity_label, mitre_techniques,
            summary_text, recommended_action, status
        ) VALUES (?,?,?,?,?,?,?,?,?,?, 'ready')
    """, (
        session_id, iocs["ip"], generated_at,
        rows[0]["timestamp"], rows[-1]["timestamp"],
        len(rows), label, json.dumps(techniques),
        summary_text, recommended,
    ))
    conn.commit()
    report_id = cur.lastrowid
    conn.close()

    return {
        "id":                 report_id,
        "session_id":         session_id,
        "ip":                 iocs["ip"],
        "generated_at":       generated_at,
        "first_seen":         rows[0]["timestamp"],
        "last_seen":          rows[-1]["timestamp"],
        "event_count":        len(rows),
        "max_severity_label": label,
        "mitre_techniques":   techniques,
        "status":             "ready",
    }


# =========================================================================
# Auth + pages
# =========================================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        ok_user = hmac.compare_digest(username.encode(), DASHBOARD_USERNAME.encode())
        ok_pass = hmac.compare_digest(password.encode(), DASHBOARD_PASSWORD.encode())
        if ok_user and ok_pass and not config.is_placeholder(DASHBOARD_PASSWORD):
            session["logged_in"] = True
            return redirect(url_for("dashboard"))
        error = "Invalid username or password"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/attack-matrix")
@login_required
def attack_matrix():
    return render_template("attack_matrix.html")


@app.route("/sessions")
@login_required
def sessions_page():
    return render_template("sessions.html")


@app.route("/sessions/<path:session_id>")
@login_required
def session_detail_page(session_id):
    # <path:> so web:<ip> ids (which contain a colon) resolve cleanly.
    return render_template("session_detail.html")


@app.route("/reports")
@login_required
def reports_page():
    return render_template("reports.html")


@app.route("/reports/<int:report_id>")
@login_required
def report_detail_page(report_id):
    return render_template("report_detail.html")


@app.route("/alerts")
@login_required
def alerts_page():
    return render_template("alerts.html")


@app.route("/alerts/<int:alert_id>")
@login_required
def alert_detail_page(alert_id):
    return render_template("alert_detail.html")


@app.route("/rules")
@login_required
def rules_page():
    return render_template("rules.html")


@app.route("/settings")
@login_required
def settings_page():
    return render_template("settings.html")


@app.context_processor
def inject_sensor():
    """Sensor info for the rail footer and Settings page (no credentials)."""
    host = config.HONEYPOT_HOST
    return {"sensor": {
        "host": "honeypot" if config.is_placeholder(host) else host,
        "ssh_port": config.HONEYPOT_SSH_PORT,
        "web_port": config.HONEYPOT_WEB_PORT,
        "db": DB_PATH,
    }}


# =========================================================================
# Existing APIs, events / stats / attack-matrix
# =========================================================================

# Extra filterable fields exposed to the Fields panel. Each maps a query-string
# key to its events-table column; all are safe, fixed column names (never user
# input), so they can be interpolated into SQL without injection risk.
FIELD_COLUMNS = {
    "severity": "severity_label",
    "type":     "type",
    "source":   "source",
    "ip":       "ip",
    "category": "category",
    "mitre":    "mitre_technique",
}


def _build_event_filter(args):
    """Build the shared WHERE clause + params for the events feed and the field
    summary, so both always agree on what 'the current result set' means."""
    q         = args.get("q", "").strip()
    date_from = args.get("date_from", "").strip()
    date_to   = args.get("date_to", "").strip()

    conditions, params = [], []
    if q:
        like = f"%{q}%"
        conditions.append("(ip LIKE ? OR command LIKE ? OR username LIKE ? OR password LIKE ? OR path LIKE ?)")
        params.extend([like, like, like, like, like])
    if date_from:
        conditions.append("timestamp >= ?")
        params.append(date_from)
    if date_to:
        conditions.append("timestamp <= ?")
        params.append(date_to)

    # Field filters (severity, type, source, ip, category, mitre). Column names
    # come from the fixed FIELD_COLUMNS map, values are always parameterised.
    for key, col in FIELD_COLUMNS.items():
        val = args.get(key, "").strip()
        if val:
            conditions.append(f"{col} = ?")
            params.append(val)

    where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    return where_clause, params


@app.route("/api/events")
@login_required
def api_events():
    where_clause, params = _build_event_filter(request.args)
    direction = "ASC" if request.args.get("sort", "desc").lower() == "asc" else "DESC"
    sql = f"SELECT * FROM events {where_clause} ORDER BY id {direction} LIMIT 200"

    conn = get_db()
    rows = conn.execute(sql, params).fetchall()
    conn.close()

    events = []
    for row in rows:
        events.append({
            "id": row["id"], "type": row["type"], "ip": row["ip"],
            "source": row["source"],
            "session_id": row["session_id"],
            "severity_label": row["severity_label"],
            "category": row["category"],
            "mitre_technique": row["mitre_technique"],
            "timestamp": row["timestamp"],
            "details": format_details(row),
        })
    return jsonify(events)


@app.route("/api/field-summary")
@login_required
def api_field_summary():
    """Splunk-style field summary: for each field, the top values (by count)
    within the CURRENT filter set. Powers the dashboard Fields panel."""
    where_clause, params = _build_event_filter(request.args)
    conn = get_db()
    summary = {}
    for key, col in FIELD_COLUMNS.items():
        base = f"{where_clause} AND {col} IS NOT NULL AND {col} != ''" if where_clause \
               else f"WHERE {col} IS NOT NULL AND {col} != ''"
        rows = conn.execute(
            f"SELECT {col} AS v, COUNT(*) AS c FROM events {base} "
            f"GROUP BY {col} ORDER BY c DESC, v ASC",
            params
        ).fetchall()
        distinct = conn.execute(
            f"SELECT COUNT(DISTINCT {col}) AS d FROM events {base}", params
        ).fetchone()["d"]
        summary[key] = {
            "column":   col,
            "distinct": distinct,
            "top": [{"value": r["v"], "count": r["c"]} for r in rows],
            "has_more": False,
        }
    conn.close()
    return jsonify(summary)


@app.route("/api/stats")
@login_required
def api_stats():
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    critical_high = conn.execute(
        "SELECT COUNT(*) FROM events WHERE severity_label IN ('critical','high')"
    ).fetchone()[0]
    unique_ips = conn.execute(
        "SELECT COUNT(DISTINCT ip) FROM events WHERE ip IS NOT NULL"
    ).fetchone()[0]
    sessions = conn.execute(
        "SELECT COUNT(DISTINCT session_id) FROM events WHERE session_id IS NOT NULL"
    ).fetchone()[0]
    conn.close()
    return jsonify({
        "total": total, "critical_high": critical_high,
        "unique_ips": unique_ips, "sessions": sessions,
    })


def _parse_ts(ts):
    """Parse the ISO timestamps written by the sensors (trailing Z allowed)."""
    if not ts:
        return None
    try:
        d = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _iso(d):
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@app.route("/api/hud")
@login_required
def api_hud():
    """Small payload polled by every page for the top bar counters."""
    conn = get_db()
    events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    last = conn.execute("SELECT MAX(timestamp) FROM events").fetchone()[0]
    try:
        open_alerts = conn.execute(
            "SELECT COUNT(*) FROM detections WHERE COALESCE(alert_status,'new') != 'resolved'"
        ).fetchone()[0]
    except sqlite3.OperationalError:
        open_alerts = 0
    conn.close()
    return jsonify({"events": events, "open_alerts": open_alerts, "last_event": last})


@app.route("/api/overview")
@login_required
def api_overview():
    """Bucketed counts by severity for the overview chart, plus breakdowns."""
    try:
        hours = max(1, min(int(request.args.get("hours", 24)), 24 * 90))
    except ValueError:
        hours = 24
    end = _parse_ts(request.args.get("end")) or datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    bucket_minutes = 60 if hours <= 24 else 180 if hours <= 72 else 360 if hours <= 168 else 1440

    # align buckets to whole bucket boundaries
    step = timedelta(minutes=bucket_minutes)
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    first = epoch + ((start - epoch) // step) * step
    n = int((end - first) / step) + 1
    buckets = [{"t": _iso(first + i * step), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
               for i in range(n)]

    conn = get_db()
    rows = conn.execute(
        "SELECT timestamp, severity_label, source, ip FROM events WHERE timestamp >= ? AND timestamp <= ?",
        (_iso(first), _iso(end) + "~"),
    ).fetchall()
    earliest = conn.execute("SELECT MIN(timestamp) FROM events").fetchone()[0]
    conn.close()

    severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    surface = {"ssh": 0, "web": 0}
    ips = set()
    for r in rows:
        d = _parse_ts(r["timestamp"])
        if d is None or d < first or d > end:
            continue
        sev = r["severity_label"] if r["severity_label"] in severity else "info"
        idx = int((d - first) / step)
        if 0 <= idx < n:
            buckets[idx][sev] += 1
        severity[sev] += 1
        src = (r["source"] or "").lower()
        if src in surface:
            surface[src] += 1
        if r["ip"]:
            ips.add(r["ip"])

    return jsonify({
        "start": _iso(first), "end": _iso(end), "bucket_minutes": bucket_minutes,
        "buckets": buckets, "severity": severity, "surface": surface,
        "unique_ips": len(ips), "total": sum(severity.values()), "earliest": earliest,
    })


@app.route("/api/attack-matrix")
@login_required
def api_attack_matrix():
    conn = get_db()
    rows = conn.execute("""
        SELECT mitre_technique, COUNT(*) AS cnt, MAX(timestamp) AS last_seen
        FROM events
        WHERE mitre_technique IS NOT NULL AND mitre_technique != ''
        GROUP BY mitre_technique
    """).fetchall()
    conn.close()

    counts    = {r["mitre_technique"]: r["cnt"] for r in rows}
    last_seen = {r["mitre_technique"]: r["last_seen"] for r in rows}
    catalog_ids = {tid for tid, _, _ in ATTACK_TECHNIQUES}
    techniques = [
        {"id": tid, "name": name, "tactic": tactic,
         "count": counts.get(tid, 0), "last_seen": last_seen.get(tid)}
        for tid, name, tactic in ATTACK_TECHNIQUES
    ]
    unmapped = [
        {"id": tid, "count": c}
        for tid, c in sorted(counts.items(), key=lambda x: -x[1])
        if tid not in catalog_ids
    ]
    return jsonify({
        "tactics": ATTACK_TACTICS, "techniques": techniques,
        "unmapped": unmapped, "total_mapped": sum(counts.values()),
    })


# =========================================================================
# Sessions APIs, drill-down + case management (SSH + web)
# =========================================================================

def _session_summary_row(r):
    return {
        "session_id":         r["session_id"],
        "ip":                 r["ip"],
        "first_seen":         r["first_seen"],
        "last_seen":          r["last_seen"],
        "event_count":        r["event_count"],
        "max_severity_label": score_to_label(r["max_score"]),
        "alert_status":       r["alert_status"] or "new",
        "trap_hit":           bool(r["trap_hit"]),
    }


def _session_time_filter(args):
    """Optional from/to time-range applied to session aggregates (matches on
    each session's activity timestamps). Returns (extra_conditions, params)."""
    conds, params = [], []
    df = args.get("date_from", "").strip()
    dt = args.get("date_to", "").strip()
    if df:
        conds.append("timestamp >= ?"); params.append(df)
    if dt:
        conds.append("timestamp <= ?"); params.append(dt)
    return conds, params


@app.route("/api/sessions")
@login_required
def api_sessions():
    direction = "ASC" if request.args.get("sort", "desc").lower() == "asc" else "DESC"
    conds, params = _session_time_filter(request.args)
    extra = (" AND " + " AND ".join(conds)) if conds else ""
    conn = get_db()
    rows = conn.execute(f"""
        SELECT session_id,
               MIN(ip)             AS ip,
               MIN(timestamp)      AS first_seen,
               MAX(timestamp)      AS last_seen,
               COUNT(*)            AS event_count,
               MAX(severity_score) AS max_score,
               MAX(alert_status)   AS alert_status,
               MAX(trap_triggered) AS trap_hit
        FROM events
        WHERE session_id IS NOT NULL AND session_id != ''{extra}
        GROUP BY session_id
        ORDER BY last_seen {direction}
    """, params).fetchall()
    conn.close()
    return jsonify([_session_summary_row(r) for r in rows])


@app.route("/api/sessions/web-activity")
@login_required
def api_sessions_web_activity():
    direction = "ASC" if request.args.get("sort", "desc").lower() == "asc" else "DESC"
    conds, params = _session_time_filter(request.args)
    extra = (" AND " + " AND ".join(conds)) if conds else ""
    conn = get_db()
    rows = conn.execute(f"""
        SELECT ip,
               COUNT(*)            AS event_count,
               MIN(timestamp)      AS first_seen,
               MAX(timestamp)      AS last_seen,
               MAX(severity_score) AS max_score,
               MAX(alert_status)   AS alert_status,
               MAX(trap_triggered) AS trap_hit
        FROM events
        WHERE type LIKE 'web_%' AND (session_id IS NULL OR session_id = ''){extra}
        GROUP BY ip
        ORDER BY last_seen {direction}
    """, params).fetchall()
    conn.close()
    return jsonify([
        {
            "session_id":         WEB_SESSION_PREFIX + (r["ip"] or ""),
            "ip":                 r["ip"],
            "event_count":        r["event_count"],
            "first_seen":         r["first_seen"],
            "last_seen":          r["last_seen"],
            "max_severity_label": score_to_label(r["max_score"]),
            "alert_status":       r["alert_status"] or "new",
            "trap_hit":           bool(r["trap_hit"]),
        }
        for r in rows
    ])


def _event_dicts(rows):
    return [
        {
            "id": row["id"], "type": row["type"], "ip": row["ip"],
            "severity_label": row["severity_label"],
            "mitre_technique": row["mitre_technique"],
            "timestamp": row["timestamp"],
            "details": format_details(row),
        }
        for row in rows
    ]


@app.route("/api/sessions/<path:session_id>")
@login_required
def api_session_detail(session_id):
    conn = get_db()
    rows = _fetch_session_rows(conn, session_id)
    conn.close()

    if not rows:
        return jsonify({"error": "session not found"}), 404

    first = rows[0]
    return jsonify({
        "session_id":    session_id,
        "ip":            first["ip"],
        "alert_status":  first["alert_status"] or "new",
        "analyst_notes": first["analyst_notes"] or "",
        "events":        _event_dicts(rows),
    })


@app.route("/api/sessions/<path:session_id>/status", methods=["POST"])
@login_required
def api_session_update_status(session_id):
    body = request.get_json(silent=True) or {}
    status = str(body.get("status", "")).strip().lower()
    notes = str(body.get("notes", ""))

    if status not in CASE_STATUSES:
        return jsonify({"error": f"status must be one of {', '.join(CASE_STATUSES)}"}), 400

    conn = get_db()
    if _is_web_session(session_id):
        cur = conn.execute(
            "UPDATE events SET alert_status = ?, analyst_notes = ? "
            "WHERE ip = ? AND type LIKE 'web_%' "
            "AND (session_id IS NULL OR session_id = '')",
            (status, notes, _web_ip(session_id))
        )
    else:
        cur = conn.execute(
            "UPDATE events SET alert_status = ?, analyst_notes = ? WHERE session_id = ?",
            (status, notes, session_id)
        )
    conn.commit()

    if cur.rowcount == 0:
        conn.close()
        return jsonify({"error": "session not found"}), 404

    rows = _fetch_session_rows(conn, session_id)
    conn.close()
    return jsonify(_summary_from_rows(session_id, rows))


# =========================================================================
# Reports APIs
# =========================================================================

def _report_row_summary(r):
    return {
        "id":                 r["id"],
        "session_id":         r["session_id"],
        "ip":                 r["ip"],
        "generated_at":       r["generated_at"],
        "first_seen":         r["first_seen"],
        "last_seen":          r["last_seen"],
        "event_count":        r["event_count"],
        "max_severity_label": r["max_severity_label"],
        "mitre_techniques":   json.loads(r["mitre_techniques"] or "[]"),
        "status":             r["status"],
    }


@app.route("/api/reports/generate", methods=["POST"])
@login_required
def api_reports_generate():
    body = request.get_json(silent=True) or {}
    session_id = str(body.get("session_id", "")).strip()
    if not session_id:
        return jsonify({"error": "session_id is required"}), 400
    report = generate_report(session_id)
    if report is None:
        return jsonify({"error": "session not found"}), 404
    return jsonify(report), 201


@app.route("/api/reports")
@login_required
def api_reports():
    direction = "ASC" if request.args.get("sort", "desc").lower() == "asc" else "DESC"
    conn = get_db()
    rows = conn.execute(
        f"SELECT * FROM reports ORDER BY generated_at {direction}, id {direction}"
    ).fetchall()
    conn.close()
    return jsonify([_report_row_summary(r) for r in rows])


@app.route("/api/reports/<int:report_id>")
@login_required
def api_report_detail(report_id):
    conn = get_db()
    r = conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    if r is None:
        conn.close()
        return jsonify({"error": "report not found"}), 404

    # Live timeline + IOCs, recomputed from events (web- or SSH-aware).
    rows = _fetch_session_rows(conn, r["session_id"])
    conn.close()

    detail = _report_row_summary(r)
    detail["summary_text"] = r["summary_text"]
    detail["recommended_action"] = r["recommended_action"]
    if _is_web_session(r["session_id"]):
        detail["iocs"] = _web_iocs(rows) if rows else {
            "ip": r["ip"], "credentials": [], "commands": [], "paths": []}
    else:
        detail["iocs"] = _report_iocs(rows) if rows else {
            "ip": r["ip"], "credentials": [], "commands": [], "paths": []}
    detail["events"] = _event_dicts(rows)
    return jsonify(detail)


# =========================================================================
# Alerts APIs, correlated detections from the engine in pipeline.py
# =========================================================================

def _alert_row_summary(r):
    return {
        "id":             r["id"],
        "rule_name":      r["rule_name"],
        "title":          r["title"],
        "severity_label": r["severity_label"],
        "ip":             r["ip"],
        "session_id":     r["session_id"],
        "event_count":    r["event_count"],
        "mitre_techniques": json.loads(r["mitre_techniques"] or "[]"),
        "alert_status":   r["alert_status"] or "new",
        "created_at":     r["created_at"],
    }


@app.route("/api/alerts")
@login_required
def api_alerts():
    direction = "ASC" if request.args.get("sort", "desc").lower() == "asc" else "DESC"
    conn = get_db()
    try:
        rows = conn.execute(
            f"SELECT * FROM detections ORDER BY created_at {direction}, id {direction}"
        ).fetchall()
    except sqlite3.OperationalError:
        # detections table not created yet (pipeline hasn't run) -> empty list
        conn.close()
        return jsonify([])
    conn.close()
    return jsonify([_alert_row_summary(r) for r in rows])


@app.route("/api/alerts/<int:alert_id>")
@login_required
def api_alert_detail(alert_id):
    conn = get_db()
    try:
        r = conn.execute("SELECT * FROM detections WHERE id = ?", (alert_id,)).fetchone()
    except sqlite3.OperationalError:
        conn.close()
        return jsonify({"error": "alert not found"}), 404
    if r is None:
        conn.close()
        return jsonify({"error": "alert not found"}), 404

    event_ids = json.loads(r["event_ids"] or "[]")
    events = []
    if event_ids:
        placeholders = ",".join("?" * len(event_ids))
        rows = conn.execute(
            f"SELECT * FROM events WHERE id IN ({placeholders}) ORDER BY id ASC",
            event_ids
        ).fetchall()
        events = _event_dicts(rows)
    conn.close()

    detail = _alert_row_summary(r)
    detail["description"] = r["description"]
    detail["rule_key"] = r["rule_key"]
    detail["analyst_notes"] = r["analyst_notes"] or ""
    detail["events"] = events
    return jsonify(detail)


@app.route("/api/alerts/<int:alert_id>/status", methods=["POST"])
@login_required
def api_alert_update_status(alert_id):
    body = request.get_json(silent=True) or {}
    status = str(body.get("status", "")).strip().lower()
    notes = str(body.get("notes", ""))
    if status not in CASE_STATUSES:
        return jsonify({"error": f"status must be one of {', '.join(CASE_STATUSES)}"}), 400

    conn = get_db()
    cur = conn.execute(
        "UPDATE detections SET alert_status = ?, analyst_notes = ? WHERE id = ?",
        (status, notes, alert_id)
    )
    conn.commit()
    if cur.rowcount == 0:
        conn.close()
        return jsonify({"error": "alert not found"}), 404
    r = conn.execute("SELECT * FROM detections WHERE id = ?", (alert_id,)).fetchone()
    conn.close()
    return jsonify(_alert_row_summary(r))


# =========================================================================
# Detection Rules APIs, user-defined Level-1 threshold rules
# =========================================================================

# Must match the allow-lists in pipeline.py's user-rule evaluator.
RULE_FIELDS = ("", "severity", "type", "source", "ip", "category", "mitre")
RULE_GROUPS = ("ip", "session_id")
RULE_SEVERITIES = ("critical", "high", "medium", "low", "info")


def _rule_row(r):
    return {
        "id":             r["id"],
        "name":           r["name"],
        "enabled":        bool(r["enabled"]),
        "field":          r["field"] or "",
        "value":          r["value"] or "",
        "group_by":       r["group_by"] or "ip",
        "threshold":      r["threshold"],
        "window_minutes": r["window_minutes"],
        "severity":       r["severity"],
        "trigger_count":  r["trigger_count"] if "trigger_count" in r.keys() else 0,
        "last_triggered": r["last_triggered"] if "last_triggered" in r.keys() else None,
        "created_at":     r["created_at"],
    }


def _validate_rule(body):
    """Return (clean_dict, error). Enforces the allow-lists so nothing unsafe
    reaches the engine."""
    name = str(body.get("name", "")).strip()
    if not name:
        return None, "name is required"
    field = str(body.get("field", "")).strip()
    if field not in RULE_FIELDS:
        return None, "invalid field"
    value = str(body.get("value", "")).strip()
    if field and not value:
        return None, "value is required when a field is chosen"
    group_by = str(body.get("group_by", "ip")).strip()
    if group_by not in RULE_GROUPS:
        return None, "invalid group_by"
    severity = str(body.get("severity", "medium")).strip()
    if severity not in RULE_SEVERITIES:
        return None, "invalid severity"
    try:
        threshold = int(body.get("threshold", 5))
        window = int(body.get("window_minutes", 60))
    except (TypeError, ValueError):
        return None, "threshold and window must be numbers"
    if threshold < 1 or threshold > 100000:
        return None, "threshold out of range"
    if window < 1 or window > 43200:
        return None, "window_minutes out of range (1..43200)"
    return {
        "name": name, "field": field, "value": value, "group_by": group_by,
        "threshold": threshold, "window_minutes": window, "severity": severity,
    }, None


def _rules_table_ready(conn):
    try:
        conn.execute("SELECT 1 FROM rules LIMIT 1")
        return True
    except sqlite3.OperationalError:
        return False


@app.route("/api/rules")
@login_required
def api_rules_list():
    conn = get_db()
    if not _rules_table_ready(conn):
        conn.close(); return jsonify([])
    rows = conn.execute("SELECT * FROM rules ORDER BY id DESC").fetchall()
    conn.close()
    return jsonify([_rule_row(r) for r in rows])


@app.route("/api/rules", methods=["POST"])
@login_required
def api_rules_create():
    clean, err = _validate_rule(request.get_json(silent=True) or {})
    if err:
        return jsonify({"error": err}), 400
    conn = get_db()
    if not _rules_table_ready(conn):
        conn.close()
        return jsonify({"error": "rules table not initialised, start pipeline.py once"}), 503
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    cur = conn.execute("""
        INSERT INTO rules (name, enabled, field, value, group_by, threshold,
                           window_minutes, severity, trigger_count, created_at)
        VALUES (?, 1, ?, ?, ?, ?, ?, ?, 0, ?)
    """, (clean["name"], clean["field"], clean["value"], clean["group_by"],
          clean["threshold"], clean["window_minutes"], clean["severity"], now))
    conn.commit()
    rid = cur.lastrowid
    r = conn.execute("SELECT * FROM rules WHERE id = ?", (rid,)).fetchone()
    conn.close()
    return jsonify(_rule_row(r)), 201


@app.route("/api/rules/<int:rule_id>", methods=["PUT"])
@login_required
def api_rules_update(rule_id):
    clean, err = _validate_rule(request.get_json(silent=True) or {})
    if err:
        return jsonify({"error": err}), 400
    conn = get_db()
    if not _rules_table_ready(conn):
        conn.close(); return jsonify({"error": "rules table not initialised"}), 503
    cur = conn.execute("""
        UPDATE rules SET name=?, field=?, value=?, group_by=?, threshold=?,
               window_minutes=?, severity=? WHERE id=?
    """, (clean["name"], clean["field"], clean["value"], clean["group_by"],
          clean["threshold"], clean["window_minutes"], clean["severity"], rule_id))
    conn.commit()
    if cur.rowcount == 0:
        conn.close(); return jsonify({"error": "rule not found"}), 404
    r = conn.execute("SELECT * FROM rules WHERE id = ?", (rule_id,)).fetchone()
    conn.close()
    return jsonify(_rule_row(r))


@app.route("/api/rules/<int:rule_id>/toggle", methods=["POST"])
@login_required
def api_rules_toggle(rule_id):
    conn = get_db()
    if not _rules_table_ready(conn):
        conn.close(); return jsonify({"error": "rules table not initialised"}), 503
    r = conn.execute("SELECT enabled FROM rules WHERE id = ?", (rule_id,)).fetchone()
    if r is None:
        conn.close(); return jsonify({"error": "rule not found"}), 404
    new_val = 0 if r["enabled"] else 1
    conn.execute("UPDATE rules SET enabled = ? WHERE id = ?", (new_val, rule_id))
    conn.commit()
    r = conn.execute("SELECT * FROM rules WHERE id = ?", (rule_id,)).fetchone()
    conn.close()
    return jsonify(_rule_row(r))


@app.route("/api/rules/<int:rule_id>", methods=["DELETE"])
@login_required
def api_rules_delete(rule_id):
    conn = get_db()
    if not _rules_table_ready(conn):
        conn.close(); return jsonify({"error": "rules table not initialised"}), 503
    cur = conn.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
    conn.commit()
    # also clear any alerts this rule produced, so the list stays clean
    conn.execute("DELETE FROM detections WHERE rule_key LIKE ?", (f"userrule:{rule_id}:%",))
    conn.commit()
    conn.close()
    if cur.rowcount == 0:
        return jsonify({"error": "rule not found"}), 404
    return jsonify({"deleted": rule_id})


if __name__ == "__main__":
    # Binds to localhost by default; set SIEM_BIND=0.0.0.0 in .env to reach it from the LAN.
    app.run(host=config.SIEM_BIND, port=config.SIEM_PORT, debug=False)