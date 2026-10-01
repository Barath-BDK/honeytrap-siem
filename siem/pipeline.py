r"""
pipeline.py, combined log puller + enrichment worker.

Each cycle: (1) pull ssh.json / web.json from the honeypot VM over SFTP,
(2) ingest + enrich any new lines into siem.db.

Run from the siem/ folder with the virtualenv active:
    python pipeline.py
"""

import json
import os
import sqlite3
import time
from datetime import datetime

import paramiko

import config

# =========================================================================
# Configuration (all values come from .env via config.py)
# =========================================================================

VM_HOST     = config.HONEYPOT_HOST
VM_PORT     = config.HONEYPOT_SFTP_PORT
VM_USER     = config.HONEYPOT_SFTP_USER
VM_PASSWORD = config.HONEYPOT_SFTP_PASSWORD

REMOTE_LOGS = [
    config.HONEYPOT_LOG_DIR.rstrip("/") + "/ssh.json",
    config.HONEYPOT_LOG_DIR.rstrip("/") + "/web.json",
]

LOCAL_DIR    = config.LOCAL_LOG_DIR
DB_PATH      = config.DB_PATH
OFFSETS_PATH = config.OFFSETS_PATH
LOG_FILES    = ["ssh.json", "web.json"]

CYCLE_INTERVAL_SECONDS = config.CYCLE_SECONDS

config.warn_placeholders(["HONEYPOT_HOST", "HONEYPOT_SFTP_USER", "HONEYPOT_SFTP_PASSWORD", "HONEYPOT_LOG_DIR"])

os.makedirs(LOCAL_DIR, exist_ok=True)

# =========================================================================
# Stage 1, SFTP pull
# =========================================================================

def pull_logs():
    try:
        transport = paramiko.Transport((VM_HOST, VM_PORT))
        transport.connect(username=VM_USER, password=VM_PASSWORD)
        sftp = paramiko.SFTPClient.from_transport(transport)

        for remote_path in REMOTE_LOGS:
            filename = os.path.basename(remote_path)
            local_path = os.path.join(LOCAL_DIR, filename)
            sftp.get(remote_path, local_path)

        sftp.close()
        transport.close()
        print(f"[{time.strftime('%H:%M:%S')}] Synced logs successfully")

    except FileNotFoundError:
        print(f"[{time.strftime('%H:%M:%S')}] One or more remote log files don't exist yet, skipping this cycle")
    except Exception as e:
        print(f"[{time.strftime('%H:%M:%S')}] Error pulling logs: {e}")

# =========================================================================
# Stage 2, enrichment / ingest
# =========================================================================

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT,
            type TEXT NOT NULL,
            ip TEXT,
            session_id TEXT,
            username TEXT,
            password TEXT,
            command TEXT,
            path TEXT,
            method TEXT,
            user_agent TEXT,
            post_data TEXT,
            trap_triggered INTEGER,
            category TEXT,
            mitre_technique TEXT,
            extracted_url TEXT,
            attempt_number_for_ip INTEGER,
            total_attempts INTEGER,
            severity_score INTEGER,
            severity_label TEXT,
            alert_status TEXT DEFAULT 'new',
            analyst_notes TEXT,
            timestamp TEXT,
            ingested_at TEXT
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ip ON events(ip)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_session ON events(session_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_type ON events(type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_severity ON events(severity_score)")

    # --- detection engine output: correlated alerts ---
    conn.execute("""
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_name TEXT NOT NULL,
            rule_key  TEXT,                 -- rule + scope, for dedup
            title TEXT,
            description TEXT,
            severity_label TEXT,
            ip TEXT,
            session_id TEXT,
            event_ids TEXT,                 -- JSON list of contributing event ids
            event_count INTEGER,
            mitre_techniques TEXT,          -- JSON list
            alert_status TEXT DEFAULT 'new',
            analyst_notes TEXT,
            created_at TEXT
        )
    """)
    # One alert per (rule + scope): dedup key is UNIQUE so a repeated pattern
    # updates the existing alert instead of spawning a new one every cycle.
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_det_key ON detections(rule_key)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_det_ip ON detections(ip)")

    # --- user-defined (Level-1 threshold) detection rules ---
    conn.execute("""
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            field TEXT,                     -- allow-listed column, or '' for any
            value TEXT,                     -- required value when field set
            group_by TEXT DEFAULT 'ip',     -- 'ip' or 'session_id'
            threshold INTEGER DEFAULT 5,
            window_minutes INTEGER DEFAULT 60,
            severity TEXT DEFAULT 'medium',
            trigger_count INTEGER DEFAULT 0,-- how many times this rule has fired
            last_triggered TEXT,
            created_at TEXT
        )
    """)
    conn.commit()
    conn.close()


def load_offsets():
    if os.path.exists(OFFSETS_PATH):
        with open(OFFSETS_PATH) as f:
            return json.load(f)
    return {}


def save_offsets(offsets):
    with open(OFFSETS_PATH, "w") as f:
        json.dump(offsets, f)


def score_to_label(score):
    if score >= 9: return "critical"
    if score >= 7: return "high"
    if score >= 4: return "medium"
    if score >= 2: return "low"
    return "info"


# Trap categories -> severity. Covers SSH post-exploitation categories AND the
# new web-attack categories emitted by the enhanced web honeypot.
TRAP_SEVERITY = {
    # --- SSH post-exploitation (unchanged) ---
    "malware_download":      10,
    "reverse_shell_attempt": 10,
    "persistence_attempt":   9,
    "log_tampering":         8,
    "obfuscated_payload":    8,
    "execution_attempt":     7,
    "account_creation":      7,
    "recon":                 4,
    # --- web attack payloads (new) ---
    "cmdi":      8,   # command injection  (T1059)
    "sqli":      7,   # SQL injection      (T1190)
    "lfi":       7,   # local file include (T1083)
    "traversal": 6,   # path traversal     (T1083)
    "xss":       5,   # cross-site script  (T1059)
     # --- SSH memory & escalation (new) ---
    "memory_exploit_attempt": 9,   # buffer overflow / shellcode / format string (T1203)
    "ssh_key_persistence":    9,   # authorized_keys implant (T1098.004)
    "privilege_escalation":   8,   # sudo / SUID abuse (T1548)
    "credential_theft":       7,   # honeytoken file access (T1552.001)
    # --- supply chain (new) ---
    "supply_chain_attempt": 8,   # malicious install / dependency tamper / CI-CD secret (T1195)
    "rogue_repository":     8,   # rogue apt/pip/npm source (T1195.002)
}

# Route-based (no-payload) event types -> baseline severity.
BASE_SEVERITY = {
    # --- SSH (unchanged) ---
    "ssh_brute_force_confirmed": 8,
    "ssh_auth_attempt":          2,
    "ssh_connect":               1,
    # --- web route probes ---
    "web_env_probe":             5,
    "web_git_probe":             5,   # new: exposed .git
    "web_backup_probe":          5,   # new: exposed backups
    "web_phpmyadmin_probe":      4,
    "web_admin_probe":           3,
    "web_api_probe":             3,   # new: search/api endpoints
    "web_robots_probe":          2,
    "web_404_probe":             2,
    "web_registry_probe":   4,   # rogue/internal registry enumeration (T1195)
}


def compute_severity(evt):
    """Trap-triggered events (SSH post-exploitation OR web attack payloads)
    are scored by category; everything else by its route/type baseline."""
    etype = evt.get("type")
    if evt.get("trap_triggered"):
        # Generalized from ssh_command-only to any trap-triggering event,
        # so web SQLi/XSS/cmdi/traversal are scored by category too.
        score = TRAP_SEVERITY.get(evt.get("category"), 6)
    elif etype == "ssh_command":
        score = 3
    else:
        score = BASE_SEVERITY.get(etype, 1)
    return score, score_to_label(score)


def process_file(filename, offsets, conn):
    local_path = os.path.join(LOCAL_DIR, filename)
    if not os.path.exists(local_path):
        return 0

    source = "ssh" if filename.startswith("ssh") else "web"
    last_offset = offsets.get(filename, 0)
    file_size = os.path.getsize(local_path)

    if file_size < last_offset:
        last_offset = 0

    new_count = 0
    with open(local_path, "r", encoding="utf-8") as f:
        f.seek(last_offset)
        lines = f.readlines()

        consumed = 0
        for line in lines:
            if not line.endswith("\n"):
                break
            consumed += len(line.encode("utf-8"))
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue

            score, label = compute_severity(evt)
            post_data = evt.get("post_data")

            conn.execute("""
                INSERT INTO events (
                    source, type, ip, session_id, username, password, command,
                    path, method, user_agent, post_data, trap_triggered, category,
                    mitre_technique, extracted_url, attempt_number_for_ip,
                    total_attempts, severity_score, severity_label, timestamp, ingested_at
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                source, evt.get("type"), evt.get("ip"), evt.get("session_id"),
                evt.get("username"), evt.get("password"), evt.get("command"),
                evt.get("path"), evt.get("method"), evt.get("user_agent"),
                json.dumps(post_data) if post_data else None,
                1 if evt.get("trap_triggered") else 0,
                evt.get("category"), evt.get("mitre_technique"),
                evt.get("extracted_url"), evt.get("attempt_number_for_ip"),
                evt.get("total_attempts"), score, label,
                evt.get("timestamp"), datetime.utcnow().isoformat() + "Z"
            ))
            new_count += 1

        offsets[filename] = last_offset + consumed

    conn.commit()
    return new_count

# =========================================================================
# Combined pipeline loop
# =========================================================================

# =========================================================================
# Detection engine, correlates events into alerts (runs each cycle)
# =========================================================================
# Alerts are separate objects: they never rewrite event/session severity.
# Two built-in rules for now, kill-chain completion and cross-surface
# correlation. Each alert is deduplicated by a rule_key so a persistent
# pattern produces ONE alert that updates, not a new one every cycle.

import json as _json

# Kill-chain stages, mapped from the categories the honeypots actually emit.
# The mapping is explicit so it is easy to justify and easy to extend.
KILL_CHAIN_STAGES = {
    "recon": [
        "recon",
    ],
    "access": [        # gaining/attempting access
        "sqli", "cmdi", "lfi", "traversal", "xss",
        "memory_exploit_attempt", "privilege_escalation",
    ],
    "credential": [    # credential access
        "credential_theft",
    ],
    "action": [        # objective / impact actions
        "malware_download", "reverse_shell_attempt",
        "supply_chain_attempt", "rogue_repository", "obfuscated_payload",
        "execution_attempt", "log_tampering",
    ],
    "persistence": [
        "persistence_attempt", "ssh_key_persistence", "account_creation",
    ],
}
# category -> stage lookup
_CAT_STAGE = {cat: stage for stage, cats in KILL_CHAIN_STAGES.items() for cat in cats}

# A kill chain is "completed" when a single session touches at least this many
# distinct stages, and includes at least one of these high-value stages.
KILL_CHAIN_MIN_STAGES = 3
KILL_CHAIN_REQUIRED_ANY = {"credential", "action", "persistence"}

# Base-severity (route) types also count toward the recon/access stages so a
# brute force -> theft -> persistence chain is recognised even across event
# kinds. brute-force confirmed counts as an access stage.
_TYPE_STAGE = {
    "ssh_brute_force_confirmed": "access",
}


def _stage_of(row):
    cat = row["category"]
    if cat and cat in _CAT_STAGE:
        return _CAT_STAGE[cat]
    return _TYPE_STAGE.get(row["type"])


def _upsert_detection(conn, rule_name, rule_key, title, description,
                      severity_label, ip, session_id, event_ids, techniques):
    """Insert a new alert, or update the existing one for this rule_key
    (dedup). Preserves analyst status/notes across updates."""
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    existing = conn.execute(
        "SELECT id FROM detections WHERE rule_key = ?", (rule_key,)
    ).fetchone()
    if existing:
        conn.execute("""
            UPDATE detections
               SET event_ids = ?, event_count = ?, mitre_techniques = ?,
                   description = ?, severity_label = ?
             WHERE rule_key = ?
        """, (_json.dumps(event_ids), len(event_ids), _json.dumps(techniques),
              description, severity_label, rule_key))
    else:
        conn.execute("""
            INSERT INTO detections (
                rule_name, rule_key, title, description, severity_label,
                ip, session_id, event_ids, event_count, mitre_techniques,
                alert_status, created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?, 'new', ?)
        """, (rule_name, rule_key, title, description, severity_label,
              ip, session_id, _json.dumps(event_ids), len(event_ids),
              _json.dumps(techniques), now))


def _rule_kill_chain(conn):
    """RULE: kill-chain completion. A single SSH session that progresses
    through >= KILL_CHAIN_MIN_STAGES distinct stages (including at least one
    high-value stage) is a confirmed multi-stage intrusion."""
    sessions = conn.execute("""
        SELECT DISTINCT session_id FROM events
        WHERE session_id IS NOT NULL AND session_id != ''
    """).fetchall()

    for s in sessions:
        sid = s["session_id"]
        rows = conn.execute(
            "SELECT * FROM events WHERE session_id = ? ORDER BY id ASC", (sid,)
        ).fetchall()

        stages, ids, techs = {}, [], []
        for r in rows:
            st = _stage_of(r)
            if st:
                stages.setdefault(st, []).append(r["id"])
                ids.append(r["id"])
                if r["mitre_technique"] and r["mitre_technique"] not in techs:
                    techs.append(r["mitre_technique"])

        if len(stages) >= KILL_CHAIN_MIN_STAGES and (set(stages) & KILL_CHAIN_REQUIRED_ANY):
            ip = rows[0]["ip"] if rows else None
            order = [st for st in ["recon", "access", "credential", "action", "persistence"] if st in stages]
            desc = ("Session progressed through multiple attack stages: "
                    + " → ".join(order) + ". This indicates a completed "
                    "multi-stage intrusion rather than isolated probing.")
            _upsert_detection(
                conn, "Kill-chain completion", f"killchain:{sid}",
                f"Multi-stage intrusion in session {sid[:8]}",
                desc, "critical", ip, sid, ids, techs)


def _rule_cross_surface(conn):
    """RULE: cross-surface correlation. An IP that attacks BOTH the SSH and
    web honeypots is a coordinated, multi-vector adversary."""
    rows = conn.execute("""
        SELECT ip,
               SUM(CASE WHEN source = 'ssh' THEN 1 ELSE 0 END) AS ssh_n,
               SUM(CASE WHEN source = 'web' THEN 1 ELSE 0 END) AS web_n
        FROM events
        WHERE ip IS NOT NULL AND ip != ''
        GROUP BY ip
        HAVING ssh_n > 0 AND web_n > 0
    """).fetchall()

    for r in rows:
        ip = r["ip"]
        ev = conn.execute(
            "SELECT id, mitre_technique FROM events WHERE ip = ? ORDER BY id ASC", (ip,)
        ).fetchall()
        ids = [e["id"] for e in ev]
        techs = []
        for e in ev:
            if e["mitre_technique"] and e["mitre_technique"] not in techs:
                techs.append(e["mitre_technique"])
        desc = (f"Source {ip} attacked both the SSH honeypot ({r['ssh_n']} events) "
                f"and the web honeypot ({r['web_n']} events), indicating a "
                f"coordinated multi-vector adversary rather than a single-surface scan.")
        _upsert_detection(
            conn, "Cross-surface correlation", f"crosssurface:{ip}",
            f"Multi-vector attacker {ip}",
            desc, "high", ip, None, ids, techs)


# --- user-defined threshold rules --------------------------------------------
# Fields a user rule may filter on. Fixed column names (never user input), so
# they can be interpolated into SQL safely; values are always parameterised.
RULE_FIELD_COLUMNS = {
    "severity": "severity_label",
    "type":     "type",
    "source":   "source",
    "ip":       "ip",
    "category": "category",
    "mitre":    "mitre_technique",
}
RULE_GROUP_COLUMNS = {"ip": "ip", "session_id": "session_id"}
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def _bump_trigger_count(conn, rule_id):
    conn.execute(
        "UPDATE rules SET trigger_count = trigger_count + 1, last_triggered = ? WHERE id = ?",
        (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), rule_id)
    )


def _evaluate_user_rule(conn, rule):
    """Evaluate one Level-1 threshold rule: count events (optionally matching a
    field=value) grouped by ip/session within a time window; raise an alert for
    any group meeting the threshold. Dedup + case-management reuse the built-in
    detections machinery."""
    field   = (rule["field"] or "").strip()
    value   = (rule["value"] or "").strip()
    group   = rule["group_by"] if rule["group_by"] in RULE_GROUP_COLUMNS else "ip"
    gcol    = RULE_GROUP_COLUMNS[group]
    thresh  = int(rule["threshold"] or 1)
    window  = int(rule["window_minutes"] or 60)
    sev     = rule["severity"] if rule["severity"] in VALID_SEVERITIES else "medium"

    # time-window lower bound (UTC ISO, matches how events store timestamps)
    since = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                          time.gmtime(time.time() - window * 60))

    conds = [f"{gcol} IS NOT NULL AND {gcol} != ''", "timestamp >= ?"]
    params = [since]
    if field and field in RULE_FIELD_COLUMNS:
        col = RULE_FIELD_COLUMNS[field]
        conds.append(f"{col} = ?")
        params.append(value)
    where = " AND ".join(conds)

    groups = conn.execute(
        f"SELECT {gcol} AS g, COUNT(*) AS c FROM events WHERE {where} "
        f"GROUP BY {gcol} HAVING c >= ?",
        params + [thresh]
    ).fetchall()

    for grp in groups:
        gval, count = grp["g"], grp["c"]
        # contributing events (same window + filter, this group)
        ev = conn.execute(
            f"SELECT id, ip, mitre_technique FROM events WHERE {where} AND {gcol} = ? ORDER BY id ASC",
            params + [gval]
        ).fetchall()
        ids = [e["id"] for e in ev]
        techs = []
        for e in ev:
            if e["mitre_technique"] and e["mitre_technique"] not in techs:
                techs.append(e["mitre_technique"])
        ip = ev[0]["ip"] if ev else (gval if group == "ip" else None)

        cond_txt = f"{field}={value}" if field else "any activity"
        desc = (f"User rule '{rule['name']}' matched: {count} event(s) "
                f"({cond_txt}) from {group} {gval} within {window} minute(s), "
                f"meeting the threshold of {thresh}.")
        rule_key = f"userrule:{rule['id']}:{gval}"

        existed = conn.execute(
            "SELECT id FROM detections WHERE rule_key = ?", (rule_key,)
        ).fetchone()
        _upsert_detection(
            conn, f"User rule: {rule['name']}", rule_key,
            f"{rule['name']}, {group} {gval}",
            desc, sev, ip, (gval if group == "session_id" else None), ids, techs)
        if not existed:
            _bump_trigger_count(conn, rule["id"])


def _rule_user_defined(conn):
    """Run every enabled user rule. Skips silently if the table is absent."""
    try:
        rules = conn.execute("SELECT * FROM rules WHERE enabled = 1").fetchall()
    except Exception:
        return
    for rule in rules:
        try:
            _evaluate_user_rule(conn, rule)
        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] user rule '{rule['name']}' error: {e}")


DETECTION_RULES = [_rule_kill_chain, _rule_cross_surface, _rule_user_defined]


def run_correlation(conn):
    """Run every built-in rule. Returns the number of alerts currently active."""
    # Rules read rows by column name, so ensure a Row factory regardless of
    # how the caller created the connection.
    conn.row_factory = sqlite3.Row
    for rule in DETECTION_RULES:
        try:
            rule(conn)
        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] detection rule error: {e}")
    conn.commit()
    return conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]


def main():
    init_db()
    offsets = load_offsets()

    print("=" * 62)
    print(" HONEYTRAP SIEM pipeline, SFTP pull + enrichment (combined)")
    print(f"   source : {VM_USER}@{VM_HOST}:{VM_PORT}  ->  ./{LOCAL_DIR}/")
    print(f"   sink   : {DB_PATH} (table: events)")
    print(f"   cycle  : every {CYCLE_INTERVAL_SECONDS}s, Ctrl+C to stop")
    print("=" * 62)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row   # rules read rows by column name
    try:
        while True:
            pull_logs()

            total_new = 0
            for filename in LOG_FILES:
                total_new += process_file(filename, offsets, conn)
            save_offsets(offsets)

            # Correlate events into alerts after each ingest cycle.
            if total_new > 0:
                run_correlation(conn)
                print(f"[{time.strftime('%H:%M:%S')}] Ingested {total_new} new event(s)")

            time.sleep(CYCLE_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()