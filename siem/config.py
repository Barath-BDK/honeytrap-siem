"""
Central configuration for the SIEM (app.py + pipeline.py).

Values are read from environment variables, and a `.env` file in the project
root (one folder above this file) or in this folder is loaded automatically.
Copy `.env.example` to `.env` and fill in your own values. Never commit `.env`.
"""
import os
import secrets
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))


def _load_dotenv():
    for path in (os.path.join(os.path.dirname(_HERE), ".env"), os.path.join(_HERE, ".env")):
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                key, val = key.strip(), val.strip()
                if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
                    val = val[1:-1]
                os.environ.setdefault(key, val)   # real env vars win over .env
        break


_load_dotenv()


def get(name, default):
    return os.environ.get(name, default)


def is_placeholder(value):
    return isinstance(value, str) and value.startswith("<") and value.endswith(">")


# ---- dashboard -----------------------------------------------------------
SECRET_KEY         = get("SIEM_SECRET_KEY", "<SIEM_SECRET_KEY>")
DASHBOARD_USERNAME = get("SIEM_ADMIN_USER", "<SIEM_ADMIN_USER>")
DASHBOARD_PASSWORD = get("SIEM_ADMIN_PASSWORD", "<SIEM_ADMIN_PASSWORD>")
DB_PATH            = get("SIEM_DB_PATH", os.path.join(_HERE, "siem.db"))
SIEM_BIND          = get("SIEM_BIND", "127.0.0.1")
SIEM_PORT          = int(get("SIEM_PORT", "5000"))

# ---- honeypot VM (log source) -------------------------------------------
HONEYPOT_HOST          = get("HONEYPOT_HOST", "<HONEYPOT_VM_IP>")
HONEYPOT_SFTP_PORT     = int(get("HONEYPOT_SFTP_PORT", "2222"))
HONEYPOT_SFTP_USER     = get("HONEYPOT_SFTP_USER", "<HONEYPOT_VM_USER>")
HONEYPOT_SFTP_PASSWORD = get("HONEYPOT_SFTP_PASSWORD", "<HONEYPOT_VM_PASSWORD>")
HONEYPOT_LOG_DIR       = get("HONEYPOT_LOG_DIR", "<HONEYPOT_LOG_DIR>")
HONEYPOT_SSH_PORT      = int(get("HONEYPOT_SSH_PORT", "22"))
HONEYPOT_WEB_PORT      = int(get("HONEYPOT_WEB_PORT", "8080"))

# ---- pipeline -----------------------------------------------------------
LOCAL_LOG_DIR   = get("PIPELINE_LOCAL_DIR", os.path.join(_HERE, "synced_logs"))
OFFSETS_PATH    = get("PIPELINE_OFFSETS", os.path.join(_HERE, "offsets.json"))
CYCLE_SECONDS   = int(get("PIPELINE_INTERVAL", "5"))


def warn_placeholders(names):
    """Print a clear warning for any setting still holding a <PLACEHOLDER>."""
    missing = [n for n in names if is_placeholder(globals().get(n))]
    if missing:
        print("[config] These settings still hold placeholders, edit .env: " + ", ".join(missing), file=sys.stderr)
    return missing


if is_placeholder(SECRET_KEY):
    # Safe fallback: random per process. Sessions reset on restart until you set one.
    SECRET_KEY = secrets.token_hex(32)
