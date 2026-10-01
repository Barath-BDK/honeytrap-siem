"""
ssh_honeypot.py, SSH honeypot (port 22) for the HONEYTRAP SIEM project.

Paramiko-based decoy SSH service. After a per-IP brute-force threshold it grants
a fake interactive shell over a simulated filesystem and logs every command to
logs/ssh.json. This revision adds four new detection trap classes on top of the
originals, following the same layered scheme as the web honeypot:

  * memory_exploit_attempt (T1203), buffer-overflow padding, shellcode / NOP
    sleds, format-string payloads, cyclic patterns, and exploit tooling. The
    honeypot SIMULATES being a vulnerable C service: on a detected memory
    exploit it returns a believable "Segmentation fault (core dumped)" so the
    attacker thinks the overflow landed. Nothing is actually executed.
  * privilege_escalation (T1548), sudo / su, SUID hunting, pkexec, known CVEs.
  * credential_theft (T1552.001), reads of honeytoken files (fake id_rsa,
    /etc/shadow, ~/.aws/credentials, .bash_history, .env). Fake secrets are
    served so any later reuse of them is a high-confidence tripwire.
  * ssh_key_persistence (T1098.004), authorized_keys implants, ssh-keygen.
  * supply_chain_attempt (T1195), malicious package installs, dependency-file
    and rogue-repository tampering, and CI/CD secret access. Fake install
    output and honeytokened pipeline secrets are served so the attacker
    believes the action worked.

SAFETY: this is a honeypot. No attacker input is ever executed, no real file is
read, and every "vulnerable" response is canned.
"""

import socket
import threading
import paramiko
import json
import os
import re
import uuid
from datetime import datetime

HOST_KEY_PATH = "ssh_host_key"
LOG_PATH      = "logs/ssh.json"
os.makedirs("logs", exist_ok=True)

BRUTE_FORCE_THRESHOLD = 5

# Any single command line longer than this is treated as an overflow attempt -
# no legitimate interactive command approaches this length.
OVERSIZED_INPUT_LEN = 800

if os.path.exists(HOST_KEY_PATH):
    HOST_KEY = paramiko.RSAKey(filename=HOST_KEY_PATH)
else:
    HOST_KEY = paramiko.RSAKey.generate(2048)
    HOST_KEY.write_private_key_file(HOST_KEY_PATH)

attempt_counts = {}
attempt_lock = threading.Lock()


def log_event(data):
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(data) + "\n")


# ===========================================================================
# Trap detection, ordered by priority (most severe first). One command maps
# to one category, matching the existing SSH model.
# ===========================================================================

TRAP_PATTERNS = [
    # --- memory-corruption exploitation attempts (T1203) ---
    (r"(\\x90){2,}",                                  "memory_exploit_attempt", "T1203"),  # NOP sled
    (r"(\\x[0-9a-fA-F]{2}){6,}",                      "memory_exploit_attempt", "T1203"),  # shellcode blob
    (r"%n|(%[xpsn]){4,}",                             "memory_exploit_attempt", "T1203"),  # format string
    (r"A{60,}",                                       "memory_exploit_attempt", "T1203"),  # overflow padding
    (r"Aa0Aa1Aa2|aaaabaaacaaad",                      "memory_exploit_attempt", "T1203"),  # cyclic pattern
    (r"(print|str|['\"]).{0,12}\*\s*\d{3,}",          "memory_exploit_attempt", "T1203"),  # python 'A'*N
    (r"perl\s+-e.{0,40}x\s*\d{3,}",                   "memory_exploit_attempt", "T1203"),  # perl "A"xN
    (r"\b(msfvenom|pwntools|ropgadget|ropper|checksec|pattern_create|cyclic|gef|pwndbg|gdb)\b",
                                                       "memory_exploit_attempt", "T1203"),  # exploit tooling
    (r"/proc/self/(maps|mem)",                        "memory_exploit_attempt", "T1203"),  # memory inspection

    # --- supply chain: malicious installs / dependency & repo tampering (T1195) ---
    (r"(pip[0-9.]*|pip3)\s+install\s+|(npm|yarn|pnpm)\s+(install|add|i)\s+|"
     r"gem\s+install|go\s+install|cargo\s+install|apt(-get)?\s+install",
                                                       "supply_chain_attempt",   "T1195.002"),  # package install
    (r"(curl|wget)\s+\S*https?://\S+\s*\|\s*(sudo\s+)?(bash|sh|python[0-9.]*)",
                                                       "supply_chain_attempt",   "T1195.002"),  # piped installer
    (r">>?\s*\S*(requirements\.txt|package\.json|Gemfile|go\.mod|pom\.xml|build\.gradle)|"
     r"(nano|vi|vim|echo|tee)\s+\S*(requirements\.txt|package\.json|Gemfile|go\.mod)",
                                                       "supply_chain_attempt",   "T1195.001"),  # dependency-file tamper
    (r"/etc/apt/sources\.list|\.npmrc|pip\.conf|/etc/pip\.conf|\.pip/pip\.conf|registry\s*=|--index-url|--extra-index-url",
                                                       "rogue_repository",       "T1195.002"),  # rogue package source
    (r"(cat|less|more|head|tail|nano|vi|vim|strings)\s+\S*"
     r"(\.github/workflows|Jenkinsfile|\.gitlab-ci\.yml|\.circleci|\.docker/config\.json|\.pypirc|deploy[_-]?key)",
                                                       "supply_chain_attempt",   "T1195"),        # CI/CD secret access

    # --- reverse shell (T1059) ---
    (r"\bnc\b\s+-|bash\s+-i|/dev/tcp/|mkfifo.*\bnc\b|sh\s+-i", "reverse_shell_attempt", "T1059"),

    # --- malware download (T1105) ---
    (r"(wget|curl)\s+\S*https?://\S+",                "malware_download",       "T1105"),

    # --- SSH-key persistence (T1098.004) ---
    (r"authorized_keys|\bssh-keygen\b",              "ssh_key_persistence",    "T1098.004"),

    # --- credential theft: honeytoken file reads (T1552.001) ---
    (r"(cat|less|more|head|tail|nano|vi|vim|strings)\s+\S*"
     r"(/etc/shadow|id_rsa|\.aws/credentials|\.bash_history|(^|/|\.)env\b|\.ssh/)",
                                                       "credential_theft",       "T1552.001"),

    # --- privilege escalation (T1548) ---
    (r"\bsudo\b|\bsu\s|\bpkexec\b|polkit|dirtypipe|dirtycow|\bCVE-\d",
                                                       "privilege_escalation",   "T1548"),
    (r"find\s+/\S*.*-perm\s*[-/]?[0-7]*[24]0{3}|find\s+.*-perm.*-u=s|chmod\s+[0-7]*[24]7{2}[0-7]|chmod\s+u\+s",
                                                       "privilege_escalation",   "T1548"),

    # --- persistence via scheduled tasks (T1053) ---
    (r"crontab|/etc/cron",                            "persistence_attempt",    "T1053"),

    # --- account creation (T1136) ---
    (r"\buseradd\b|\badduser\b",                      "account_creation",       "T1136"),

    # --- log tampering (T1070) ---
    (r"history\s+-c|rm\s+.*bash_history|>\s*/var/log", "log_tampering",         "T1070"),

    # --- obfuscated payload (T1027) ---
    (r"base64\s+-d|base64\s+--decode|\beval\b",       "obfuscated_payload",     "T1027"),

    # --- execution attempt (T1222) ---
    (r"chmod\s+\+x",                                  "execution_attempt",      "T1222"),

    # --- reconnaissance (T1082) ---
    (r"\buname\b|\bwhoami\b|ifconfig|ip\s+a\b|cat\s+/etc/passwd|\blscpu\b|\bhostnamectl\b",
                                                       "recon",                  "T1082"),
]


def check_traps(cmd):
    # Oversized single line => buffer-overflow attempt.
    if len(cmd) > OVERSIZED_INPUT_LEN:
        return {"trap_triggered": True, "category": "memory_exploit_attempt",
                "mitre_technique": "T1203", "extracted_url": None}
    for pattern, category, technique in TRAP_PATTERNS:
        if re.search(pattern, cmd, re.IGNORECASE):
            url_match = re.search(r"https?://\S+", cmd)
            return {
                "trap_triggered":  True,
                "category":        category,
                "mitre_technique": technique,
                "extracted_url":   url_match.group(0) if url_match else None,
            }
    return {"trap_triggered": False}


# ===========================================================================
# Simulated filesystem + believable responses
# ===========================================================================

FAKE_RESPONSES = {
    "whoami":   "root",
    "id":       "uid=0(root) gid=0(root) groups=0(root)",
    "pwd":      "/root",
    "hostname": "ubuntu",
    "uname -a": "Linux ubuntu 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 18:15:07 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux",
    "uname":    "Linux",
    "date":     "Mon Jan 13 09:42:30 UTC 2025",
    "w":        " 09:42:31 up 42 days,  3:11,  1 user,  load average: 0.02, 0.03, 0.00",
    "ps":       "  PID TTY          TIME CMD\n 1123 pts/0    00:00:00 bash\n 1188 pts/0    00:00:00 ps",
    "df -h":    "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        49G   12G   35G  26% /",
    "free -m":  "               total        used        free\nMem:            3936        612        2841",
}

FAKE_DIRS = {
    "/":            "bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var",
    "/root":        ".aws  .bash_history  .bashrc  .profile  .ssh  backup.sh  notes.txt",
    "/root/.ssh":   "authorized_keys  id_rsa  id_rsa.pub  known_hosts",
    "/etc":         "cron.d  crontab  hostname  hosts  passwd  shadow  ssh  sudoers",
    "/home":        "admin  deploy",
    "/var/www":     "app  html",
    "/var/www/app": ".env  index.php  config.php",
}

# Non-secret readable files.
FAKE_FILES = {
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\n"
                   "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                   "admin:x:1000:1000:Admin User:/home/admin:/bin/bash\n"
                   "deploy:x:1001:1001:Deploy:/home/deploy:/bin/bash",
    "/etc/hostname": "ubuntu",
    "/etc/os-release": 'PRETTY_NAME="Ubuntu 22.04.5 LTS"\nVERSION_ID="22.04"\nID=ubuntu',
}

# Honeytoken files, fake secrets. Reads are logged as credential_theft; any
# later reuse of these exact values is a high-confidence indicator of leak.
HONEYTOKEN_FILES = {
    "/etc/shadow":
        "root:$6$rXt9pQ$K1c8yN0vB7wZ2mL4hFdG9sT3uJ6xR8aQ:19876:0:99999:7:::\n"
        "admin:$6$aB2kLm$P9xQ2mR4nT6vW8yZ1cF3hJ5kL7pS9dG:19876:0:99999:7:::",
    "/root/.ssh/id_rsa":
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gt\n"
        "cnNhAAAAAwEAAQAAAYEA0xT9pQrXt9K1c8yN0vB7wZ2mL4hFdG9sT3uJ6xR8aQP9xQ2m\n"
        "R4nT6vW8yZ1cF3hJ5kL7pS9dGxQ2mR4nT6vW8yZ1cF3hJ5kL7pS9dGxQ2mR4nT6vW8yZ\n"
        "-----END OPENSSH PRIVATE KEY-----",
    "/root/.aws/credentials":
        "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "/root/.bash_history":
        "ls -la\ncd /var/www/app\ncat .env\nmysql -u root -pS3cr3tDBpass prod\n"
        "systemctl restart nginx\ncurl http://10.0.0.5/deploy.sh | bash\nexit",
    "/var/www/app/.env":
        "APP_ENV=production\nDB_HOST=127.0.0.1\nDB_USER=app\n"
        "DB_PASSWORD=S3cr3tDBpass\nJWT_SECRET=kL9xQ2mP7wZ2mL4hFdG9sT3uJ6xR8aQ",
    "/root/.docker/config.json":
        '{\n  "auths": {\n    "registry.harlowsys.local": {\n'
        '      "auth": "aGFybG93X2RlcGxveTpEZXBsMHlSZWcyMDI0IQ=="\n    }\n  }\n}',
    "/root/.pypirc":
        "[distutils]\nindex-servers =\n    internal\n\n[internal]\n"
        "repository = https://pypi.harlowsys.local/simple\n"
        "username = ci-deploy\npassword = pyP1-Upl0ad-T0ken-9f3a",
    "/var/www/app/.github/workflows/deploy.yml":
        "name: deploy\non: [push]\njobs:\n  build:\n    runs-on: self-hosted\n"
        "    steps:\n      - uses: actions/checkout@v4\n"
        "      - run: echo \"$DEPLOY_KEY\" > id_deploy\n"
        "    env:\n      DEPLOY_KEY: ghp_R3al1sticL00k1ngT0ken0nSelfHostedRunner",
}

# Fake SUID inventory returned to SUID-hunting find commands.
FAKE_SUID_LIST = (
    "/usr/bin/sudo\n/usr/bin/passwd\n/usr/bin/chsh\n/usr/bin/chfn\n"
    "/usr/bin/newgrp\n/usr/bin/gpasswd\n/bin/mount\n/bin/su\n/usr/bin/pkexec"
)

# Path aliases so ~, relative, and absolute forms resolve to the same file.
_PATH_ALIASES = {
    "~/.ssh/id_rsa": "/root/.ssh/id_rsa", ".ssh/id_rsa": "/root/.ssh/id_rsa",
    "id_rsa": "/root/.ssh/id_rsa",
    "~/.aws/credentials": "/root/.aws/credentials", ".aws/credentials": "/root/.aws/credentials",
    "~/.bash_history": "/root/.bash_history", ".bash_history": "/root/.bash_history",
    ".env": "/var/www/app/.env",
    "/etc/passwd": "/etc/passwd", "/etc/shadow": "/etc/shadow",
    "~/.docker/config.json": "/root/.docker/config.json",
    ".docker/config.json": "/root/.docker/config.json",
    "~/.pypirc": "/root/.pypirc", ".pypirc": "/root/.pypirc",
    ".github/workflows/deploy.yml": "/var/www/app/.github/workflows/deploy.yml",
}


def _resolve(path):
    path = path.strip().strip('"').strip("'")
    if path in _PATH_ALIASES:
        return _PATH_ALIASES[path]
    return path


def _supply_chain_response(cmd):
    """Believable output for supply-chain actions (installs, rogue repos).
    Returns None to fall through to normal handling (e.g. honeytoken reads)."""
    low = cmd.lower()
    # pip install <pkg>
    m = re.search(r"pip[0-9.]*\s+install\s+([A-Za-z0-9_.\-]+)", cmd)
    if m:
        pkg = m.group(1)
        return (f"Collecting {pkg}\n"
                f"  Downloading {pkg}-1.0.2-py3-none-any.whl (18 kB)\n"
                f"Installing collected packages: {pkg}\n"
                f"Successfully installed {pkg}-1.0.2")
    # npm install <pkg>
    m = re.search(r"(npm|yarn|pnpm)\s+(?:install|add|i)\s+([A-Za-z0-9_.@/\-]+)", cmd)
    if m:
        pkg = m.group(2)
        return f"added 1 package in 1s\n\n1 package is looking for funding"
    # apt-get install
    if re.search(r"apt(-get)?\s+install", low):
        return ("Reading package lists... Done\nBuilding dependency tree... Done\n"
                "The following NEW packages will be installed:\n"
                "0 upgraded, 1 newly installed, 0 to remove.")
    # piped installer:  curl ... | bash
    if re.search(r"\|\s*(sudo\s+)?(bash|sh|python)", low):
        return ""   # script "runs" silently
    # editing / appending to a rogue repo source or dependency file
    if ">" in cmd or re.search(r"\b(nano|vi|vim|tee)\b", low):
        return ""   # write "succeeds"
    return None


def generate_response(cmd, trap_info):
    # Simulated crash on a memory-exploit attempt sells the vulnerable service.
    if trap_info.get("category") == "memory_exploit_attempt":
        return "Segmentation fault (core dumped)"

    # Play along with supply-chain actions so the attacker believes they worked.
    cat = trap_info.get("category")
    if cat in ("supply_chain_attempt", "rogue_repository"):
        r = _supply_chain_response(cmd)
        if r is not None:
            return r

    stripped = cmd.strip()
    low = stripped.lower()

    # exact canned responses
    if stripped in FAKE_RESPONSES:
        return FAKE_RESPONSES[stripped]

    first = stripped.split()[0] if stripped.split() else ""

    # SUID hunting -> believable inventory
    if first == "find" and re.search(r"-perm", low):
        return FAKE_SUID_LIST

    # file reads
    m = re.match(r"^(?:cat|less|more|head|tail|strings)\s+(\S+)", stripped)
    if m:
        path = _resolve(m.group(1))
        if path in HONEYTOKEN_FILES:
            return HONEYTOKEN_FILES[path]
        if path in FAKE_FILES:
            return FAKE_FILES[path]
        return f"cat: {m.group(1)}: No such file or directory"

    # directory listings
    if first == "ls":
        args = [a for a in stripped.split()[1:] if not a.startswith("-")]
        target = _resolve(args[0]) if args else "/root"
        if target in FAKE_DIRS:
            return FAKE_DIRS[target]
        return f"ls: cannot access '{args[0] if args else target}': No such file or directory"

    # echo, reflect content, swallow redirections (write "succeeds")
    if first == "echo":
        body = stripped[4:].strip()
        if ">" in body:
            return ""
        return body.strip('"').strip("'")

    # sudo / su, already logged as privilege_escalation; give a benign result
    if first == "sudo":
        return ""            # already root; command "runs" silently
    if first in ("su",):
        return ""

    # no-output commands
    if first in ("cd", "export", "unset", "clear", "true", ":", "history"):
        return ""

    # exact uname -a etc handled above; default: silent
    return ""


# ===========================================================================
# Shell loop
# ===========================================================================

def fake_shell(chan, ip, session_id):
    buf = ""
    while True:
        try:
            data = chan.recv(4096)
            if not data:
                break
            for ch in data.decode("utf-8", errors="ignore"):
                if ch in ("\r", "\n"):
                    cmd = buf.strip()
                    if cmd:
                        trap_info = check_traps(cmd)
                        log_event({
                            "type":       "ssh_command",
                            "ip":         ip,
                            "session_id": session_id,
                            "command":    cmd,
                            "timestamp":  datetime.utcnow().isoformat() + "Z",
                            **trap_info,
                        })
                        resp = generate_response(cmd, trap_info)
                    else:
                        resp = ""
                    out = "\r\n"
                    if resp:
                        out += resp.replace("\n", "\r\n") + "\r\n"
                    out += "root@ubuntu:~# "
                    chan.send(out)
                    buf = ""
                elif ch == "\x7f" and buf:
                    buf = buf[:-1]
                    chan.send("\x08 \x08")
                else:
                    buf += ch
                    chan.send(ch)
        except Exception:
            break


class HoneypotServer(paramiko.ServerInterface):
    def __init__(self, ip, session_id):
        self.ip = ip
        self.session_id = session_id
        self.shell_event = threading.Event()

    def check_auth_password(self, username, password):
        with attempt_lock:
            attempt_counts[self.ip] = attempt_counts.get(self.ip, 0) + 1
            count = attempt_counts[self.ip]

        log_event({
            "type":       "ssh_auth_attempt",
            "ip":         self.ip,
            "session_id": self.session_id,
            "username":   username,
            "password":   password,
            "attempt_number_for_ip": count,
            "timestamp":  datetime.utcnow().isoformat() + "Z",
        })

        if count >= BRUTE_FORCE_THRESHOLD:
            log_event({
                "type":           "ssh_brute_force_confirmed",
                "ip":             self.ip,
                "session_id":     self.session_id,
                "total_attempts": count,
                "timestamp":      datetime.utcnow().isoformat() + "Z",
            })
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        self.shell_event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def get_allowed_auths(self, username):
        return "password"


def handle_connection(client_sock, client_addr):
    ip = client_addr[0]
    session_id = str(uuid.uuid4())
    log_event({
        "type":       "ssh_connect",
        "ip":         ip,
        "session_id": session_id,
        "timestamp":  datetime.utcnow().isoformat() + "Z",
    })
    transport = None
    try:
        transport = paramiko.Transport(client_sock)
        transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
        transport.add_server_key(HOST_KEY)
        server = HoneypotServer(ip, session_id)
        transport.start_server(server=server)

        chan = transport.accept(timeout=20)
        if chan is None:
            return
        server.shell_event.wait(timeout=10)

        chan.send("Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n")
        chan.send("Last login: Mon Jan 13 09:42:11 2025 from 10.0.0.24\r\n")
        chan.send("root@ubuntu:~# ")
        fake_shell(chan, ip, session_id)
    except Exception:
        pass
    finally:
        try:
            if transport:
                transport.close()
        except Exception:
            pass


def start(port=22):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(128)
    print(f"SSH honeypot listening on port {port}")
    while True:
        client_sock, client_addr = sock.accept()
        threading.Thread(
            target=handle_connection,
            args=(client_sock, client_addr),
            daemon=True,
        ).start()


if __name__ == "__main__":
    start(port=int(os.environ.get("HONEYPOT_SSH_PORT", "22")))