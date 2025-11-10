import os
import hashlib
import json
import random
import time
from datetime import datetime
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename

UPLOAD_DIR = "/data/uploads"
LOG_FILE = "/data/logs/app.json"
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

def log_event(data: dict):
    data.setdefault("timestamp", datetime.utcnow().isoformat() + "Z")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(data, ensure_ascii=False) + "\n")

def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

app = Flask(__name__)
VALID_USER = {"username": "testuser", "password": "Password123"}

# ---------- Defense configuration (change via admin endpoint) ----------
CONFIG = {
    # Account lockout: if >= threshold attempts in window seconds, lock for duration seconds
    "account_lock_threshold": 5,
    "account_lock_window": 300,
    "account_lock_duration": 600,

    # Per-IP blocking: if >= threshold attempts in window seconds, block IP for duration seconds
    "ip_block_threshold": 50,
    "ip_block_window": 60,
    "ip_block_duration": 600,

    # Global rate limiting: if >= threshold requests across all clients in window seconds, enable global block for duration
    "global_rate_threshold": 100,
    "global_rate_window": 60,
    "global_block_duration": 60,

    # Fake IP switching
    "fake_ip_enabled": False,
    "fake_ip_list": ["10.0.0.10", "10.0.0.11", "10.0.0.12"],

    # Admin token (change before demos if desired)
    "admin_token": "admintoken"
}

# ---------- In-memory state ----------
account_attempts = {}   # username -> [timestamps]
locked_accounts = {}    # username -> unlock_timestamp

ip_attempts = {}        # ip -> [timestamps]
blocked_ips = {}        # ip -> unblock_timestamp

global_attempts = []    # timestamps
global_block_until = 0  # epoch seconds until which global blocking is active

# ---------- Helper funcs ----------
def now():
    return time.time()

def prune_old(timestamps, window):
    cutoff = now() - window
    # keep only timestamps newer than cutoff
    return [t for t in timestamps if t >= cutoff]

def is_account_locked(username):
    unlock = locked_accounts.get(username, 0)
    return now() < unlock

def is_ip_blocked(ip):
    unblock = blocked_ips.get(ip, 0)
    return now() < unblock

def record_login_attempt(username, ip):
    ts = now()
    # account attempts
    lst = account_attempts.get(username, [])
    lst.append(ts)
    lst = prune_old(lst, CONFIG["account_lock_window"])
    account_attempts[username] = lst
    # ip attempts
    ilst = ip_attempts.get(ip, [])
    ilst.append(ts)
    ilst = prune_old(ilst, CONFIG["ip_block_window"])
    ip_attempts[ip] = ilst
    # global attempts
    global_attempts.append(ts)
    # prune global attempts
    cut = now() - CONFIG["global_rate_window"]
    while global_attempts and global_attempts[0] < cut:
        global_attempts.pop(0)

    # evaluate account lock condition
    if len(lst) >= CONFIG["account_lock_threshold"]:
        locked_accounts[username] = now() + CONFIG["account_lock_duration"]
        log_event({"event":"account_locked","username":username,"ip":ip,"threshold":CONFIG["account_lock_threshold"],"lock_until":locked_accounts[username]})
    # evaluate IP block condition
    if len(ilst) >= CONFIG["ip_block_threshold"]:
        blocked_ips[ip] = now() + CONFIG["ip_block_duration"]
        log_event({"event":"ip_blocked","ip":ip,"threshold":CONFIG["ip_block_threshold"],"block_until":blocked_ips[ip]})
    # evaluate global block
    if len(global_attempts) >= CONFIG["global_rate_threshold"]:
        global global_block_until
        global_block_until = now() + CONFIG["global_block_duration"]
        log_event({"event":"global_rate_block","count":len(global_attempts),"block_until":global_block_until})

def get_logged_ip():
    # real remote addr
    real_ip = request.remote_addr or "0.0.0.0"
    # fake ip override: headers-driven for testing (X-Use-Fake-IP: true)
    if CONFIG.get("fake_ip_enabled") and request.headers.get("X-Use-Fake-IP", "").lower() in ("1","true","yes"):
        fake = random.choice(CONFIG.get("fake_ip_list", [real_ip]))
        return fake
    return real_ip

def check_global_block():
    return now() < global_block_until

# ---------- Endpoints ----------
@app.route("/upload", methods=["POST"])
def upload():
    client_ip = get_logged_ip()
    ua = request.headers.get("User-Agent")
    if check_global_block():
        log_event({"event":"upload_blocked_global","ip":client_ip,"ua":ua})
        return jsonify({"error":"service rate-limited"}), 429

    file = request.files.get("file")
    if not file:
        log_event({"event": "upload_attempt", "result": "no_file", "ip": client_ip, "ua": ua})
        return jsonify({"error": "no file"}), 400
    filename = secure_filename(file.filename)
    saved_path = os.path.join(UPLOAD_DIR, filename)
    file.save(saved_path)
    sha = sha256_of_file(saved_path)
    log_event({
        "event": "file_upload",
        "ip": client_ip,
        "ua": ua,
        "filename": filename,
        "saved_path": saved_path,
        "sha256": sha,
        "content_length": request.content_length
    })
    return jsonify({"ok": True, "filename": filename, "sha256": sha})

@app.route("/submit", methods=["POST"])
def submit():
    client_ip = get_logged_ip()
    ua = request.headers.get("User-Agent")
    if check_global_block():
        log_event({"event":"submit_blocked_global","ip":client_ip,"ua":ua})
        return jsonify({"error":"service rate-limited"}), 429
    title = request.form.get("title", "")
    desc = request.form.get("desc", "")
    tags = request.form.get("tags", "")
    log_event({
        "event": "form_submit",
        "ip": client_ip,
        "ua": ua,
        "title": title,
        "desc": desc,
        "tags": tags,
        "content_length": request.content_length
    })
    return jsonify({"ok": True})

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    client_ip = get_logged_ip()
    ua = request.headers.get("User-Agent")

    # check global block
    if check_global_block():
        log_event({"event":"login_blocked_global","ip":client_ip,"ua":ua,"username":username})
        # simulate denial: always 429
        return jsonify({"ok": False, "reason":"service rate-limited"}), 429

    # check IP block
    if is_ip_blocked(client_ip):
        log_event({"event":"login_blocked_ip","ip":client_ip,"ua":ua,"username":username})
        return jsonify({"ok": False, "reason":"ip blocked"}), 429

    # check account lock
    if is_account_locked(username):
        log_event({"event":"login_blocked_account_locked","ip":client_ip,"ua":ua,"username":username})
        return jsonify({"ok": False, "reason":"account locked"}), 423

    # At this point we will record the attempt (for thresholds)
    record_login_attempt(username, client_ip)

    success = username == VALID_USER["username"] and password == VALID_USER["password"]
    log_event({
        "event": "login_attempt",
        "ip": client_ip,
        "ua": ua,
        "username": username,
        "success": success
    })

    if success:
        return jsonify({"ok": True})
    else:
        return jsonify({"ok": False}), 401

@app.route("/", methods=["GET"])
def index():
    return "Minimal doc-host app (for lab). Use /upload, /submit, /login."

# ---------- Admin endpoints to inspect and toggle config/state ----------
def admin_auth():
    token = request.headers.get("X-Admin-Token", "")
    return token == CONFIG.get("admin_token")

@app.route("/admin/config", methods=["GET","POST"])
def admin_config():
    if not admin_auth():
        return "unauthorized", 401
    if request.method == "GET":
        # return a shallow copy of config and current state
        state = {
            "config": CONFIG,
            "locked_accounts": {k: v for k,v in locked_accounts.items()},
            "blocked_ips": {k: v for k,v in blocked_ips.items()},
            "global_block_until": global_block_until
        }
        return jsonify(state)
    else:
        # set provided config fields (whitelist keys)
        allowed = {"account_lock_threshold","account_lock_window","account_lock_duration",
                   "ip_block_threshold","ip_block_window","ip_block_duration",
                   "global_rate_threshold","global_rate_window","global_block_duration",
                   "fake_ip_enabled","fake_ip_list","admin_token"}
        try:
            data = request.get_json() or {}
        except Exception:
            data = {}
        for k,v in data.items():
            if k in allowed:
                CONFIG[k] = v
        log_event({"event":"admin_config_update","changes":data,"by_ip":request.remote_addr})
        return jsonify({"ok": True, "new_config": CONFIG})

@app.route("/admin/reset_state", methods=["POST"])
def admin_reset_state():
    if not admin_auth():
        return "unauthorized", 401
    account_attempts.clear()
    locked_accounts.clear()
    ip_attempts.clear()
    blocked_ips.clear()
    global_attempts.clear()
    global global_block_until
    global_block_until = 0
    log_event({"event":"admin_reset_state","by_ip":request.remote_addr})
    return jsonify({"ok": True})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
