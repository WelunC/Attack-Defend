import os
import hashlib
import json
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

@app.route("/upload", methods=["POST"])
def upload():
    client_ip = request.remote_addr
    ua = request.headers.get("User-Agent")
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
    client_ip = request.remote_addr
    ua = request.headers.get("User-Agent")
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
    client_ip = request.remote_addr
    ua = request.headers.get("User-Agent")
    username = request.form.get("username", "")
    password = request.form.get("password", "")
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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
