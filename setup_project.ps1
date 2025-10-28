<#
setup_project.ps1
Creates a dockerized minimal doc-host project skeleton at:
C:\Users\Conor\Desktop\projectattackdefend

Usage:
  - Create files only:
      powershell -ExecutionPolicy Bypass -File "C:\path\to\setup_project.ps1"
  - Create files + run docker compose (must have Docker running):
      powershell -ExecutionPolicy Bypass -File "C:\path\to\setup_project.ps1" -RunDocker
#>

param(
    [switch]$RunDocker
)

$projectPath = "C:\Users\Conor\Desktop\projectattackdefend"

Write-Host "Project path: $projectPath"

# Create folder structure
$dirs = @(
    $projectPath,
    (Join-Path $projectPath "app"),
    (Join-Path $projectPath "data"),
    (Join-Path $projectPath "data\logs"),
    (Join-Path $projectPath "data\uploads")
)
foreach ($d in $dirs) {
    if (-not (Test-Path -Path $d)) {
        New-Item -ItemType Directory -Path $d | Out-Null
        Write-Host "Created: $d"
    } else {
        Write-Host "Exists:  $d"
    }
}

# app/app.py
$appPy = @'
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
'@

$appPyPath = Join-Path $projectPath "app\app.py"
Write-Output $appPy | Out-File -FilePath $appPyPath -Encoding UTF8 -Force
Write-Host "Wrote: $appPyPath"

# app/requirements.txt
$reqs = "flask==2.3.2`nwerkzeug==3.0.0"
$appReqPath = Join-Path $projectPath "app\requirements.txt"
$reqs | Out-File -FilePath $appReqPath -Encoding UTF8 -Force
Write-Host "Wrote: $appReqPath"

# Dockerfile
$dockerfile = @'
FROM python:3.11-slim
WORKDIR /app
COPY app/requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt
COPY app /app
RUN mkdir -p /data/uploads /data/logs
EXPOSE 5000
CMD ["python", "app.py"]
'@
$dockerfilePath = Join-Path $projectPath "Dockerfile"
$dockerfile | Out-File -FilePath $dockerfilePath -Encoding UTF8 -Force
Write-Host "Wrote: $dockerfilePath"

# docker-compose.yml
$compose = @'
version: "3.8"
services:
  app:
    build: .
    container_name: dochost_app
    volumes:
      - ./data:/data
    ports:
      - "5000:5000"
    networks:
      - labnet

networks:
  labnet:
    driver: bridge
'@
$composePath = Join-Path $projectPath "docker-compose.yml"
$compose | Out-File -FilePath $composePath -Encoding UTF8 -Force
Write-Host "Wrote: $composePath"

# .gitignore
$gitignore = @"
data/*
!data/logs/.gitkeep
!data/uploads/.gitkeep
__pycache__/
*.pyc
"@
$gitignorePath = Join-Path $projectPath ".gitignore"
$gitignore | Out-File -FilePath $gitignorePath -Encoding UTF8 -Force
Write-Host "Wrote: $gitignorePath"

# README.md
$readme = @"
# Project: Document upload forensics lab

Minimal Flask doc-host app, dockerized, for use in an isolated test environment. Endpoints:
- POST /upload (file)
- POST /submit (form)
- POST /login (auth test)
"@
$readmePath = Join-Path $projectPath "README.md"
$readme | Out-File -FilePath $readmePath -Encoding UTF8 -Force
Write-Host "Wrote: $readmePath"

# .gitkeep files
New-Item -ItemType File -Path (Join-Path $projectPath "data\logs\.gitkeep") -Force | Out-Null
New-Item -ItemType File -Path (Join-Path $projectPath "data\uploads\.gitkeep") -Force | Out-Null
Write-Host "Created .gitkeep files in data\logs and data\uploads"

# Initialize git repo if git is available
$gitCmd = Get-Command git -ErrorAction SilentlyContinue
if ($gitCmd) {
    Push-Location $projectPath
    try {
        if (-not (Test-Path (Join-Path $projectPath ".git"))) {
            git init | Out-Null
            git add .
            git commit -m "Initial lab skeleton: Flask app, Dockerfile, compose" | Out-Null
            Write-Host "Initialized git repo and made initial commit."
        } else {
            Write-Host "Git repo already initialized."
        }
    } catch {
        Write-Warning "Git init/commit failed or produced output. This is non-fatal."
    } finally {
        Pop-Location
    }
} else {
    Write-Host "Git not found on PATH; skipping git init (this is optional)."
}

Write-Host ""
Write-Host "Project skeleton successfully created at: $projectPath"
Write-Host ""
Write-Host "Next steps (recommended):"
Write-Host "  1) Open a PowerShell terminal and run: cd `"$projectPath`""
Write-Host "  2) Build & run the app with Docker (if Docker Desktop is running):"
Write-Host "       docker compose up --build"
Write-Host "  3) From another terminal test endpoints:"
Write-Host "       curl -v -F `"file=@C:\path\to\somefile.txt`" http://localhost:5000/upload"
Write-Host "       curl -X POST -F `"title=hi`" -F `"desc=<script>alert(1)</script>`" http://localhost:5000/submit"
Write-Host "       curl -X POST -F `"username=testuser`" -F `"password=wrong`" http://localhost:5000/login"
Write-Host ""
Write-Host "Important safety note:"
Write-Host "  - This lab is intended for local, isolated testing only. Do NOT expose this container to the public internet."
Write-Host "  - Use an isolated Docker network or remove the ports mapping to avoid exposing the service if needed."
Write-Host ""

# Optionally run docker compose if requested and if docker is available
if ($RunDocker) {
    $dockerCmd = Get-Command docker -ErrorAction SilentlyContinue
    if (-not $dockerCmd) {
        Write-Warning "Docker CLI not found on PATH. Please ensure Docker Desktop is installed and running before using -RunDocker."
    } else {
        Write-Host "Attempting to run: docker compose up --build (Ctrl-C to stop)"
        Push-Location $projectPath
        try {
            & docker compose up --build
        } catch {
            Write-Warning "docker compose up failed or was interrupted. Please run `docker compose up --build` manually in $projectPath."
        } finally {
            Pop-Location
        }
    }
}
