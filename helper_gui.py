#!/usr/bin/env python3
"""
helper_gui.py — Server control + attack launcher + security toggles

Save/replace this file and run:
  pip install requests
  python helper_gui.py

This GUI:
 - can start/stop the server (docker compose or python app)
 - send quick login attempts (1/10/100) with optional X-Use-Fake-IP header
 - toggle 3 security features remotely via the app admin API:
    * Account lockout
    * Per-IP blocking
    * Global rate limiting
   When a feature is disabled via the GUI, the script calls /admin/reset_state
   to clear any existing locks/blocks (as requested).
"""
import os
import sys
import threading
import subprocess
import time
import signal
from queue import Queue, Empty
from tkinter import Tk, Button, Label, Entry, Text, Scrollbar, Checkbutton, IntVar, StringVar, Frame, END, LEFT
import requests

# ---------- Configuration defaults ----------
DEFAULT_SERVER_URL = "http://localhost:5000"
DEFAULT_PROJECT_PATH = os.path.expanduser("C:\\Users\\Conor\\Desktop\\projectattackdefend")  # change if you like

# ---------- Globals for server subprocess handling ----------
server_proc = None
server_stdout_thread = None
server_stdout_queue = Queue()

# ---------- Utility logging ----------
def gui_log_insert(txt_widget, txt):
    txt_widget.configure(state="normal")
    txt_widget.insert(END, txt)
    txt_widget.see(END)
    txt_widget.configure(state="disabled")

def log(msg, txt_widget=None):
    timestamp = time.strftime("%H:%M:%S")
    text = f"[{timestamp}] {msg}\n"
    if txt_widget:
        gui_log_insert(txt_widget, text)
    else:
        print(text, end='')

# ---------- Server start/stop ----------
def start_server_docker(compose_path, log_widget):
    global server_proc, server_stdout_thread
    if server_proc:
        log(f"Server already running (PID: {server_proc.pid})", log_widget)
        return
    if not os.path.isdir(compose_path):
        log(f"ERROR: compose path does not exist: {compose_path}", log_widget)
        return
    cmd = ["docker", "compose", "up", "--build"]
    log(f"Starting docker compose in: {compose_path}", log_widget)
    try:
        if os.name == "nt":
            server_proc = subprocess.Popen(cmd, cwd=compose_path, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=False)
        else:
            server_proc = subprocess.Popen(cmd, cwd=compose_path, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, preexec_fn=os.setsid, shell=False)
    except FileNotFoundError as e:
        log(f"ERROR launching docker compose: {e}. Is docker on PATH?", log_widget)
        server_proc = None
        return

    def stream_stdout(proc, q):
        try:
            for line in iter(proc.stdout.readline, b''):
                if not line:
                    break
                q.put(line.decode(errors="replace"))
        except Exception as e:
            q.put(f"SERVER STDOUT THREAD ERROR: {e}\n")

    server_stdout_thread = threading.Thread(target=stream_stdout, args=(server_proc, server_stdout_queue), daemon=True)
    server_stdout_thread.start()
    log(f"Server process started (PID {server_proc.pid}). Give it a few seconds to boot.", log_widget)

def start_server_python(project_path, app_file, log_widget):
    global server_proc, server_stdout_thread
    if server_proc:
        log(f"Server already running (PID: {server_proc.pid})", log_widget)
        return
    app_path = os.path.join(project_path, app_file)
    if not os.path.isfile(app_path):
        log(f"ERROR: app file not found: {app_path}", log_widget)
        return
    cmd = [sys.executable, app_path]
    log(f"Starting Python server: {' '.join(cmd)}", log_widget)
    if os.name == "nt":
        server_proc = subprocess.Popen(cmd, cwd=project_path, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=False)
    else:
        server_proc = subprocess.Popen(cmd, cwd=project_path, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, preexec_fn=os.setsid, shell=False)

    def stream_stdout(proc, q):
        try:
            for line in iter(proc.stdout.readline, b''):
                if not line:
                    break
                q.put(line.decode(errors="replace"))
        except Exception as e:
            q.put(f"SERVER STDOUT THREAD ERROR: {e}\n")

    server_stdout_thread = threading.Thread(target=stream_stdout, args=(server_proc, server_stdout_queue), daemon=True)
    server_stdout_thread.start()
    log(f"Python server started (PID {server_proc.pid}).", log_widget)

def stop_server(log_widget):
    global server_proc
    if not server_proc:
        log("No server process to stop.", log_widget)
        return
    pid = server_proc.pid
    log(f"Stopping server (PID {pid})...", log_widget)
    try:
        if os.name == "nt":
            server_proc.terminate()
            server_proc.wait(timeout=5)
        else:
            os.killpg(os.getpgid(server_proc.pid), signal.SIGTERM)
            server_proc.wait(timeout=5)
    except Exception as e:
        log(f"Error stopping server: {e}", log_widget)
    finally:
        server_proc = None
    log("Server stopped.", log_widget)

# ---------- Attack sending ----------
def send_login_attempts(target_url, username, password, count=1, use_fake_ip=False, delay=0.05, result_queue=None):
    session = requests.Session()
    headers = {}
    if use_fake_ip:
        headers["X-Use-Fake-IP"] = "true"
    successes = 0
    for i in range(count):
        try:
            resp = session.post(target_url.rstrip("/") + "/login", data={"username": username, "password": password}, headers=headers, timeout=10)
            code = resp.status_code
            text = resp.text.strip()
            line = f"{time.strftime('%H:%M:%S')} -> {i+1}/{count}: {code} {text}"
            if result_queue:
                result_queue.put(line)
            else:
                print(line)
            if code == 200:
                successes += 1
        except Exception as e:
            line = f"{time.strftime('%H:%M:%S')} -> {i+1}/{count}: ERROR {e}"
            if result_queue:
                result_queue.put(line)
            else:
                print(line)
        time.sleep(delay)
    summary = f"Done: {count} attempts, successes={successes}"
    if result_queue:
        result_queue.put(summary)
    else:
        print(summary)

# ---------- Admin config helpers ----------
def post_admin_config(server_url, token, data, log_widget):
    url = server_url.rstrip("/") + "/admin/config"
    headers = {"X-Admin-Token": token, "Content-Type": "application/json"}
    try:
        r = requests.post(url, json=data, headers=headers, timeout=10)
        log(f"POST /admin/config -> {r.status_code} {r.text}", log_widget)
        return r
    except Exception as e:
        log(f"ERROR POST /admin/config: {e}", log_widget)
        return None

def reset_admin_state(server_url, token, log_widget):
    url = server_url.rstrip("/") + "/admin/reset_state"
    headers = {"X-Admin-Token": token}
    try:
        r = requests.post(url, headers=headers, timeout=10)
        log(f"POST /admin/reset_state -> {r.status_code} {r.text}", log_widget)
        return r
    except Exception as e:
        log(f"ERROR POST /admin/reset_state: {e}", log_widget)
        return None

# ---------- GUI ----------
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from queue import Queue as ThreadQueue

root = tk.Tk()
root.title("Lab Helper — Server & Login Attack Launcher")
root.geometry("900x640")

# Top: project path / server controls
top = Frame(root)
top.pack(fill="x", padx=6, pady=4)

Label(top, text="Project path:").pack(side=LEFT)
project_path_var = StringVar(value=DEFAULT_PROJECT_PATH)
Entry(top, textvariable=project_path_var, width=52).pack(side=LEFT, padx=4)

start_btn = Button(top, text="Start (docker compose)", width=20)
start_py_btn = Button(top, text="Start (python app.py)", width=20)
stop_btn = Button(top, text="Stop server", width=12)
start_btn.pack(side=LEFT, padx=4)
start_py_btn.pack(side=LEFT, padx=4)
stop_btn.pack(side=LEFT, padx=4)

# Mid: server URL, credentials, admin token
mid = Frame(root)
mid.pack(fill="x", padx=6, pady=4)

Label(mid, text="Server URL:").pack(side=LEFT)
server_url_var = StringVar(value=DEFAULT_SERVER_URL)
Entry(mid, textvariable=server_url_var, width=28).pack(side=LEFT, padx=4)

Label(mid, text="Username:").pack(side=LEFT)
username_var = StringVar(value="testuser")
Entry(mid, textvariable=username_var, width=12).pack(side=LEFT, padx=4)

Label(mid, text="Password:").pack(side=LEFT)
password_var = StringVar(value="wrong")
Entry(mid, textvariable=password_var, width=12, show="*").pack(side=LEFT, padx=4)

Label(mid, text="Admin token:").pack(side=LEFT)
admin_token_var = StringVar(value="admintoken")
Entry(mid, textvariable=admin_token_var, width=18).pack(side=LEFT, padx=4)

fakeip_var = IntVar(value=0)
Checkbutton(mid, text="Random IP (X-Use-Fake-IP)", variable=fakeip_var).pack(side=LEFT, padx=8)

# Security toggles area
sec_frame = Frame(root, relief="groove", bd=1)
sec_frame.pack(fill="x", padx=6, pady=6)

Label(sec_frame, text="Security feature toggles (remote via /admin/config):").pack(anchor="w", padx=6, pady=2)

account_lock_var = IntVar(value=1)
ip_block_var = IntVar(value=1)
global_rate_var = IntVar(value=1)

Checkbutton(sec_frame, text="Account lockout (threshold)", variable=account_lock_var).pack(anchor="w", padx=10)
Checkbutton(sec_frame, text="Per-IP blocking (threshold)", variable=ip_block_var).pack(anchor="w", padx=10)
Checkbutton(sec_frame, text="Global rate limit (threshold)", variable=global_rate_var).pack(anchor="w", padx=10)

# Apply button
apply_btn = Button(sec_frame, text="Apply security settings (enable/disable)", width=36)
apply_btn.pack(padx=6, pady=6)

# Buttons for 1/10/100
btn_frame = Frame(root)
btn_frame.pack(fill="x", padx=6, pady=4)
Button(btn_frame, text="Send 1", width=12, command=lambda: threaded_send(1)).pack(side=LEFT, padx=6)
Button(btn_frame, text="Send 10", width=12, command=lambda: threaded_send(10)).pack(side=LEFT, padx=6)
Button(btn_frame, text="Send 100", width=12, command=lambda: threaded_send(100)).pack(side=LEFT, padx=6)

# Log area
log_frame = Frame(root)
log_frame.pack(fill="both", expand=True, padx=6, pady=6)
gui_log = ScrolledText(log_frame, state="disabled", wrap="word")
gui_log.pack(fill="both", expand=True)
gui_log.configure(font=("Consolas", 10))

# status bar
status_bar = Label(root, text="Ready", anchor="w")
status_bar.pack(fill="x", padx=6, pady=2)

# Thread-safe queue for results
result_q = ThreadQueue()

def threaded_send(count):
    server = server_url_var.get().strip()
    username = username_var.get().strip()
    password = password_var.get().strip()
    use_fake = bool(fakeip_var.get())
    status_bar.config(text=f"Sending {count} attempts to {server} ...")
    t = threading.Thread(target=lambda: send_login_attempts(server, username, password, count=count, use_fake_ip=use_fake, delay=0.03, result_queue=result_q), daemon=True)
    t.start()

def process_result_queue():
    try:
        while True:
            line = result_q.get_nowait()
            gui_log_insert(gui_log, line + "\n")
    except Empty:
        pass
    # server stdout
    try:
        while True:
            s = server_stdout_queue.get_nowait()
            gui_log_insert(gui_log, "[SERVER] " + s)
    except Empty:
        pass
    root.after(200, process_result_queue)

# Apply security settings action
def apply_security_settings_action():
    server = server_url_var.get().strip()
    token = admin_token_var.get().strip()
    if not token:
        gui_log_insert(gui_log, "[WARN] Admin token empty — cannot update config\n")
        return
    # determine desired state
    acc_enabled = bool(account_lock_var.get())
    ip_enabled = bool(ip_block_var.get())
    glob_enabled = bool(global_rate_var.get())

    # default enabling thresholds (you can change these if you want)
    data = {}
    # when enabling set sane defaults; when disabling, set huge thresholds so feature effectively disabled
    if acc_enabled:
        data["account_lock_threshold"] = 5
        data["account_lock_window"] = 300
        data["account_lock_duration"] = 600
    else:
        data["account_lock_threshold"] = 999999
        # keep other values but it's not necessary

    if ip_enabled:
        data["ip_block_threshold"] = 50
        data["ip_block_window"] = 60
        data["ip_block_duration"] = 600
    else:
        data["ip_block_threshold"] = 999999

    if glob_enabled:
        data["global_rate_threshold"] = 1000
        data["global_rate_window"] = 60
        data["global_block_duration"] = 60
    else:
        data["global_rate_threshold"] = 999999

    # send config update
    gui_log_insert(gui_log, f"[ADMIN] Updating config: {data}\n")
    threading.Thread(target=lambda: apply_config_and_maybe_reset(server, token, data, acc_enabled, ip_enabled, glob_enabled), daemon=True).start()

def apply_config_and_maybe_reset(server, token, data, acc_enabled, ip_enabled, glob_enabled):
    # post config
    r = post_admin_config(server, token, data, gui_log)
    # If any feature was disabled, clear state so existing locks are removed
    if not (acc_enabled and ip_enabled and glob_enabled):
        gui_log_insert(gui_log, "[ADMIN] One or more features disabled — clearing locked state via /admin/reset_state\n")
        reset_admin_state(server, token, gui_log)

apply_btn.config(command=apply_security_settings_action)

# Hook up server control buttons
def on_start_docker():
    path = project_path_var.get().strip()
    threading.Thread(target=start_server_docker, args=(path, gui_log), daemon=True).start()

def on_start_python():
    path = project_path_var.get().strip()
    threading.Thread(target=start_server_python, args=(path, "app/app.py", gui_log), daemon=True).start()

def on_stop_server():
    threading.Thread(target=stop_server, args=(gui_log,), daemon=True).start()

start_btn.config(command=on_start_docker)
start_py_btn.config(command=on_start_python)
stop_btn.config(command=on_stop_server)

# Startup tasks
root.after(200, process_result_queue)

def on_close():
    try:
        stop_server(gui_log)
    except Exception:
        pass
    root.destroy()

root.protocol("WM_DELETE_WINDOW", on_close)

if __name__ == "__main__":
    gui_log_insert(gui_log, "[INFO] Helper GUI started.\n")
    root.mainloop()
