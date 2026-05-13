"""
Cloudflare WAF Attack Simulator
--------------------------------
Fires realistic attack payloads at a target URL to generate
meaningful security events in Cloudflare WAF + SentinelOne.

AUTHORIZED USE ONLY - only target systems you own or have permission to test.
"""

import json
import os
import queue
import threading
import time

from dotenv import load_dotenv
from flask import (Flask, Response, jsonify, redirect, render_template,
                   request, session, url_for)

from attacks.scenarios import run_scenario

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "change-this-before-deploying")

# Simple credentials loaded from .env
APP_USERNAME = os.getenv("APP_USERNAME", "admin")
APP_PASSWORD = os.getenv("APP_PASSWORD", "changeme")
TARGET_URL   = os.getenv("TARGET_URL", "https://mihirkansagra.com")

# Global state — one attack at a time
log_queue     = queue.Queue()
attack_running = False


# ── Auth routes ─────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == APP_USERNAME and password == APP_PASSWORD:
            session["logged_in"] = True
            return redirect(url_for("index"))
        return render_template("login.html", error="Invalid credentials. Try again.")
    return render_template("login.html", error=None)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ── Main UI ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    return render_template("index.html", target=TARGET_URL)


# ── API: launch attack ───────────────────────────────────────────────────────

@app.route("/launch", methods=["POST"])
def launch():
    global attack_running, log_queue

    if not session.get("logged_in"):
        return jsonify({"error": "Unauthorized"}), 401

    if attack_running:
        return jsonify({"error": "An attack is already running. Please wait."}), 400

    data     = request.get_json(silent=True) or {}
    scenario = data.get("scenario", "recon")
    volume   = data.get("volume", "low")

    # Fresh queue for each run
    log_queue     = queue.Queue()
    attack_running = True

    def run():
        global attack_running
        try:
            run_scenario(scenario, volume, TARGET_URL, log_queue)
        finally:
            attack_running = False
            log_queue.put({"type": "done", "message": "✅ Campaign complete. Check Cloudflare + SentinelOne consoles."})

    thread = threading.Thread(target=run, daemon=True)
    thread.start()

    return jsonify({"status": "started", "scenario": scenario, "volume": volume})


# ── API: SSE log stream ──────────────────────────────────────────────────────

@app.route("/stream")
def stream():
    if not session.get("logged_in"):
        return jsonify({"error": "Unauthorized"}), 401

    def generate():
        while True:
            try:
                entry = log_queue.get(timeout=60)
                yield f"data: {json.dumps(entry)}\n\n"
                if entry.get("type") == "done":
                    break
            except queue.Empty:
                # Keep connection alive
                yield f"data: {json.dumps({'type': 'ping'})}\n\n"

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ── API: status check ────────────────────────────────────────────────────────

@app.route("/status")
def status():
    if not session.get("logged_in"):
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"running": attack_running})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
