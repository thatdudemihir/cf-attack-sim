# 🎯 Cloudflare WAF Attack Simulator

A web-based tool that fires realistic attack payloads at a target URL to generate meaningful security events in **Cloudflare WAF** and **SentinelOne** — purpose-built for demonstrating the Cloudflare + SentinelOne AI-SIEM integration.

> ⚠️ **AUTHORIZED USE ONLY.** Only target systems you own or have explicit written permission to test.

---

## What It Does

Fires 5 realistic attack scenarios at your target URL so Cloudflare WAF generates real, meaningful security events that SentinelOne can ingest.

| Scenario | Attack Type | What Cloudflare Sees |
|----------|-------------|----------------------|
| 🔍 Reconnaissance | Path traversal, scanner agents | Bot Management alerts, 403s |
| 💉 SQL Injection | UNION attacks, blind SQLi, XSS | OWASP Core Ruleset blocks |
| 🔐 Credential Stuffing | Rapid POST login attempts | Rate limiting + Bot score |
| 💥 Zero-Day CVEs | Log4Shell, Spring4Shell, Shellshock | CVE signature rule blocks |
| 🎯 Full Campaign | All 4 scenarios in sequence | Complete attack story |

---

## Demo Story (Use This Script)

**Step 1 — Night before the demo:**
Run `Full Campaign` on `HIGH` volume. This generates 400+ real WAF events.

**Step 2 — Show Cloudflare:**
`Security → Events` → show the attack spike, highlight Log4Shell blocks and Bot Management scores.

**Step 3 — Pivot to SentinelOne:**
Show the same events ingested into AI-SIEM. SentinelOne correlates 400 events into **1 incident**.

**Step 4 — Hyperautomation story:**
Show the automated workflow: detect → enrich → block. SentinelOne pushes a block rule back to Cloudflare automatically.

> 💬 **Talking point:** *"A human analyst would take 45 minutes to correlate this. SentinelOne's AI did it in 4 seconds and automatically pushed the block to Cloudflare's edge — before the attacker could pivot."*

---

## Quick Start

### Option A — Local (for testing)

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/cf-attack-sim.git
cd cf-attack-sim

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set up environment
cp .env.example .env
nano .env   # Set your password and target URL

# 5. Run
python app.py
# Open http://localhost:5000
```

### Option B — DigitalOcean / AWS (recommended)

```bash
# 1. SSH into your server
ssh root@YOUR_SERVER_IP

# 2. Clone the repo
git clone https://github.com/YOUR_USERNAME/cf-attack-sim.git
cd cf-attack-sim

# 3. Run the setup script (installs everything + configures Nginx)
bash setup.sh

# 4. Edit your credentials
nano /opt/waf-simulator/.env

# 5. Restart
systemctl restart waf-simulator

# 6. Open http://YOUR_SERVER_IP
```

---

## Pushing to GitHub (First Time)

```bash
# On your local machine
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/cf-attack-sim.git
git push -u origin main
```

---

## Configuration

Edit `.env` to change settings:

```env
SECRET_KEY=your-random-string      # Run: python3 -c "import secrets; print(secrets.token_hex(32))"
APP_USERNAME=admin                  # Login username
APP_PASSWORD=your-strong-password   # Login password
TARGET_URL=https://mihirkansagra.com  # Target URL
```

---

## Adding New Attack Payloads

Open `attacks/payloads.py` and add entries to any list. No other files need to change.

```python
PAYLOADS = {
    "sqli": [
        "' OR '1'='1",   # existing
        "YOUR NEW PAYLOAD HERE",  # just add a line
    ],
    ...
}
```

---

## Managing the Server

```bash
# View live logs
journalctl -u waf-simulator -f

# Restart after code changes
systemctl restart waf-simulator

# Stop
systemctl stop waf-simulator
```

---

## Project Structure

```
cf-attack-sim/
├── app.py                  # Flask web app (routes, SSE streaming)
├── requirements.txt        # Python dependencies
├── .env.example            # Config template
├── .gitignore
├── setup.sh                # One-command DigitalOcean setup
├── README.md
├── attacks/
│   ├── payloads.py         # All attack payloads — edit this to add more
│   └── scenarios.py        # Scenario logic — controls how attacks fire
└── templates/
    ├── login.html           # Login page
    └── index.html           # Main attack launcher UI
```
