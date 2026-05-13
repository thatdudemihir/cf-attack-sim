#!/bin/bash
# setup.sh — One-command setup for Ubuntu (DigitalOcean/AWS)
# Run as root or with sudo: bash setup.sh

set -e

echo ""
echo "======================================"
echo "  WAF Simulator — Server Setup"
echo "======================================"
echo ""

# ── 1. System packages ────────────────────────────────────────────────────────
echo "[1/6] Installing system packages..."
apt-get update -qq
apt-get install -y python3 python3-pip python3-venv nginx certbot python3-certbot-nginx -qq

# ── 2. App directory ──────────────────────────────────────────────────────────
echo "[2/6] Setting up app directory..."
APP_DIR="/opt/waf-simulator"

if [ ! -d "$APP_DIR" ]; then
  mkdir -p "$APP_DIR"
fi

# Copy files if running from repo root
cp -r . "$APP_DIR/"
cd "$APP_DIR"

# ── 3. Python virtual environment ─────────────────────────────────────────────
echo "[3/6] Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate
pip install --quiet -r requirements.txt
deactivate

# ── 4. .env file ──────────────────────────────────────────────────────────────
echo "[4/6] Setting up environment..."
if [ ! -f "$APP_DIR/.env" ]; then
  cp "$APP_DIR/.env.example" "$APP_DIR/.env"

  # Generate a random secret key automatically
  SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
  sed -i "s/change-this-to-a-random-string/$SECRET/" "$APP_DIR/.env"

  echo ""
  echo "  ⚠️  IMPORTANT: Edit /opt/waf-simulator/.env to set your password!"
  echo "  Run: nano /opt/waf-simulator/.env"
  echo ""
fi

# ── 5. Systemd service ────────────────────────────────────────────────────────
echo "[5/6] Creating systemd service..."
cat > /etc/systemd/system/waf-simulator.service << EOF
[Unit]
Description=WAF Attack Simulator
After=network.target

[Service]
User=www-data
WorkingDirectory=/opt/waf-simulator
Environment="PATH=/opt/waf-simulator/venv/bin"
ExecStart=/opt/waf-simulator/venv/bin/python app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

chown -R www-data:www-data "$APP_DIR"
systemctl daemon-reload
systemctl enable waf-simulator
systemctl start waf-simulator

# ── 6. Nginx reverse proxy ────────────────────────────────────────────────────
echo "[6/6] Configuring Nginx..."
cat > /etc/nginx/sites-available/waf-simulator << 'EOF'
server {
    listen 80;
    server_name _;   # Replace _ with your domain if you have one

    # Important for SSE streaming — disable buffering
    proxy_buffering off;
    proxy_cache off;

    location / {
        proxy_pass         http://127.0.0.1:5000;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;

        # SSE-specific headers
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
        chunked_transfer_encoding on;
    }
}
EOF

ln -sf /etc/nginx/sites-available/waf-simulator /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl restart nginx

echo ""
echo "======================================"
echo "  ✅ Setup complete!"
echo "======================================"
echo ""
echo "  App running at: http://$(curl -s ifconfig.me)"
echo ""
echo "  Next steps:"
echo "  1. Edit .env:   nano /opt/waf-simulator/.env"
echo "  2. Restart app: systemctl restart waf-simulator"
echo "  3. View logs:   journalctl -u waf-simulator -f"
echo ""
