# AgentForge — Hostinger VPS Deployment

## 1. SSH into your VPS

```bash
ssh root@82.180.139.113
```

## 2. Install dependencies

```bash
apt update && apt install -y python3 python3-pip python3-venv git nginx
```

## 3. Clone the project

```bash
git clone https://github.com/D0NMEGA/agentforge.git /opt/agentforge
```

## 4. Set up Python environment

```bash
cd /opt/agentforge
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 5. Test it works

```bash
cd /opt/agentforge
source venv/bin/activate
uvicorn main:app --host 127.0.0.1 --port 8000
# In another terminal: curl http://127.0.0.1:8000/v1/health
# You should see {"status":"operational",...}
# Ctrl+C to stop
```

## 6. Create systemd service (auto-start on boot)

```bash
cat > /etc/systemd/system/agentforge.service << 'EOF'
[Unit]
Description=AgentForge API
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/agentforge
Environment=PATH=/opt/agentforge/venv/bin:/usr/bin
ExecStart=/opt/agentforge/venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000 --workers 2
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable agentforge
systemctl start agentforge
systemctl status agentforge
```

## 7. Set up Nginx reverse proxy (with WebSocket support)

```bash
cat > /etc/nginx/sites-available/agentforge << 'EOF'
server {
    listen 80;
    server_name _;

    # Landing page
    location / {
        root /opt/agentforge;
        try_files /landing.html =404;
    }

    # API endpoints
    location /v1/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 300s;

        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    # Swagger docs
    location /docs {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
    }
    location /openapi.json {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
    }
}
EOF

ln -sf /etc/nginx/sites-available/agentforge /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl restart nginx
```

## 8. Verify everything works

```bash
# Health check:
curl http://82.180.139.113/v1/health

# Register an agent:
curl -X POST http://82.180.139.113/v1/register \
  -H "Content-Type: application/json" \
  -d '{"name": "first-bot"}'

# Check the directory:
curl http://82.180.139.113/v1/directory
```

---

## Updating after code changes (use this every time)

```bash
cd /opt/agentforge
git pull origin main
source venv/bin/activate
pip install -r requirements.txt
systemctl restart agentforge
systemctl status agentforge
```

## Quick reference commands

```bash
# Check status
systemctl status agentforge

# View logs (live tail)
journalctl -u agentforge -f

# View last 50 log lines
journalctl -u agentforge -n 50

# Restart after code changes
systemctl restart agentforge

# Check nginx logs
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log
```

## Firewall (if needed)

```bash
ufw allow 80
ufw allow 443
ufw allow 22
ufw enable
```
