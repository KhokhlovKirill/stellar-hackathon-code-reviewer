#!/bin/bash
# SSH Reverse Tunnel: Mac:8099 → VPS:127.0.0.1:18099 → nginx:8099 → internet
# Webhook URL: http://87.242.94.247:8099/webhooks/github

VPS_HOST="87.242.94.247"
VPS_USER="superadmin"
SSH_KEY="$HOME/.ssh/vps_aegis_key"
TUNNEL_PORT=18099   # on VPS (internal, nginx proxies to this)
LOCAL_PORT=8099     # Docker web (nginx + React), proxies API

echo "[tunnel] Starting SSH reverse tunnel..."
echo "[tunnel] Webhook URL: http://${VPS_HOST}:8099/webhooks/github"
echo "[tunnel] Web UI:      http://${VPS_HOST}:8099"

# -N = no remote command, -T = no TTY, -R = reverse tunnel
# Auto-reconnect loop
while true; do
    ssh -i "$SSH_KEY" \
        -o StrictHostKeyChecking=no \
        -o ServerAliveInterval=30 \
        -o ServerAliveCountMax=3 \
        -o ExitOnForwardFailure=yes \
        -N -T \
        -R "127.0.0.1:${TUNNEL_PORT}:localhost:${LOCAL_PORT}" \
        "${VPS_USER}@${VPS_HOST}"
    
    echo "[tunnel] Disconnected, reconnecting in 5s..."
    sleep 5
done
