#!/usr/bin/env bash
# ==============================================================================
# Hunter Security Labs - VM Setup Script for velociraptor (User: manumw21)
# ==============================================================================
set -euo pipefail

echo "======================================================================"
echo " Starting Hunter Setup on velociraptor for user manumw21"
echo "======================================================================"

HUNTER_DIR="/home/manumw21/Hunter"

# 1. Update OS Packages
echo "[*] Updating base system packages..."
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    git \
    python3 \
    python3-venv \
    python3-pip \
    jq \
    unzip \
    file

# 2. Install Docker CE Engine
echo "[*] Installing Docker Engine..."
sudo install -m 0755 -d /etc/apt/keyrings
if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg
fi

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin

# 3. Enable and Start Docker Service & add manumw21 to docker group
echo "[*] Enabling Docker daemon..."
sudo systemctl enable --now docker
sudo usermod -aG docker manumw21

# 4. Build the Air-Gapped Sandbox Container Image
echo "[*] Building air-gapped threat sandbox container (threat-sandbox:latest)..."
cd "${HUNTER_DIR}/sandbox"
sudo docker build -t threat-sandbox:latest .

# 5. Setup Python Virtual Environment
echo "[*] Initializing Python virtual environment in ${HUNTER_DIR}..."
cd "${HUNTER_DIR}"
python3 -m venv "${HUNTER_DIR}/.venv"
"${HUNTER_DIR}/.venv/bin/pip" install --upgrade pip
"${HUNTER_DIR}/.venv/bin/pip" install -r "${HUNTER_DIR}/requirements.txt"

# 6. Configure Systemd Service for Hunter
echo "[*] Installing hunter-detonation.service..."
cat << 'EOF' | sudo tee /etc/systemd/system/hunter-detonation.service > /dev/null
[Unit]
Description=Hunter Threat Detonation API Server
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=manumw21
Group=manumw21
WorkingDirectory=/home/manumw21/Hunter
EnvironmentFile=/home/manumw21/Hunter/.env
ExecStart=/home/manumw21/Hunter/.venv/bin/uvicorn src.api:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now hunter-detonation.service

# 7. Install ngrok
echo "[*] Installing ngrok agent..."
if ! command -v ngrok &>/dev/null; then
    curl -sSL https://ngrok-agent.s3.amazonaws.com/ngrok.asc | sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null
    echo "deb https://ngrok-agent.s3.amazonaws.com buster main" | sudo tee /etc/apt/sources.list.d/ngrok.list
    sudo apt-get update
    sudo apt-get install -y ngrok
fi

echo "======================================================================"
echo "[+] Hunter setup complete on velociraptor!"
echo "    - Docker version: $(sudo docker --version)"
echo "    - Hunter service status: $(sudo systemctl is-active hunter-detonation)"
echo "    - ngrok version: $(ngrok --version)"
echo "======================================================================"
