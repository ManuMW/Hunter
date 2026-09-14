#!/usr/bin/env bash
# ==============================================================================
# Hunter Security Labs - Cloud Detonation Host Provisioning Script (Option B)
# Target OS: Ubuntu 24.04 LTS / Debian 12 (GCP Compute Engine e2-standard / e2-micro)
# ==============================================================================
set -euo pipefail

echo "======================================================================"
echo " Starting Hunter Cloud Detonation Host Provisioning"
echo "======================================================================"

# 1. Update OS Packages
echo "[*] Updating base system packages..."
sudo apt-get update && sudo apt-get upgrade -y
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
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg
fi

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin

# 3. Enable and Start Docker Service
echo "[*] Enabling Docker daemon..."
sudo systemctl enable docker
sudo systemctl start docker

# 4. Provision Dedicated Non-Privileged User
echo "[*] Configuring dedicated hunter user..."
if ! id -u hunter >/dev/null 2>&1; then
    sudo useradd -m -s /bin/bash hunter
fi
sudo usermod -aG docker hunter

# 5. Setup Project Directory Structure
HUNTER_ROOT="/opt/hunter"
echo "[*] Setting up Hunter workspace at ${HUNTER_ROOT}..."
sudo mkdir -p "${HUNTER_ROOT}"
sudo cp -r . "${HUNTER_ROOT}/" || true
sudo chown -R hunter:hunter "${HUNTER_ROOT}"

# 6. Build the Air-Gapped Sandbox Container Image
echo "[*] Building air-gapped threat sandbox container (threat-sandbox:latest)..."
cd "${HUNTER_ROOT}/sandbox"
sudo docker build -t threat-sandbox:latest .

# 7. Setup Python Virtual Environment
echo "[*] Initializing Python virtual environment..."
cd "${HUNTER_ROOT}"
sudo -u hunter python3 -m venv "${HUNTER_ROOT}/.venv"
sudo -u hunter "${HUNTER_ROOT}/.venv/bin/pip" install --upgrade pip
sudo -u hunter "${HUNTER_ROOT}/.venv/bin/pip" install -r "${HUNTER_ROOT}/requirements.txt"

# 8. Configure Systemd Service
echo "[*] Installing hunter-detonation.service..."
sudo cp "${HUNTER_ROOT}/deploy/hunter-detonation.service" /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable hunter-detonation.service

echo "======================================================================"
echo "[+] Provisioning complete!"
echo "    - Next steps: Populate /opt/hunter/.env with API keys"
echo "    - Start service: sudo systemctl start hunter-detonation"
echo "    - View logs: journalctl -u hunter-detonation -f"
echo "======================================================================"
