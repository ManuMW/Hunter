# Hunter Cloud Detonation Host Deployment Guide (Option B)

This document provides step-by-step instructions for provisioning the dedicated Linux **Detonation Host** in Google Cloud Platform (GCP) to execute untrusted Linux samples inside air-gapped Docker sandboxes with embedded Velociraptor forensic triage.

---

## 1. Create GCP Compute Engine Instance

Run via Google Cloud SDK (`gcloud`):

```bash
# Set GCP Project and Region
gcloud config set project <YOUR_GCP_PROJECT_ID>
gcloud config set compute/zone us-central1-a

# Create standard Linux VM (e2-small or e2-medium recommended for dynamic sandboxing)
gcloud compute instances create hunter-detonation-host \
    --machine-type=e2-medium \
    --image-family=ubuntu-2404-lts-amd64 \
    --image-project=ubuntu-os-cloud \
    --boot-disk-size=30GB \
    --tags=hunter-sandbox \
    --metadata=startup-script-url=gs://<YOUR_BUCKET>/provision_gcp_detonation_host.sh
```

---

## 2. Manual Provisioning on the VM

SSH into the instance:

```bash
gcloud compute ssh hunter-detonation-host
```

Clone the repository and run the provisioning script:

```bash
git clone https://github.com/ManuMW/Hunter.git /tmp/Hunter
cd /tmp/Hunter
chmod +x deploy/provision_gcp_detonation_host.sh
./deploy/provision_gcp_detonation_host.sh
```

---

## 3. Configure Secrets

Edit `/opt/hunter/.env`:

```bash
sudo nano /opt/hunter/.env
```

Ensure the following variables are set:
```env
GEMINI_API_KEY=<YOUR_GOOGLE_AI_STUDIO_KEY>
GEMINI_MODEL=gemini-2.0-flash
MALWAREBAZAAR_AUTH_KEY=<YOUR_ABUSE_CH_AUTH_KEY>
DETONATION_TIMEOUT=90
SANDBOX_IMAGE=threat-sandbox:latest
```

---

## 4. Start the Detonation Host Service

```bash
sudo systemctl start hunter-detonation
sudo systemctl status hunter-detonation
```

Verify service is listening:
```bash
curl http://127.0.0.1:8000/docs
```

---

## 5. Cloudflare Tunnel for Public Web Ingress

To expose the Detonation Host safely to the public GitHub Pages submission interface without opening VM firewall ports:

```bash
# Install cloudflared
curl -L --output cloudflared.deb https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
sudo dpkg -i cloudflared.deb

# Authenticate and route traffic to local port 8000
cloudflared tunnel login
cloudflared tunnel create hunter-ingress
cloudflared tunnel route dns hunter-ingress api.hunter-labs.domain
cloudflared tunnel run hunter-ingress
```
