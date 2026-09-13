# Automated Threat Research Pipeline

An automated threat intelligence and dynamic malware detonation backend that ingests untrusted Linux binaries and scripts, executes them in ephemeral air-gapped Docker sandboxes, extracts DFIR triage telemetry using Velociraptor, synthesizes intelligence using Google AI Studio (Gemini), and generates defanged threat analysis reports.

---

## Architecture Overview

```
User / Analyst
      │
      ▼
FastAPI Detonation Host (GCP VM)
  ├── 1. Quarantine Store (quarantine/<sha256>.bin with chmod 0600)
  ├── 2. Sequential Detonation Worker (asyncio queue)
  ├── 3. Ephemeral Sandbox (Docker container, --network none, 90s timeout)
  │       └── Embedded Velociraptor CLI Triage
  ├── 4. Forensic Triage Parser (Filters system noise)
  ├── 5. Google AI Studio (Gemini 2.0 / 1.5 Flash structured analysis)
  └── 6. Defanged Markdown Report (reports/<sha256>.md)
```

For domain terminology and architectural decisions, see:
- [Domain Glossary (`CONTEXT.md`)](file:///D:/Unga/CONTEXT.md)
- [ADR 0001: Ephemeral Docker Sandboxes](file:///D:/Unga/docs/adr/0001-ephemeral-docker-sandboxes.md)
- [ADR 0002: Air-Gapped Sandbox Network](file:///D:/Unga/docs/adr/0002-air-gapped-sandbox-network.md)
- [ADR 0003: Standalone Velociraptor CLI Triage](file:///D:/Unga/docs/adr/0003-standalone-velociraptor-cli-triage.md)
- [ADR 0004: Compute Engine Host over Cloud Run](file:///D:/Unga/docs/adr/0004-compute-engine-host-over-cloud-run.md)

---

## Features

- **Safe Ingestion**: Calculates SHA-256, SHA-1, MD5, detects file types via magic bytes, and strips executable bits (`chmod 0600`).
- **GCP Abuse Immunity**: Detonates with Docker `--network none`. Zero network packets leave the container, completely preventing GCP billing account suspension.
- **Resource Guardrails**: Enforces `--memory=512m`, `--cpus=1.0`, and `--pids-limit=100` to prevent fork bombs and host starvation.
- **DFIR Telemetry via Velociraptor**: Captures spawned process trees, cron persistence, systemd hooks, and `/tmp` drops.
- **Google AI Studio Structured Output**: Synthesizes findings using Gemini with a strict JSON schema (MITRE ATT&CK mapping, severity score 1-10, IoCs, behavior analysis, and candidate YARA rule).
- **Automated Defanging**: Defangs all IoCs (`hxxp://`, `192[.]168[.]1[.]1`, `evil[.]com`) to avoid GitHub Pages abuse flags.
- **Interactive Swagger UI & CLI**: Easy testing via web browser or command line.

---

## Quickstart & Local Setup

### 1. Prerequisites
- Python 3.10+
- Docker (optional for local mock testing, required for real detonation)

### 2. Installation
```bash
# Clone or navigate to the repository
cd Unga

# Install Python dependencies
pip install -r requirements.txt
```

### 3. Configuration
Copy `.env.example` to `.env` and add your Google AI Studio API key:
```bash
cp .env.example .env
```
Edit `.env`:
```env
GEMINI_API_KEY=your_google_ai_studio_api_key_here
GEMINI_MODEL=gemini-2.0-flash
DETONATION_TIMEOUT=90
```

---

## Building the Sandbox Docker Image

To build the air-gapped detonation container with embedded Velociraptor:

```bash
cd sandbox
docker build -t threat-sandbox:latest .
cd ..
```

---

## Running the Backend

### Start the FastAPI Server
```bash
python -m src.cli serve --port 8000
```
Open your browser to **http://localhost:8000/docs** for the interactive Swagger UI.

### API Endpoints
- `POST /api/samples`: Upload an untrusted binary or script for detonation.
- `GET /api/tasks/{task_id}`: Check real-time progress (`queued` → `detonating` → `extracting_artifacts` → `analyzing` → `completed`).
- `GET /api/reports/{sha256}`: Fetch the completed Markdown report or JSON analysis.
- `GET /api/reports`: List all generated reports.
- `GET /health`: Health and Docker daemon check.

---

## Command-Line Usage (CLI)

### Detonate a Sample
```bash
# Live Detonation (requires Docker)
python -m src.cli submit /path/to/malware.elf

# Mock Detonation (for testing pipeline logic without Docker)
python -m src.cli submit sandbox/test_sample.sh --mock
```

### List Generated Reports
```bash
python -m src.cli list
```

### View a Specific Report
```bash
python -m src.cli show <SHA256_HASH>
```

---

## Running Tests

Run the full automated test suite:
```bash
python -m pytest -v
```

---

## Deploying on Google Cloud Platform (GCP)

1. Provision a free-tier **`e2-micro` Compute Engine VM** (Ubuntu 24.04 LTS).
2. Install Docker and Python on the VM:
   ```bash
   sudo apt-get update && sudo apt-get install -y docker.io python3-pip git
   sudo usermod -aG docker $USER
   ```
3. Clone this repository onto the VM and build the sandbox:
   ```bash
   git clone <your-repo-url>
   cd Unga
   pip install -r requirements.txt
   cd sandbox && docker build -t threat-sandbox:latest . && cd ..
   ```
4. Run the API as a systemd service or via tmux:
   ```bash
   python3 -m src.cli serve --host 0.0.0.0 --port 8000
   ```
5. *(When ready to connect the GitHub Pages website)* Run `cloudflared tunnel` or Caddy on the VM to get a free HTTPS endpoint for your frontend!
