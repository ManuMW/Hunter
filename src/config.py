import os
from pathlib import Path

# Base workspace directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Load .env manually to avoid unnecessary dependencies
env_file = BASE_DIR / ".env"
if env_file.exists():
    with open(env_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, val = line.split("=", 1)
                os.environ.setdefault(key.strip(), val.strip())

# Google AI Studio Configuration
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")

# Detonation Configuration
DETONATION_TIMEOUT = int(os.getenv("DETONATION_TIMEOUT", "90"))
SANDBOX_IMAGE = os.getenv("SANDBOX_IMAGE", "threat-sandbox:latest")

# Storage Directories
QUARANTINE_DIR = BASE_DIR / os.getenv("QUARANTINE_DIR", "quarantine")
REPORTS_DIR = BASE_DIR / os.getenv("REPORTS_DIR", "reports")
ARTIFACTS_DIR = BASE_DIR / os.getenv("ARTIFACTS_DIR", "artifacts")

# Ensure required directories exist
for directory in [QUARANTINE_DIR, REPORTS_DIR, ARTIFACTS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)
