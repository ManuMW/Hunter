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
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")

# Detonation Configuration
DETONATION_TIMEOUT = int(os.getenv("DETONATION_TIMEOUT", "90"))
SANDBOX_IMAGE = os.getenv("SANDBOX_IMAGE", "threat-sandbox:latest")

# MalwareBazaar (abuse.ch) Configuration
MALWAREBAZAAR_AUTH_KEY = os.getenv("MALWAREBAZAAR_AUTH_KEY") or os.getenv("MALWAREBAZAAR_API_KEY") or ""
MALWAREBAZAAR_API_KEY = MALWAREBAZAAR_AUTH_KEY  # Backwards-compatible alias
MALWAREBAZAAR_API_URL = "https://mb-api.abuse.ch/api/v1/"

# Rate Limiting and Bot Protection
CLIENT_DAILY_QUOTA = int(os.getenv("CLIENT_DAILY_QUOTA", "5"))
TURNSTILE_SECRET_KEY = os.getenv("TURNSTILE_SECRET_KEY", "")
DATABASE_PATH = BASE_DIR / "detonation_quotas.db"

# Storage Directories
QUARANTINE_DIR = BASE_DIR / os.getenv("QUARANTINE_DIR", "quarantine")
REPORTS_DIR = BASE_DIR / os.getenv("REPORTS_DIR", "reports")
ARTIFACTS_DIR = BASE_DIR / os.getenv("ARTIFACTS_DIR", "artifacts")

# Ensure required directories exist
for directory in [QUARANTINE_DIR, REPORTS_DIR, ARTIFACTS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)
