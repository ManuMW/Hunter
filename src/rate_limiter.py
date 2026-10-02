import logging
from datetime import datetime, timezone
from typing import Tuple, Optional

import httpx

import src.config as config
from src.config import CLIENT_DAILY_QUOTA, TURNSTILE_SECRET_KEY
from src.db import HunterDatabase, db
from pathlib import Path

logger = logging.getLogger(__name__)

DATABASE_PATH = db.db_path


def init_db():
    """Initializes the database schema."""
    global db
    if Path(DATABASE_PATH) != db.db_path:
        db = HunterDatabase(Path(DATABASE_PATH))
    else:
        db.init_db()


def _get_active_db() -> HunterDatabase:
    global db
    if Path(DATABASE_PATH) != db.db_path:
        db = HunterDatabase(Path(DATABASE_PATH))
    return db


def get_today_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def build_client_identifier(ip: str, browser_uuid: Optional[str] = None) -> str:
    """Builds a composite client identifier combining IP and browser UUID if present."""
    clean_ip = ip.strip()
    if browser_uuid and browser_uuid.strip():
        return f"{clean_ip}:{browser_uuid.strip()}"
    return clean_ip


def check_client_quota(client_id: str) -> Tuple[bool, int, int]:
    """
    Checks if a client has remaining quota for today (UTC).
    Returns (is_allowed, current_count, remaining_quota).
    """
    today = get_today_utc()
    daily_limit = globals().get("CLIENT_DAILY_QUOTA", CLIENT_DAILY_QUOTA)
    return _get_active_db().check_client_quota(client_id, today, daily_limit=daily_limit)


def consume_client_quota(client_id: str) -> int:
    """
    Increments the client's detonation count for today.
    Returns the new used count.
    """
    today = get_today_utc()
    return _get_active_db().consume_client_quota(client_id, today)


def verify_turnstile_token(token: Optional[str], client_ip: str) -> bool:
    """
    Verifies Cloudflare Turnstile CAPTCHA token if TURNSTILE_SECRET_KEY is configured.
    If secret key is empty, verification is bypassed (for local testing/development).
    """
    if not TURNSTILE_SECRET_KEY:
        return True

    if not token:
        logger.warning(f"Turnstile token missing from client {client_ip}")
        return False

    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.post(
                "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                data={
                    "secret": TURNSTILE_SECRET_KEY,
                    "response": token,
                    "remoteip": client_ip
                }
            )
            data = resp.json()
            return bool(data.get("success"))
    except Exception as e:
        logger.error(f"Failed to verify Turnstile token: {e}")
        return False
