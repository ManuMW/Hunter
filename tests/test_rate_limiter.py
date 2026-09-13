import sqlite3
from src.rate_limiter import check_client_quota, consume_client_quota, build_client_identifier


def test_build_client_identifier():
    assert build_client_identifier("1.2.3.4") == "1.2.3.4"
    assert build_client_identifier("1.2.3.4", "uuid-123") == "1.2.3.4:uuid-123"
    assert build_client_identifier(" 1.2.3.4 ", "  ") == "1.2.3.4"


def test_quota_tracking(tmp_path, monkeypatch):
    test_db = tmp_path / "test_quotas.db"
    monkeypatch.setattr("src.rate_limiter.DATABASE_PATH", test_db)
    monkeypatch.setattr("src.rate_limiter.CLIENT_DAILY_QUOTA", 3)

    from src.rate_limiter import init_db
    init_db()

    client_id = "test_user_ip"

    # Initially allowed with 3 remaining
    allowed, used, remaining = check_client_quota(client_id)
    assert allowed is True
    assert used == 0
    assert remaining == 3

    # Consume 1
    new_used = consume_client_quota(client_id)
    assert new_used == 1

    # Consume 2 more
    consume_client_quota(client_id)
    new_used = consume_client_quota(client_id)
    assert new_used == 3

    # Now quota should be exhausted
    allowed, used, remaining = check_client_quota(client_id)
    assert allowed is False
    assert used == 3
    assert remaining == 0
