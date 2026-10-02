import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from src.db import HunterDatabase


@pytest.fixture
def test_db(tmp_path):
    db_file = tmp_path / "test_hunter.db"
    return HunterDatabase(db_path=db_file)


def test_client_quota_lifecycle(test_db):
    client_id = "192.168.1.100"
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # 1. Initial check
    allowed, used, remaining = test_db.check_client_quota(client_id, today, daily_limit=5)
    assert allowed is True
    assert used == 0
    assert remaining == 5

    # 2. Consume 1
    new_used = test_db.consume_client_quota(client_id, today)
    assert new_used == 1

    allowed, used, remaining = test_db.check_client_quota(client_id, today, daily_limit=5)
    assert allowed is True
    assert used == 1
    assert remaining == 4

    # 3. Consume up to limit
    for _ in range(4):
        test_db.consume_client_quota(client_id, today)

    allowed, used, remaining = test_db.check_client_quota(client_id, today, daily_limit=5)
    assert allowed is False
    assert used == 5
    assert remaining == 0


def test_task_save_update_retrieve(test_db):
    task_id = "task-12345"
    sha256 = "d97bb4393a46028fd499df9edf4851f33f9a68ffee7fef3b4d06e871f2209522"

    task_data = {
        "task_id": task_id,
        "sha256": sha256,
        "filename": "sample.elf",
        "status": "queued",
        "sample_meta": {"filename": "sample.elf", "file_type": "ELF 32-bit"}
    }

    # 1. Save
    test_db.save_task(task_data)

    retrieved = test_db.get_task(task_id)
    assert retrieved is not None
    assert retrieved["task_id"] == task_id
    assert retrieved["sha256"] == sha256
    assert retrieved["status"] == "queued"
    assert retrieved["filename"] == "sample.elf"
    assert retrieved["sample_meta"]["file_type"] == "ELF 32-bit"

    # 2. Update status to detonating then completed
    test_db.update_task_status(task_id, status="detonating")
    assert test_db.get_task(task_id)["status"] == "detonating"

    test_db.update_task_status(
        task_id,
        status="completed",
        completed_at="2026-10-02T12:00:00Z",
        report_path="reports/d97bb.md",
        report_data={"title": "Threat Report Mirai", "family": "Mirai"}
    )

    completed = test_db.get_task(task_id)
    assert completed["status"] == "completed"
    assert completed["report_data"]["family"] == "Mirai"
    assert completed["report_path"] == "reports/d97bb.md"

    # 3. Retrieve by sha256
    by_sha = test_db.get_task_by_sha256(sha256)
    assert by_sha is not None
    assert by_sha["task_id"] == task_id


def test_recover_interrupted_tasks(test_db):
    # Save a running task
    test_db.save_task({
        "task_id": "crashed-task-1",
        "sha256": "4ba17752a7fa6fb2afb70124ea1e8651999487d1f4ece5196ab1c37beee75718",
        "status": "detonating"
    })
    test_db.save_task({
        "task_id": "crashed-task-2",
        "sha256": "e41ff2d7a604a3ee1c1d99502b390adf9cf7119f1b6b7902ea26b88c148cb451",
        "status": "analyzing"
    })
    test_db.save_task({
        "task_id": "good-task",
        "sha256": "ae4cb49ce4fa6aeb8f38ca703bc661cde36fbcadc05e3862ba3d8f7737ce7dcc",
        "status": "completed"
    })

    recovered = test_db.recover_interrupted_tasks()
    assert recovered == 2

    assert test_db.get_task("crashed-task-1")["status"] == "failed"
    assert "aborted" in test_db.get_task("crashed-task-1")["error"].lower()
    assert test_db.get_task("good-task")["status"] == "completed"


def test_prune_expired_records(test_db):
    old_date = (datetime.now(timezone.utc) - timedelta(days=10)).strftime("%Y-%m-%d")
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    with test_db._get_connection() as conn:
        conn.execute("INSERT INTO client_quotas VALUES ('old_client', ?, 5, ?)", (old_date, "2026-09-01T00:00:00Z"))
        conn.execute("INSERT INTO client_quotas VALUES ('today_client', ?, 2, ?)", (today, "2026-10-02T00:00:00Z"))
        conn.commit()

    pruned = test_db.prune_expired_records(retention_days=7)
    assert pruned >= 1

    allowed, used, _ = test_db.check_client_quota("old_client", old_date)
    assert used == 0  # old row was deleted
    allowed, used, _ = test_db.check_client_quota("today_client", today)
    assert used == 2  # today's row remains
