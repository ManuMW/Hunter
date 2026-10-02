import json
import sqlite3
import pytest
from pathlib import Path

from scripts.manage_reports import (
    load_catalog,
    save_catalog,
    prune_catalog,
    delete_report,
    rebuild_catalog,
    list_reports
)


@pytest.fixture
def test_env(tmp_path):
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    catalog_path = data_dir / "reports.js"
    db_path = data_dir / "hunter.db"

    # Setup a test sqlite database
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("""
            CREATE TABLE detonation_tasks (
                task_id TEXT PRIMARY KEY,
                sha256 TEXT NOT NULL,
                status TEXT NOT NULL
            )
        """)
        conn.execute("INSERT INTO detonation_tasks VALUES ('t1', 'aaaabbbbcccc1111', 'completed')")
        conn.execute("INSERT INTO detonation_tasks VALUES ('t2', 'ddddeeeeffff2222', 'completed')")
        conn.commit()

    # Create one markdown report on disk
    (reports_dir / "aaaabbbbcccc1111.md").write_text("# Threat Report AAA\n", encoding="utf-8")

    # Initial catalog has two reports (one present on disk, one missing)
    initial_reports = [
        {
            "id": "aaaabbbbcccc1111",
            "sha256": "aaaabbbbcccc1111",
            "title": "Threat Report AAA",
            "family": "Mirai",
            "category": "BOTNET",
            "severity": "HIGH",
            "date": "2026-10-02"
        },
        {
            "id": "ddddeeeeffff2222",
            "sha256": "ddddeeeeffff2222",
            "title": "Threat Report DDD",
            "family": "Gafgyt",
            "category": "BOTNET",
            "severity": "CRITICAL",
            "date": "2026-10-02"
        }
    ]
    save_catalog(initial_reports, catalog_path)

    return {
        "reports_dir": reports_dir,
        "catalog_path": catalog_path,
        "db_path": db_path
    }


def test_load_and_save_catalog(test_env):
    catalog_path = test_env["catalog_path"]
    reports = load_catalog(catalog_path)
    assert len(reports) == 2
    assert reports[0]["sha256"] == "aaaabbbbcccc1111"
    assert reports[1]["sha256"] == "ddddeeeeffff2222"

    # Add a new report and save
    reports.append({"id": "ffff0000", "sha256": "ffff0000", "title": "New Sample"})
    save_catalog(reports, catalog_path)

    reloaded = load_catalog(catalog_path)
    assert len(reloaded) == 3
    assert reloaded[2]["sha256"] == "ffff0000"


def test_list_reports(test_env):
    reports_dir = test_env["reports_dir"]
    catalog_path = test_env["catalog_path"]

    status_list = list_reports(reports_dir=reports_dir, catalog_path=catalog_path)
    assert len(status_list) == 2
    assert status_list[0]["sha256"] == "aaaabbbbcccc1111"
    assert status_list[0]["markdown_present"] is True

    assert status_list[1]["sha256"] == "ddddeeeeffff2222"
    assert status_list[1]["markdown_present"] is False


def test_prune_catalog(test_env):
    reports_dir = test_env["reports_dir"]
    catalog_path = test_env["catalog_path"]
    db_path = test_env["db_path"]

    pruned = prune_catalog(reports_dir=reports_dir, catalog_path=catalog_path, db_path=db_path)
    assert pruned == ["ddddeeeeffff2222"]

    # Catalog should only contain the present report
    remaining = load_catalog(catalog_path)
    assert len(remaining) == 1
    assert remaining[0]["sha256"] == "aaaabbbbcccc1111"

    # SQLite task record for ddddeeeeffff2222 should be deleted
    with sqlite3.connect(str(db_path)) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT sha256 FROM detonation_tasks")
        rows = [r[0] for r in cursor.fetchall()]
        assert "ddddeeeeffff2222" not in rows
        assert "aaaabbbbcccc1111" in rows


def test_delete_report(test_env):
    reports_dir = test_env["reports_dir"]
    catalog_path = test_env["catalog_path"]
    db_path = test_env["db_path"]

    assert (reports_dir / "aaaabbbbcccc1111.md").exists()

    success = delete_report(
        sha256="aaaabbbbcccc1111",
        reports_dir=reports_dir,
        catalog_path=catalog_path,
        db_path=db_path
    )
    assert success is True

    # File must be deleted
    assert not (reports_dir / "aaaabbbbcccc1111.md").exists()

    # Catalog must not have it
    remaining = load_catalog(catalog_path)
    assert not any(r["sha256"] == "aaaabbbbcccc1111" for r in remaining)

    # Database must not have it
    with sqlite3.connect(str(db_path)) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT sha256 FROM detonation_tasks WHERE sha256 = 'aaaabbbbcccc1111'")
        assert cursor.fetchone() is None


def test_rebuild_catalog(test_env):
    reports_dir = test_env["reports_dir"]
    catalog_path = test_env["catalog_path"]

    # Add a second markdown file with frontmatter
    md2 = reports_dir / "1111222233334444.md"
    md2.write_text("---\ntitle: \"Linux Trojan XYZ\"\nmalware_family: \"TrojanX\"\ndate: \"2026-10-02\"\n---\n", encoding="utf-8")

    count = rebuild_catalog(reports_dir=reports_dir, catalog_path=catalog_path)
    assert count == 2

    catalog = load_catalog(catalog_path)
    hashes = [r["sha256"] for r in catalog]
    assert "aaaabbbbcccc1111" in hashes
    assert "1111222233334444" in hashes


def test_append_to_empty_catalog(tmp_path, monkeypatch):
    from src.queue import append_to_catalog
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    reports_js = data_dir / "reports.js"
    reports_js.write_text("const THREAT_REPORTS = [];\n", encoding="utf-8")

    # Monkeypatch target file in append_to_catalog
    monkeypatch.chdir(tmp_path)

    sample = {
        "id": "9999888877776666",
        "sha256": "9999888877776666",
        "title": "Dynamic Sample",
        "family": "Mirai"
    }
    append_to_catalog(sample)

    updated = load_catalog(reports_js)
    assert len(updated) == 1
    assert updated[0]["sha256"] == "9999888877776666"
