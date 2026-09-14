from fastapi.testclient import TestClient
from src.api import app

client = TestClient(app)


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "docker_available" in data
    assert "queued_tasks" in data


def test_submit_hash_cache_hit(tmp_path, monkeypatch):
    """Verifies that an existing report is returned immediately as a cache hit without consuming quota."""
    monkeypatch.setattr("src.api.REPORTS_DIR", tmp_path)
    sha256 = "ae4cb49ce4fa6aeb8f38ca703bc661cde36fbcadc05e3862ba3d8f7737ce7dcc"
    fake_report = tmp_path / f"{sha256}.md"
    fake_report.write_text("# Test Report", encoding="utf-8")

    response = client.post(
        "/api/submissions",
        json={"sha256": sha256}
    )
    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "cached"
    assert data["sha256"] == sha256
    assert f"/api/reports/{sha256}" in data["report_url"]


def test_submit_hash_missing_mb_key_returns_503(tmp_path, monkeypatch):
    """Verifies that when MalwareBazaar key is missing, API returns 503 out-of-order notification."""
    monkeypatch.setattr("src.api.REPORTS_DIR", tmp_path)
    monkeypatch.setattr("src.malwarebazaar.MALWAREBAZAAR_AUTH_KEY", "")
    monkeypatch.setattr("src.malwarebazaar.MALWAREBAZAAR_API_KEY", "")
    sha256 = "1111111111111111111111111111111111111111111111111111111111111111"

    response = client.post(
        "/api/submissions",
        json={"sha256": sha256}
    )
    assert response.status_code == 503
    assert "out of order" in response.json()["detail"].lower()


def test_submit_hash_quota_exceeded(tmp_path, monkeypatch):
    """Verifies that exceeding the 5 detonations/day limit returns 429 Too Many Requests."""
    monkeypatch.setattr("src.api.REPORTS_DIR", tmp_path)
    monkeypatch.setattr("src.rate_limiter.CLIENT_DAILY_QUOTA", 0)  # Immediately exhausted
    sha256 = "2222222222222222222222222222222222222222222222222222222222222222"

    response = client.post(
        "/api/submissions",
        json={"sha256": sha256}
    )
    assert response.status_code == 429
    assert "quota exceeded" in response.json()["detail"].lower()


def test_list_reports():
    response = client.get("/api/reports")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_submit_hash_alias(tmp_path, monkeypatch):
    """Verifies that /api/submit-hash works identically to /api/submissions."""
    monkeypatch.setattr("src.api.REPORTS_DIR", tmp_path)
    sha256 = "ae4cb49ce4fa6aeb8f38ca703bc661cde36fbcadc05e3862ba3d8f7737ce7dcc"
    fake_report = tmp_path / f"{sha256}.md"
    fake_report.write_text("# Test Report", encoding="utf-8")

    response = client.post(
        "/api/submit-hash",
        json={"sha256": sha256}
    )
    assert response.status_code == 202
    assert response.json()["status"] == "cached"


def test_get_threat_report_json(tmp_path, monkeypatch):
    """Verifies that /api/reports/{sha256}?format=json returns structured report data."""
    monkeypatch.setattr("src.api.REPORTS_DIR", tmp_path)
    sha256 = "ae4cb49ce4fa6aeb8f38ca703bc661cde36fbcadc05e3862ba3d8f7737ce7dcc"
    fake_report = tmp_path / f"{sha256}.md"
    fake_report.write_text(
        '---\ntitle: Threat Analysis Report - test.elf\nmalware_family: "Mirai"\nclassification: "Botnet"\nseverity_score: 8\n---\n\n# Threat Analysis Report\n',
        encoding="utf-8"
    )

    response = client.get(f"/api/reports/{sha256}?format=json")
    assert response.status_code == 200
    data = response.json()
    assert data["sha256"] == sha256
    assert data["family"] == "Mirai"
    assert data["category"] == "BOTNET"
    assert data["severity"] == "CRITICAL"

