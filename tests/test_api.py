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


def test_submit_empty_sample():
    response = client.post(
        "/api/samples",
        files={"file": ("empty.bin", b"", "application/octet-stream")}
    )
    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()


def test_submit_valid_sample(tmp_path, monkeypatch):
    monkeypatch.setattr("src.quarantine.QUARANTINE_DIR", tmp_path)
    content = b"#!/bin/bash\necho 'hello world'\n"

    response = client.post(
        "/api/samples",
        files={"file": ("test_script.sh", content, "text/x-shellscript")}
    )
    assert response.status_code == 202
    data = response.json()
    assert "task_id" in data
    assert "sha256" in data
    assert data["filename"] == "test_script.sh"
    assert data["file_type"] == "Shell Script"

    # Verify task status query
    task_id = data["task_id"]
    task_resp = client.get(f"/api/tasks/{task_id}")
    assert task_resp.status_code == 200
    task_data = task_resp.json()
    assert task_data["task_id"] == task_id


def test_list_reports():
    response = client.get("/api/reports")
    assert response.status_code == 200
    assert isinstance(response.json(), list)
