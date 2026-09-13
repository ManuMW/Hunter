import hashlib
from pathlib import Path
from src.quarantine import quarantine_sample, detect_file_type


def test_detect_file_type():
    assert detect_file_type(b"\x7fELF\x02\x01\x01") == "Linux ELF Binary"
    assert detect_file_type(b"MZ\x90\x00") == "Windows PE Executable"
    assert detect_file_type(b"#!/usr/bin/env python3\nprint('hi')") == "Python Script"
    assert detect_file_type(b"#!/bin/bash\necho hi") == "Shell Script"
    assert detect_file_type(b"raw binary noise") == "Unknown Binary / Data"


def test_quarantine_sample(tmp_path, monkeypatch):
    monkeypatch.setattr("src.quarantine.QUARANTINE_DIR", tmp_path)
    content = b"#!/bin/bash\necho 'malicious action'\n"
    expected_hash = hashlib.sha256(content).hexdigest()

    meta = quarantine_sample(content, "drop.sh")
    assert meta["sha256"] == expected_hash
    assert meta["filename"] == "drop.sh"
    assert meta["size_bytes"] == len(content)
    assert meta["file_type"] == "Shell Script"

    stored_file = tmp_path / f"{expected_hash}.bin"
    assert stored_file.exists()
    assert stored_file.read_bytes() == content
