import json
from pathlib import Path
from src.triage import parse_native_processes, parse_native_dropped_files, parse_native_crontabs, extract_triage_data


def test_parse_native_processes_filters_noise():
    raw_ps = (
        "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
        "root         1  0.0  0.0   1234   567 ?        Ss   12:00   0:00 /bin/bash /sandbox/entrypoint.sh\n"
        "root        10  0.0  0.0    999   111 ?        S    12:00   0:00 systemd\n"
        "root        42  1.5  0.2   5555  2222 ?        S    12:01   0:01 /sandbox/work/sample\n"
        "root        43  0.0  0.0   3333   888 ?        S    12:01   0:00 /tmp/.xmrig -o 1.2.3.4:4444\n"
    )
    procs = parse_native_processes(raw_ps)
    # entrypoint.sh and systemd should be filtered out
    assert len(procs) == 2
    cmds = [p["command"] for p in procs]
    assert "/sandbox/work/sample" in cmds
    assert "/tmp/.xmrig -o 1.2.3.4:4444" in cmds


def test_parse_native_dropped_files():
    raw_find = (
        "123  4 drwxr-xr-x 2 root root 4096 Sep 13 12:00 /tmp\n"
        "124  4 -rwxr-xr-x 1 root root 1024 Sep 13 12:01 /tmp/.payload\n"
        "125  4 -rw-r--r-- 1 root root  128 Sep 13 12:01 /var/tmp/config.ini\n"
    )
    files = parse_native_dropped_files(raw_find)
    assert len(files) == 2
    paths = [f["path"] for f in files]
    assert "/tmp/.payload" in paths
    assert "/var/tmp/config.ini" in paths


def test_parse_native_crontabs():
    raw_cron = (
        "total 4\n"
        "# system cron file\n"
        "* * * * * root /tmp/beacon.sh\n"
    )
    entries = parse_native_crontabs(raw_cron)
    assert len(entries) == 1
    assert entries[0] == "* * * * * root /tmp/beacon.sh"


def test_extract_triage_data_with_directory(tmp_path):
    native_dir = tmp_path / "native"
    native_dir.mkdir()
    (native_dir / "processes.txt").write_text(
        "USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND\n"
        "root 99 0.0 0.0 1 1 ? S 12:00 0:00 /tmp/malware\n",
        encoding="utf-8"
    )
    (native_dir / "crontabs.txt").write_text("* * * * * root /tmp/malware\n", encoding="utf-8")
    (tmp_path / "run_summary.json").write_text(json.dumps({"status": "completed"}), encoding="utf-8")

    data = extract_triage_data(str(tmp_path))
    assert len(data["spawned_processes"]) == 1
    assert data["spawned_processes"][0]["command"] == "/tmp/malware"
    assert len(data["persistence_hooks"]) == 1
    assert data["execution_summary"]["status"] == "completed"
