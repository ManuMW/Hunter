from src.report_generator import defang_ioc, generate_threat_report
from src.ai_synthesis import ThreatAnalysisSynthesis, MitreTechnique, ObservedBehavior, IndicatorOfCompromise


def test_defang_ioc():
    assert defang_ioc("http://evil.com/drop.sh") == "hxxp://evil[.]com/drop.sh"
    assert defang_ioc("https://c2.xyz/api") == "hxxps://c2[.]xyz/api"
    assert defang_ioc("192.168.1.50:4444") == "192[.]168[.]1[.]50:4444"
    assert defang_ioc("ftp://update.org") == "fxp://update[.]org"


def test_generate_threat_report(tmp_path, monkeypatch):
    monkeypatch.setattr("src.report_generator.REPORTS_DIR", tmp_path)

    sample_meta = {
        "filename": "suspicious_elf",
        "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "sha1": "abcdef1234567890abcdef1234567890abcdef12",
        "md5": "abcdef1234567890abcdef1234567890",
        "file_type": "Linux ELF Binary",
        "size_bytes": 4096
    }
    triage_data = {
        "spawned_processes": [{"pid": "100", "user": "root", "command": "/tmp/bot"}],
        "dropped_files": [{"permissions": "-rwxr-xr-x", "size": "1024", "path": "/tmp/bot"}],
        "persistence_hooks": ["* * * * * root /tmp/bot"]
    }
    synthesis = ThreatAnalysisSynthesis(
        malware_family="Mirai Variant",
        threat_severity_score=9,
        threat_classification="Botnet",
        executive_summary="Sample exhibits botnet behavior with persistence.",
        mitre_attack_techniques=[
            MitreTechnique(
                technique_id="T1053.003",
                technique_name="Scheduled Task/Job: Cron",
                tactic="Persistence",
                evidence="Installed cron job"
            )
        ],
        observed_behaviors=[
            ObservedBehavior(
                category="Persistence",
                description="Installed persistent cron job",
                evidence="/etc/cron.d/persistence"
            )
        ],
        indicators_of_compromise=[
            IndicatorOfCompromise(type="sha256", value=sample_meta["sha256"], description="Sample hash"),
            IndicatorOfCompromise(type="ip", value="198.51.100.23", description="C2 Server")
        ],
        yara_rule_candidate="rule TestBot { condition: true }",
        confidence_score=0.9
    )

    report_md = generate_threat_report(sample_meta, triage_data, synthesis)
    assert "# Threat Analysis Report: `suspicious_elf`" in report_md
    assert "Mirai Variant" in report_md
    assert "9/10" in report_md
    assert "198[.]51[.]100[.]23" in report_md  # Verifies defanging
    assert "T1053.003" in report_md
    assert "rule TestBot" in report_md

    saved_file = tmp_path / f"{sample_meta['sha256']}.md"
    assert saved_file.exists()
    assert saved_file.read_text(encoding="utf-8") == report_md
