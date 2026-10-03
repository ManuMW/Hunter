import pytest
from pathlib import Path
from src.static_analyzer import (
    calculate_shannon_entropy,
    extract_plain_strings,
    find_indicators_in_text,
    brute_force_xor_strings,
    analyze_elf_structure,
    perform_full_static_analysis,
)


def test_calculate_shannon_entropy():
    # Constant data has 0 entropy
    assert calculate_shannon_entropy(b"AAAAAAA") == 0.0
    # Empty data has 0 entropy
    assert calculate_shannon_entropy(b"") == 0.0
    # High entropy for all 256 unique bytes
    all_bytes = bytes(range(256))
    assert calculate_shannon_entropy(all_bytes) == 8.0


def test_extract_plain_strings():
    data = b"\x00\x01\x02Hello World\x00\x03\x04Testing123\x00\x05"
    strings = extract_plain_strings(data, min_len=4)
    assert "Hello World" in strings
    assert "Testing123" in strings


def test_find_indicators_in_text():
    text = "Connecting to 198.51.100.25 on port 80 via http://malicious-c2.net/bot with /bin/busybox and telnet"
    indicators = find_indicators_in_text(text)
    assert "198.51.100.25" in indicators["ips"]
    assert "http://malicious-c2.net/bot" in indicators["urls"]
    assert "/bin/busybox" in indicators["paths"]
    assert "busybox" in indicators["keywords"]
    assert "telnet" in indicators["keywords"]


def test_brute_force_xor_strings():
    # Encode known botnet indicators with XOR key 0x22 (classic Mirai key)
    plain = (
        b"GET /bin/busybox HTTP/1.1\r\n"
        b"User-Agent: mirai\r\n"
        b"Host: 198.51.100.55\r\n"
        b"POST /login admin:admin\r\n"
        b"http://c2.botnet.example/feed"
    )
    xor_key = 0x22
    xored_data = bytes([b ^ xor_key for b in plain])

    findings = brute_force_xor_strings(xored_data)
    assert len(findings) > 0
    top_hit = findings[0]
    assert top_hit["key_hex"] == "0x22"
    assert top_hit["type"] == "single_byte_xor"
    assert "busybox" in top_hit["discovered_keywords"]
    assert "198.51.100.55" in top_hit["discovered_ips"]
    assert "http://c2.botnet.example/feed" in top_hit["discovered_urls"]


def test_analyze_elf_structure_on_sample():
    sample_path = Path("quarantine/4ba17752a7fa6fb2afb70124ea1e8651999487d1f4ece5196ab1c37beee75718.bin")
    if not sample_path.exists():
        pytest.skip("Sample binary not found in quarantine")

    raw_bytes = sample_path.read_bytes()
    res = analyze_elf_structure(raw_bytes)
    assert res["is_elf"] is True
    assert res["class"] == "32-bit"
    assert res["endianness"] == "Little Endian"
    assert "security_mitigations" in res
    mitigations = res["security_mitigations"]
    assert "nx" in mitigations
    assert "pie" in mitigations
    assert "relro" in mitigations
    assert "canary" in mitigations
    assert "stripped" in mitigations


def test_perform_full_static_analysis():
    sample_path = Path("quarantine/4ba17752a7fa6fb2afb70124ea1e8651999487d1f4ece5196ab1c37beee75718.bin")
    if not sample_path.exists():
        pytest.skip("Sample binary not found in quarantine")

    result = perform_full_static_analysis(str(sample_path))
    assert "overall_entropy" in result
    assert result["overall_entropy"] > 0.0
    assert result["elf_decomposition"]["is_elf"] is True
    assert "plain_indicators" in result
    assert "xor_deobfuscation" in result
