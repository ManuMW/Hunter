"""
Hunter Static Binary Decomposition & Deobfuscated String Analysis Engine
Part of Hunter Threat Research Pipeline (HUN-29).

Provides:
1. Deep ELF structural decomposition using pyelftools:
   - Header, sections, segments (program headers), dynamic symbols, libraries.
   - Stripped status and security mitigations (NX, PIE, Canary, RelRO).
2. Shannon entropy calculation:
   - File-level and per-section entropy to detect packers and cryptors (e.g. UPX).
3. Obfuscated string extraction and single-byte XOR brute forcing:
   - Identifies hidden C2 domains, IPs, URLs, botnet commands (Mirai, Gafgyt, Mozi).
   - Tests all single-byte XOR keys (0x01..0xFF) and well-known rolling keys (0xDEADBEEF).
"""

import io
import math
import re
from collections import Counter
from pathlib import Path
from typing import Dict, Any, List, Optional, Set

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    HAVE_PYELFTOOLS = True
except ImportError:
    HAVE_PYELFTOOLS = False


# High-value threat indicator regexes and keywords
SUSPICIOUS_KEYWORDS = [
    "busybox", "watchdog", "POST ", "GET ", "HTTP/1.1", "User-Agent:",
    "/bin/sh", "/bin/bash", "/dev/watchdog", "/dev/misc/watchdog",
    "iptables", "kill -9", "rm -rf", "tftp", "wget", "curl",
    "admin:admin", "root:root", "default:default", "service:service",
    "telnet", "ssh", "mirai", "gafgyt", "bashlite", "mozi", "botnet",
    "scanner", "killer", "attack", "flood", "syn", "ack", "udp", "cnc",
    "HELO", "PONG", "PING", "report", "login", "password"
]

COMMON_ROLLING_KEYS = [
    b"\xde\xad\xbe\xef",  # Mirai default table key
    b"\xba\xad\xf0\x0d",
    b"\xca\xfe\xba\xbe",
]


def calculate_shannon_entropy(data: bytes) -> float:
    """Computes Shannon entropy (0.0 to 8.0) for a given byte buffer."""
    if not data:
        return 0.0
    counter = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counter.values():
        p = count / total
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_plain_strings(data: bytes, min_len: int = 4) -> List[str]:
    """Extracts printable ASCII strings (length >= min_len)."""
    pattern = rb"[ -~]{" + str(min_len).encode() + rb",}"
    matches = re.findall(pattern, data)
    return [m.decode("ascii", errors="ignore") for m in matches]


def find_indicators_in_text(text: str) -> Dict[str, List[str]]:
    """Extracts IPv4s, URLs, filesystem paths, and suspicious keywords from text."""
    # IPv4 regex
    ip_pattern = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )
    raw_ips = set(ip_pattern.findall(text))
    valid_ips = [
        ip for ip in raw_ips
        if not ip.startswith(("0.", "127.", "255.", "10.", "192.168.", "172.16."))
    ]

    # URLs
    url_pattern = re.compile(r"(?:https?|ftp)://[a-zA-Z0-9\-\.]+(?::[0-9]{1,5})?(?:/[^\s\"\'<>]*)?")
    urls = list(set(url_pattern.findall(text)))

    # Linux paths
    path_pattern = re.compile(r"/(?:tmp|etc|var|proc|sys|dev|bin|usr|sbin)/[a-zA-Z0-9_\-\./]+")
    paths = list(set(path_pattern.findall(text)))

    # Keywords
    text_lower = text.lower()
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw.lower() in text_lower]

    return {
        "ips": valid_ips[:20],
        "urls": urls[:20],
        "paths": paths[:30],
        "keywords": matched_keywords
    }


def brute_force_xor_strings(
    data: bytes,
    plain_indicators: Optional[Set[str]] = None,
    max_scan_bytes: int = 512 * 1024
) -> List[Dict[str, Any]]:
    """
    Scans for single-byte XOR and known rolling-key obfuscated strings.
    Filters out indicators that were already present in the plain text.
    """
    if plain_indicators is None:
        plain_text = " ".join(extract_plain_strings(data[:max_scan_bytes]))
        plain_dict = find_indicators_in_text(plain_text)
        plain_indicators = set(plain_dict["ips"] + plain_dict["urls"] + plain_dict["keywords"])

    scan_chunk = data[:max_scan_bytes]
    discovered = []

    # 1. Single-byte XOR brute force (0x01 to 0xFF)
    for key in range(1, 256):
        # Fast byte translation
        table = bytes([b ^ key for b in range(256)])
        decrypted = scan_chunk.translate(table)
        dec_strings = extract_plain_strings(decrypted, min_len=4)
        dec_text = " ".join(dec_strings)

        ind = find_indicators_in_text(dec_text)
        new_keywords = [k for k in ind["keywords"] if k not in plain_indicators]
        new_ips = [ip for ip in ind["ips"] if ip not in plain_indicators]
        new_urls = [u for u in ind["urls"] if u not in plain_indicators]

        score = (len(new_keywords) * 2) + (len(new_ips) * 3) + (len(new_urls) * 4)

        # Require significant new indicators
        if score >= 4 or len(new_ips) >= 1 or len(new_urls) >= 1 or len(new_keywords) >= 2:
            discovered.append({
                "type": "single_byte_xor",
                "key_hex": f"0x{key:02x}",
                "key_int": key,
                "score": score,
                "discovered_ips": new_ips[:10],
                "discovered_urls": new_urls[:10],
                "discovered_keywords": new_keywords[:15],
                "sample_decoded_strings": [
                    s for s in dec_strings
                    if any(marker in s for marker in [":", "/", ".", "http", "busybox", "attack", "admin"])
                ][:20]
            })

    # 2. Known rolling multi-byte XOR keys
    for rk in COMMON_ROLLING_KEYS:
        key_len = len(rk)
        decrypted = bytes([b ^ rk[i % key_len] for i, b in enumerate(scan_chunk)])
        dec_strings = extract_plain_strings(decrypted, min_len=4)
        dec_text = " ".join(dec_strings)
        ind = find_indicators_in_text(dec_text)
        new_keywords = [k for k in ind["keywords"] if k not in plain_indicators]
        new_ips = [ip for ip in ind["ips"] if ip not in plain_indicators]
        new_urls = [u for u in ind["urls"] if u not in plain_indicators]

        score = (len(new_keywords) * 2) + (len(new_ips) * 3) + (len(new_urls) * 4)
        if score >= 4:
            discovered.append({
                "type": "rolling_key_xor",
                "key_hex": f"0x{rk.hex()}",
                "score": score,
                "discovered_ips": new_ips[:10],
                "discovered_urls": new_urls[:10],
                "discovered_keywords": new_keywords[:15],
                "sample_decoded_strings": dec_strings[:15]
            })

    # Sort descending by detection score
    discovered.sort(key=lambda x: x["score"], reverse=True)
    return discovered[:5]


def analyze_elf_structure(data: bytes) -> Dict[str, Any]:
    """
    Performs full static decomposition of ELF binary headers, sections,
    segments, security mitigations, and symbols using pyelftools.
    """
    if len(data) < 16 or data[:4] != b"\x7fELF":
        return {"is_elf": False, "error": "Not an ELF binary"}

    if not HAVE_PYELFTOOLS:
        return {
            "is_elf": True,
            "pyelftools_available": False,
            "error": "pyelftools not installed"
        }

    try:
        stream = io.BytesIO(data)
        elf = ELFFile(stream)

        # Header Info
        header = elf.header
        e_type = str(header.get("e_type", ""))
        e_machine = str(header.get("e_machine", ""))
        e_entry = hex(header.get("e_entry", 0))
        elf_class = f"{elf.elfclass}-bit"
        endianness = "Little Endian" if elf.little_endian else "Big Endian"

        # Sections & Section Entropy
        sections = []
        section_names = []
        is_packed = False
        has_symtab = False

        for s in elf.iter_sections():
            name = s.name
            section_names.append(name)
            if name == ".symtab":
                has_symtab = True

            size = s["sh_size"]
            s_entropy = 0.0
            if size > 0:
                try:
                    s_data = s.data()
                    s_entropy = calculate_shannon_entropy(s_data)
                    if name in [".text", ".data", ".rodata"] and s_entropy > 7.1:
                        is_packed = True
                except Exception:
                    pass

            sections.append({
                "name": name or "(unnamed)",
                "type": str(s["sh_type"]),
                "size": size,
                "entropy": s_entropy,
                "addr": hex(s["sh_addr"])
            })

        # Segments & Mitigations
        has_nx = False
        nx_explicit = False
        has_relro = False
        bind_now = False

        for seg in elf.iter_segments():
            p_type = seg["p_type"]
            flags = seg["p_flags"]
            if p_type == "PT_GNU_STACK":
                nx_explicit = True
                # PF_X = 1 -> executable stack
                has_nx = (flags & 1) == 0
            elif p_type == "PT_GNU_RELRO":
                has_relro = True

        # Check Dynamic Tags
        dynamic_libraries = []
        dynamic_section = elf.get_section_by_name(".dynamic")
        if dynamic_section:
            for tag in dynamic_section.iter_tags():
                if tag.entry.d_tag == "DT_NEEDED":
                    dynamic_libraries.append(tag.needed)
                elif tag.entry.d_tag in ["DT_BIND_NOW", "DF_BIND_NOW"]:
                    bind_now = True

        # Check Stack Canary (__stack_chk_fail)
        has_canary = b"__stack_chk_fail" in data

        # Check UPX / Packer signatures
        upx_detected = b"UPX!" in data or b"UPX0" in data or b"UPX1" in data

        # Security Mitigations Matrix
        if nx_explicit:
            nx_status = "Enabled" if has_nx else "Disabled (Executable Stack)"
        else:
            nx_status = "Disabled (Missing PT_GNU_STACK)"

        if has_relro:
            relro_status = "Full RelRO" if bind_now else "Partial RelRO"
        else:
            relro_status = "No RelRO"

        pie_status = "Enabled (PIE)" if "ET_DYN" in e_type else "Disabled (Fixed Address)"
        canary_status = "Detected" if has_canary else "Not Detected"
        stripped_status = "Stripped" if not has_symtab else "Not Stripped (Symbols Present)"

        return {
            "is_elf": True,
            "pyelftools_available": True,
            "class": elf_class,
            "endianness": endianness,
            "machine": e_machine,
            "type": e_type,
            "entry_point": e_entry,
            "is_stripped": not has_symtab,
            "stripped_status": stripped_status,
            "is_likely_packed": is_packed or upx_detected,
            "packer_detected": "UPX" if upx_detected else ("High Entropy / Custom Packer" if is_packed else None),
            "security_mitigations": {
                "nx": nx_status,
                "pie": pie_status,
                "relro": relro_status,
                "canary": canary_status,
                "stripped": stripped_status
            },
            "dynamic_libraries": dynamic_libraries[:15],
            "sections": sections[:25]
        }

    except Exception as e:
        return {
            "is_elf": True,
            "pyelftools_available": True,
            "error": f"ELF parsing error: {e}"
        }


def perform_full_static_analysis(
    sample_path: Optional[str] = None,
    raw_bytes: Optional[bytes] = None
) -> Dict[str, Any]:
    """
    Main entry point for full static binary analysis & string deobfuscation.
    Accepts either file path or in-memory bytes.
    """
    if raw_bytes is None:
        if not sample_path or not Path(sample_path).exists():
            raise ValueError("No valid sample path or raw bytes provided.")
        raw_bytes = Path(sample_path).read_bytes()

    file_size = len(raw_bytes)
    overall_entropy = calculate_shannon_entropy(raw_bytes)

    # 1. ELF Structural Decomposition
    elf_decomp = analyze_elf_structure(raw_bytes)

    # 2. Plain Text Extraction & Indicators
    plain_strings = extract_plain_strings(raw_bytes, min_len=4)
    plain_text = " ".join(plain_strings[:20000])
    plain_indicators = find_indicators_in_text(plain_text)
    known_plain_set = set(plain_indicators["ips"] + plain_indicators["urls"] + plain_indicators["keywords"])

    # 3. Obfuscated / XOR String Brute-Force Extraction
    xor_findings = brute_force_xor_strings(raw_bytes, plain_indicators=known_plain_set)

    # Aggregate extracted deobfuscated IoCs
    deobfuscated_ips = []
    deobfuscated_urls = []
    for xf in xor_findings:
        for ip in xf.get("discovered_ips", []):
            if ip not in deobfuscated_ips and ip not in plain_indicators["ips"]:
                deobfuscated_ips.append(ip)
        for u in xf.get("discovered_urls", []):
            if u not in deobfuscated_urls and u not in plain_indicators["urls"]:
                deobfuscated_urls.append(u)

    return {
        "file_size": file_size,
        "overall_entropy": overall_entropy,
        "is_high_entropy": overall_entropy > 7.1,
        "elf_decomposition": elf_decomp,
        "plain_indicators": plain_indicators,
        "sample_plain_strings": plain_strings[:40],
        "total_plain_strings": len(plain_strings),
        "xor_deobfuscation": {
            "detected_keys": xor_findings,
            "deobfuscated_ips": deobfuscated_ips,
            "deobfuscated_urls": deobfuscated_urls,
            "is_xor_obfuscated": len(xor_findings) > 0
        }
    }
