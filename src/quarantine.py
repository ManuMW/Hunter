import hashlib
import os
import stat
from pathlib import Path
from typing import Dict, Any
from src.config import QUARANTINE_DIR


def detect_file_type(header: bytes) -> str:
    """Basic magic bytes detection for common executables and scripts."""
    if header.startswith(b"\x7fELF"):
        return "Linux ELF Binary"
    elif header.startswith(b"MZ"):
        return "Windows PE Executable"
    elif header.startswith(b"#!"):
        line = header.split(b"\n")[0].decode("latin-1", errors="ignore")
        if "python" in line:
            return "Python Script"
        elif "sh" in line or "bash" in line:
            return "Shell Script"
        elif "perl" in line:
            return "Perl Script"
        return f"Script ({line.strip()})"
    elif b"import " in header or b"def " in header:
        return "Python Script (Headerless)"
    return "Unknown Binary / Data"


def quarantine_sample(content: bytes, original_filename: str) -> Dict[str, Any]:
    """
    Safely stores an untrusted sample in the Quarantine Store.
    
    1. Computes cryptographic hashes (SHA-256, SHA-1, MD5).
    2. Determines file type from magic bytes.
    3. Saves file as quarantine/<sha256>.bin.
    4. Applies chmod 0600 (non-executable, owner read/write only).
    """
    sha256 = hashlib.sha256(content).hexdigest()
    sha1 = hashlib.sha1(content).hexdigest()
    md5 = hashlib.md5(content).hexdigest()
    size_bytes = len(content)
    file_type = detect_file_type(content[:1024])
    
    target_path = QUARANTINE_DIR / f"{sha256}.bin"
    with open(target_path, "wb") as f:
        f.write(content)
        
    # Strip executable bits and restrict permissions to owner only
    try:
        os.chmod(target_path, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        # Best effort on non-POSIX systems like Windows
        pass

    return {
        "sha256": sha256,
        "sha1": sha1,
        "md5": md5,
        "filename": original_filename,
        "size_bytes": size_bytes,
        "file_type": file_type,
        "quarantine_path": str(target_path),
        "raw_bytes": content
    }
