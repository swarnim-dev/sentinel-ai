"""
File Scanner — Static analysis for downloaded files.
Performs multiple heuristic checks without external APIs:
  1. Dangerous file extension detection
  2. Double extension detection (e.g. invoice.pdf.exe)
  3. Magic byte analysis (file signature vs extension mismatch)
  4. Entropy analysis (packed/encrypted detection)
  5. Suspicious string scanning (PowerShell, base64, shell commands)
  6. Office macro indicator detection
"""

import math
import re
from collections import Counter

# ── Dangerous extensions ──
DANGEROUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".scr", ".pif", ".com",
    ".msi", ".msp", ".mst",
    ".ps1", ".psm1", ".psd1",     # PowerShell
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",  # Script files
    ".hta", ".cpl", ".inf", ".reg",
    ".jar",                        # Java
    ".app", ".command",            # macOS
    ".sh", ".bash",                # Unix shell
    ".dll", ".sys",                # Libraries/drivers
    ".iso", ".img",                # Disk images
}

MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm"}

ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz"}

# ── Magic bytes (file signatures) ──
MAGIC_BYTES = {
    b"MZ":                          "PE executable (Windows EXE/DLL)",
    b"\x7fELF":                     "ELF executable (Linux/macOS)",
    b"PK\x03\x04":                  "ZIP archive (or Office OOXML / JAR)",
    b"\xd0\xcf\x11\xe0":            "OLE2 document (legacy Office with potential macros)",
    b"%PDF":                        "PDF document",
    b"\x89PNG":                     "PNG image",
    b"\xff\xd8\xff":                "JPEG image",
    b"GIF87a":                      "GIF image",
    b"GIF89a":                      "GIF image",
    b"Rar!":                        "RAR archive",
    b"7z\xbc\xaf":                  "7-Zip archive",
    b"\x1f\x8b":                    "GZIP compressed",
    b"\xca\xfe\xba\xbe":            "macOS Mach-O / Java class",
    b"\xfe\xed\xfa":                "macOS Mach-O executable",
    b"\xcf\xfa\xed\xfe":            "macOS Mach-O executable (64-bit)",
}

# Map extensions to expected magic byte descriptions
EXTENSION_MAGIC_MAP = {
    ".exe": ["PE executable"],
    ".dll": ["PE executable"],
    ".pdf": ["PDF document"],
    ".png": ["PNG image"],
    ".jpg": ["JPEG image"],
    ".jpeg": ["JPEG image"],
    ".gif": ["GIF image"],
    ".zip": ["ZIP archive"],
    ".docx": ["ZIP archive"],
    ".xlsx": ["ZIP archive"],
    ".pptx": ["ZIP archive"],
    ".doc": ["OLE2 document"],
    ".xls": ["OLE2 document"],
    ".rar": ["RAR archive"],
    ".7z": ["7-Zip archive"],
    ".gz": ["GZIP compressed"],
    ".jar": ["ZIP archive"],
}

# ── Suspicious string patterns ──
SUSPICIOUS_PATTERNS = [
    (r"powershell", "Contains PowerShell reference"),
    (r"cmd\.exe|command\.com", "References Windows command interpreter"),
    (r"Invoke-(WebRequest|Expression|Mimikatz)", "Contains PowerShell attack commands"),
    (r"wget\s|curl\s", "Contains download commands (wget/curl)"),
    (r"/bin/(ba)?sh", "Contains Unix shell reference"),
    (r"base64[_\s]*-?d(ecode)?", "Contains base64 decode instructions"),
    (r"<script[^>]*>", "Contains embedded script tags"),
    (r"eval\s*\(", "Contains eval() — potential code injection"),
    (r"exec\s*\(", "Contains exec() — potential code execution"),
    (r"HKEY_(LOCAL_MACHINE|CURRENT_USER)", "Modifies Windows registry"),
    (r"\\\\[A-Za-z0-9]+\\", "Contains UNC network path"),
    (r"rm\s+-rf\s+/", "Contains destructive delete command"),
    (r"chmod\s+777", "Sets overly permissive file permissions"),
    (r"net\s+user\s+", "Attempts user account manipulation"),
    (r"nc\s+-[el]|ncat\s+", "Contains netcat (reverse shell) command"),
]


def scan_file(filename: str, content: bytes) -> dict:
    """
    Perform all heuristic checks on a file.
    Returns a dict with risk_score, verdict, and detailed reasons.
    """
    reasons = []
    risk_points = 0
    max_points = 0

    ext = _get_extension(filename).lower()

    # ── 1. Dangerous extension check ──
    max_points += 30
    if ext in DANGEROUS_EXTENSIONS:
        risk_points += 30
        reasons.append(f"File extension '{ext}' is a known dangerous/executable type.")
    elif ext in MACRO_EXTENSIONS:
        risk_points += 20
        reasons.append(f"Office file '{ext}' can contain macros — a common malware delivery method.")
    elif ext in ARCHIVE_EXTENSIONS:
        risk_points += 5
        reasons.append(f"Archive file '{ext}' — contents cannot be verified without extraction.")

    # ── 2. Double extension detection ──
    max_points += 20
    parts = filename.rsplit(".", 2)
    if len(parts) >= 3:
        fake_ext = "." + parts[-2].lower()
        real_ext = "." + parts[-1].lower()
        if real_ext in DANGEROUS_EXTENSIONS and fake_ext not in DANGEROUS_EXTENSIONS:
            risk_points += 20
            reasons.append(
                f"Double extension detected: '{fake_ext}{real_ext}' — "
                f"file pretends to be '{fake_ext}' but is actually '{real_ext}'."
            )

    # ── 3. Magic byte analysis ──
    max_points += 25
    detected_type = _detect_magic(content)
    if detected_type:
        expected_types = EXTENSION_MAGIC_MAP.get(ext, [])
        if expected_types and not any(e in detected_type for e in expected_types):
            risk_points += 25
            reasons.append(
                f"File signature mismatch: extension is '{ext}' but actual content is '{detected_type}'. "
                f"This file may be disguised."
            )
        elif "PE executable" in detected_type and ext not in (".exe", ".dll", ".sys", ".scr"):
            risk_points += 25
            reasons.append(
                f"File contains a Windows executable signature but has extension '{ext}'. "
                f"Likely a disguised malware binary."
            )
    else:
        if ext in DANGEROUS_EXTENSIONS:
            risk_points += 5
            reasons.append("File signature could not be identified — unusual for this file type.")

    # ── 4. Entropy analysis ──
    max_points += 15
    entropy = _calculate_entropy(content)
    if entropy > 7.5:
        risk_points += 15
        reasons.append(
            f"Very high entropy ({entropy:.2f}/8.0) — file may be packed, encrypted, or obfuscated. "
            f"Malware often uses packing to avoid detection."
        )
    elif entropy > 6.8:
        risk_points += 5
        reasons.append(f"Elevated entropy ({entropy:.2f}/8.0) — could indicate compressed or encoded content.")

    # ── 5. Suspicious string scanning ──
    max_points += 30
    text_content = _safe_decode(content)
    if text_content:
        found_patterns = []
        for pattern, description in SUSPICIOUS_PATTERNS:
            if re.search(pattern, text_content, re.IGNORECASE):
                found_patterns.append(description)

        if found_patterns:
            pts = min(30, len(found_patterns) * 8)
            risk_points += pts
            for desc in found_patterns[:5]:  # Max 5 reasons
                reasons.append(desc)

    # ── 6. Office macro indicators ──
    max_points += 10
    if ext in MACRO_EXTENSIONS or (detected_type and "OLE2" in detected_type):
        macro_keywords = [b"VBA", b"AutoOpen", b"Auto_Open", b"Workbook_Open",
                          b"Document_Open", b"Shell", b"CreateObject"]
        found_macros = [kw.decode() for kw in macro_keywords if kw in content]
        if found_macros:
            risk_points += 10
            reasons.append(
                f"Contains macro indicators: {', '.join(found_macros[:3])}. "
                f"Malicious macros are a top malware delivery method."
            )

    # ── Calculate final score ──
    if max_points > 0:
        risk_score = min(1.0, round(risk_points / max_points, 3))
    else:
        risk_score = 0.0

    if risk_score >= 0.6:
        verdict = "dangerous"
    elif risk_score >= 0.3:
        verdict = "suspicious"
    else:
        verdict = "safe"

    return {
        "filename": filename,
        "size_bytes": len(content),
        "risk_score": risk_score,
        "verdict": verdict,
        "detected_type": detected_type or "Unknown",
        "entropy": round(entropy, 2) if content else 0,
        "reasons": reasons if reasons else ["No suspicious indicators found."]
    }


def _get_extension(filename: str) -> str:
    idx = filename.rfind(".")
    return filename[idx:] if idx != -1 else ""


def _detect_magic(content: bytes) -> str:
    """Identify file type from magic bytes."""
    for sig, desc in MAGIC_BYTES.items():
        if content[:len(sig)] == sig:
            return desc
    return None


def _calculate_entropy(data: bytes) -> float:
    """Shannon entropy of binary content (0 = uniform, 8 = max random)."""
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
    return entropy


def _safe_decode(content: bytes) -> str:
    """Try to decode binary content as text for string scanning."""
    try:
        # Only scan the first 100KB of text
        return content[:102400].decode("utf-8", errors="ignore")
    except Exception:
        return ""
