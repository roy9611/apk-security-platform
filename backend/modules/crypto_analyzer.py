"""
crypto_analyzer.py — Detects insecure cryptography patterns in decompiled Java source.

Checks:
  - Weak/broken cipher algorithms (DES, 3DES, RC4, Blowfish)
  - ECB mode usage (no IV, deterministic output)
  - Hardcoded / static initialization vectors
  - Weak random number generators (java.util.Random)
  - MD5 / SHA-1 used for password hashing
"""

from pathlib import Path

from models import Finding, ModuleResult

EVIDENCE_MAX   = 80
_SEV_ORDER     = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# Algorithms that are broken and should never be used for confidentiality
_WEAK_CIPHERS = {
    '"DES"':          ("DES", "56-bit key, brute-forceable in hours on commodity hardware"),
    '"DESede"':       ("3DES", "Triple-DES is deprecated; 112-bit effective security, slow"),
    '"TripleDES"':    ("3DES", "Triple-DES is deprecated; 112-bit effective security, slow"),
    '"Blowfish"':     ("Blowfish", "64-bit block size; vulnerable to SWEET32 birthday attacks"),
    '"RC4"':          ("RC4", "RC4 is broken; biased keystream bytes leak plaintext"),
    '"ARCFOUR"':      ("RC4", "RC4 is broken; biased keystream bytes leak plaintext"),
}

# ECB mode patterns in Cipher.getInstance calls
_ECB_PATTERNS = [
    "/ECB/",
    '"AES"',       # AES without mode defaults to ECB in most JCE providers
]


def analyze_crypto(workspace_paths: dict) -> ModuleResult:
    jadx_dir = Path(workspace_paths.get("jadx_dir", ""))
    findings = []
    errors   = []

    if not jadx_dir.exists():
        return ModuleResult(
            module="crypto",
            severity="INFO",
            findings=[Finding(
                title="No Decompiled Java Source Available",
                detail="jadx output directory not found; cryptography analysis could not run.",
                severity="INFO",
                location="N/A",
                evidence=f"jadx_dir missing: {jadx_dir}",
            )],
            errors=[f"jadx_dir not found: {jadx_dir}"],
        )

    for java_file in jadx_dir.rglob("*.java"):
        try:
            _scan_file(java_file, findings)
        except Exception as exc:
            errors.append(f"Error scanning {java_file.name}: {exc}")

    highest = _highest_severity(findings)
    return ModuleResult(module="crypto", severity=highest, findings=findings, errors=errors)


# ── Per-file checks ────────────────────────────────────────────────────────────

def _scan_file(java_file: Path, findings: list):
    try:
        content = java_file.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return

    # Skip files that don't touch crypto at all — fast exit
    if not any(kw in content for kw in [
        "Cipher", "MessageDigest", "KeySpec", "IvParameter",
        "SecretKey", "new Random(", "java.util.Random",
    ]):
        return

    lines = content.splitlines()

    _check_weak_ciphers(java_file, lines, findings)
    _check_ecb_mode(java_file, lines, findings)
    _check_static_iv(java_file, lines, findings)
    _check_weak_random(java_file, lines, findings)
    _check_weak_hash(java_file, lines, findings)


def _check_weak_ciphers(java_file: Path, lines: list, findings: list):
    """Detects Cipher.getInstance() calls using broken algorithms."""
    reported = set()
    for i, line in enumerate(lines):
        if "Cipher.getInstance" not in line:
            continue
        for token, (algo_name, reason) in _WEAK_CIPHERS.items():
            if token in line and algo_name not in reported:
                reported.add(algo_name)
                findings.append(Finding(
                    title=f"Weak Cipher Algorithm: {algo_name}",
                    detail=(
                        f"{reason}. Replace with AES-256 in GCM mode: "
                        f'Cipher.getInstance("AES/GCM/NoPadding").'
                    ),
                    severity="HIGH",
                    location=f"{java_file.name}:{i + 1}",
                    evidence=line.strip()[:EVIDENCE_MAX],
                ))


def _check_ecb_mode(java_file: Path, lines: list, findings: list):
    """
    Detects ECB mode — either explicit '/ECB/' or bare 'AES' without a mode string.
    ECB encrypts each 16-byte block independently, producing identical ciphertext
    for identical plaintext blocks. Pattern analysis reveals data structure.
    """
    for i, line in enumerate(lines):
        if "Cipher.getInstance" not in line:
            continue

        is_ecb = False
        reason = ""

        if "/ECB/" in line:
            is_ecb = True
            reason = "ECB mode specified explicitly"
        elif '"AES"' in line and "/CBC/" not in line and "/GCM/" not in line and "/CTR/" not in line:
            is_ecb = True
            reason = 'Cipher.getInstance("AES") defaults to AES/ECB in most JCE providers'

        if is_ecb:
            findings.append(Finding(
                title="ECB Mode Encryption (No IV, Deterministic Output)",
                detail=(
                    f"{reason}. ECB produces identical ciphertext for identical plaintext blocks — "
                    "an attacker can identify repeated data patterns without decrypting. "
                    'Use AES/GCM/NoPadding with a random 96-bit IV for authenticated encryption.'
                ),
                severity="HIGH",
                location=f"{java_file.name}:{i + 1}",
                evidence=line.strip()[:EVIDENCE_MAX],
            ))
            return  # One per file


def _check_static_iv(java_file: Path, lines: list, findings: list):
    """
    Detects IvParameterSpec constructed from a literal byte array.
    A static IV means the same key+IV pair is reused across encryptions,
    breaking semantic security (CBC) or enabling nonce-reuse attacks (GCM).
    """
    for i, line in enumerate(lines):
        if "IvParameterSpec" not in line:
            continue

        # Look ahead up to 3 lines for a byte[] literal
        window = lines[i: min(len(lines), i + 4)]
        window_text = " ".join(window)
        if "new byte[]{" in window_text or "new byte[] {" in window_text or "{0," in window_text:
            findings.append(Finding(
                title="Static / Hardcoded Initialization Vector (IV)",
                detail=(
                    "IvParameterSpec is initialized with a hardcoded byte array. "
                    "Reusing the same IV with the same key breaks CBC confidentiality and "
                    "enables GCM nonce-reuse attacks which can expose the authentication key. "
                    "Always generate a random IV with SecureRandom for each encryption operation."
                ),
                severity="HIGH",
                location=f"{java_file.name}:{i + 1}",
                evidence=line.strip()[:EVIDENCE_MAX],
            ))
            return


def _check_weak_random(java_file: Path, lines: list, findings: list):
    """
    Detects java.util.Random used in security-sensitive contexts.
    java.util.Random is a linear congruential generator — predictable from a small
    sample of outputs. Only SecureRandom is appropriate for cryptographic use.
    """
    for i, line in enumerate(lines):
        stripped = line.strip()
        if "new Random()" not in stripped and "new java.util.Random()" not in stripped:
            continue
        # Avoid false positives on test files and imports
        if "import" in stripped or "test" in java_file.name.lower():
            continue

        findings.append(Finding(
            title="Insecure Random Number Generator (java.util.Random)",
            detail=(
                "java.util.Random uses a linear congruential algorithm whose output is "
                "predictable given a small number of observed values. It must not be used "
                "for session tokens, keys, nonces, or any security-relevant random values. "
                "Replace with java.security.SecureRandom."
            ),
            severity="MEDIUM",
            location=f"{java_file.name}:{i + 1}",
            evidence=stripped[:EVIDENCE_MAX],
        ))
        return  # One per file


def _check_weak_hash(java_file: Path, lines: list, findings: list):
    """
    Detects MD5 and SHA-1 used via MessageDigest — commonly for password hashing.
    Both are collision-broken and trivially crackable via rainbow tables when
    used without a salt and cost factor.
    """
    reported = set()
    for i, line in enumerate(lines):
        if "MessageDigest" not in line and "getInstance" not in line:
            continue
        for algo in ['"MD5"', '"SHA-1"', '"SHA1"']:
            if algo in line and algo not in reported:
                reported.add(algo)
                findings.append(Finding(
                    title=f"Broken Hash Algorithm for Cryptographic Use: {algo.strip('\"')}",
                    detail=(
                        f"{algo.strip('\"')} is cryptographically broken — collision attacks exist "
                        "and preimage attacks are feasible. If used for password storage, it is "
                        "trivially crackable. Replace with SHA-256 for integrity checks, or "
                        "BCrypt/Argon2 for password hashing."
                    ),
                    severity="MEDIUM",
                    location=f"{java_file.name}:{i + 1}",
                    evidence=line.strip()[:EVIDENCE_MAX],
                ))


def _highest_severity(findings: list) -> str:
    for level in _SEV_ORDER:
        if any(f.severity == level for f in findings):
            return level
    return "INFO"
