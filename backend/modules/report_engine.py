"""
report_engine.py — Builds the final ScanResult from all module outputs.

calculate_risk_score  — sums severity weights and normalises to 0-100.
generate_remediation  — maps finding titles to specific developer action items.
build_scan_result     — assembles the complete ScanResult dataclass.
"""

from pathlib import Path

import config
from models import ModuleResult, ScanResult

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# Maximum raw points each module can contribute (prevents noisy modules dominating)
_MODULE_CAPS = {
    "manifest":    60,
    "yara":        55,
    "ssl":         50,
    "firebase":    45,
    "secrets":     40,
    "crypto":      35,
    "webview":     35,
    "storage":     30,
    "permissions": 25,
}
_DEFAULT_MODULE_CAP = 20

# High-signal confirmed-critical rule titles — get a 2× multiplier
_CONFIRMED_CRITICAL_KEYWORDS = [
    "debuggable", "trustmanager", "hostnameVerifier",
    "aws", "private key", "firebase", "sms exfiltration",
]

# Effective normalisation baseline — anchored so that a 3-module fully-exploitable
# scan (manifest+ssl+secrets at max multiplier + context bonuses) maps to ~70/100.
# sum of top-5 module caps (60+55+50+45+40) = 250
_MAX_RAW = 250


def _finding_multiplier(finding) -> float:
    """Return the weight multiplier for a single finding."""
    title    = (finding.get("title", "")    if isinstance(finding, dict) else finding.title).lower()
    sev      = (finding.get("severity", "") if isinstance(finding, dict) else finding.severity).upper()
    evidence = (finding.get("evidence", "") if isinstance(finding, dict) else finding.evidence).lower()

    # INFO findings contribute nothing
    if sev == "INFO" or "permission summary" in title:
        return 0.0

    # Entropy findings are very noisy — heavily discounted
    if "entropy" in evidence or "entropy" in title:
        return 0.1

    # YARA-confirmed findings are high-signal
    if "yara rule" in evidence:
        # Confirmed critical exploits get a further boost
        if sev == "CRITICAL" and any(kw in title for kw in _CONFIRMED_CRITICAL_KEYWORDS):
            return 2.0
        return 1.5

    # Non-YARA confirmed criticals still get a boost
    if sev == "CRITICAL" and any(kw in title for kw in _CONFIRMED_CRITICAL_KEYWORDS):
        return 2.0

    return 1.0


def calculate_risk_score(all_results: dict) -> tuple:
    """
    Smart scoring: per-module weight caps + finding-type multipliers + context bonuses.
    Normalises to 0-100. Returns (int score, str level).
    """
    total = 0.0

    # Collect module-level data for context bonus checks
    module_findings: dict[str, list] = {}

    for module_name, module_result in all_results.items():
        if isinstance(module_result, dict):
            findings = module_result.get("findings", [])
        else:
            findings = module_result.findings

        module_findings[module_name] = findings

        raw = sum(
            config.SEVERITY_WEIGHTS.get(
                f.get("severity", "INFO") if isinstance(f, dict) else f.severity, 0
            ) * _finding_multiplier(f)
            for f in findings
        )
        cap = _MODULE_CAPS.get(module_name, _DEFAULT_MODULE_CAP)
        total += min(raw, cap)

    # ── Context bonuses ───────────────────────────────────────────────────────

    def _has_title_keyword(module: str, *keywords: str) -> bool:
        for f in module_findings.get(module, []):
            t = (f.get("title", "") if isinstance(f, dict) else f.title).lower()
            if any(kw in t for kw in keywords):
                return True
        return False

    def _has_sev(module: str, sev: str) -> bool:
        for f in module_findings.get(module, []):
            s = f.get("severity", "") if isinstance(f, dict) else f.severity
            if s == sev:
                return True
        return False

    # Debuggable + exposed creds = extremely dangerous
    if _has_title_keyword("manifest", "debuggable") and _has_sev("secrets", "CRITICAL"):
        total += 15

    # TLS bypass is directly exploitable
    if _has_title_keyword("ssl", "trustmanager", "hostnameVerifier"):
        total += 10

    # Strong malware indicators
    if _has_title_keyword("yara", "sms exfiltration", "accessibility abuse"):
        total += 20

    # WebView JS bridge + JavaScript enabled = direct code execution path
    if _has_title_keyword("webview", "addjavascriptinterface", "java object exposed") \
       and _has_title_keyword("webview", "javascript enabled"):
        total += 15

    # Crypto + SSL both broken = full network interception possible
    if _has_sev("crypto", "HIGH") and _has_title_keyword("ssl", "trustmanager", "hostnameVerifier"):
        total += 10

    # ── Normalise to 0-100 ────────────────────────────────────────────────────
    normalised = min(100, int((total / _MAX_RAW) * 100))

    if normalised >= 75:
        level = "CRITICAL"
    elif normalised >= 50:
        level = "HIGH"
    elif normalised >= 25:
        level = "MEDIUM"
    elif normalised >= 10:
        level = "LOW"
    else:
        level = "INFO"

    return normalised, level


def generate_remediation(all_results: dict) -> list:
    """
    Inspects all findings across modules and returns specific, ordered remediation steps.
    CRITICAL findings appear first, then HIGH, then everything else.
    Duplicate actions are removed while preserving order.
    """
    critical_actions = []
    high_actions     = []
    other_actions    = []

    for module_result in all_results.values():
        findings = []
        if isinstance(module_result, dict):
            raw = module_result.get("findings", [])
            findings = raw
        else:
            findings = module_result.findings

        for finding in findings:
            title    = finding.get("title", "")    if isinstance(finding, dict) else finding.title
            severity = finding.get("severity", "") if isinstance(finding, dict) else finding.severity
            action   = _title_to_action(title)
            if not action:
                continue
            if severity == "CRITICAL":
                critical_actions.append(action)
            elif severity == "HIGH":
                high_actions.append(action)
            else:
                other_actions.append(action)

    # Deduplicate while preserving insertion order
    seen        = set()
    remediation = []
    for action in critical_actions + high_actions + other_actions:
        if action not in seen:
            seen.add(action)
            remediation.append(action)

    return remediation


def _title_to_action(title: str) -> str:
    """
    Maps a finding title to a concrete remediation instruction.
    Returns an empty string if the title doesn't match any known pattern.
    """
    t = title.lower()

    if "debuggable" in t:
        return "Remove android:debuggable='true' from AndroidManifest.xml in all release build configurations."
    if "backup" in t:
        return "Set android:allowBackup='false' or restrict backup scope with android:fullBackupContent rules."
    if "unprotected exported" in t or ("exported" in t and "unprotected" in t):
        return "Add android:permission or android:exported='false' to all exported components that should not be publicly accessible."
    if "trustmanager" in t or ("certificate" in t and "accept" in t):
        return "Remove the custom TrustManager — never override checkServerTrusted() with an empty body. Use the system default TLS validation."
    if "hostname" in t and "true" in t:
        return "Remove the HostnameVerifier that returns true — use Android's default hostname verification."
    if "open firebase" in t:
        return "Add Firebase Realtime Database security rules to deny unauthenticated read and write access."
    if "aws" in t or "stripe" in t or "private key" in t:
        return "Rotate compromised credentials immediately and store them server-side — never embed credentials in APK source."
    if "hardcoded" in t or "high-entropy" in t:
        return "Remove all hardcoded secrets and API keys from source code; use a server-side configuration or a secrets manager."
    if "cleartext" in t and "url" in t:
        return "Replace all http:// endpoints with https:// and remove android:usesCleartextTraffic='true'."
    if "cleartext" in t:
        return "Replace all cleartext HTTP connections with HTTPS and remove cleartextTrafficPermitted='true' from network security config."
    if "user-installed certificates" in t or "user" in t and "certificate" in t:
        return "Remove <certificates src='user'/> from network security config to prevent interception with user-installed CAs."
    if "world-readable" in t or "world-writable" in t:
        return "Replace MODE_WORLD_READABLE and MODE_WORLD_WRITEABLE with MODE_PRIVATE for all file and SharedPreferences operations."
    if "external storage" in t:
        return "Store sensitive files in internal storage (getFilesDir()) rather than external storage."
    if "unencrypted sqlite" in t:
        return "Replace SQLiteOpenHelper with SQLCipher to encrypt the database at rest."
    if "certificate pinning" in t or "pin-set" in t:
        return "Implement certificate pinning with a <pin-set> in res/xml/network_security_config.xml."
    if "combination" in t or "exfiltration" in t or "surveillance" in t:
        return "Audit the declared permissions list and remove all permissions not essential to the app's core functionality."
    if "ecb mode" in t:
        return 'Replace ECB mode with AES/GCM/NoPadding and a random 96-bit IV generated with SecureRandom.'
    if "weak cipher" in t or "des" in t or "rc4" in t or "blowfish" in t:
        return 'Replace broken cipher with AES-256-GCM: Cipher.getInstance("AES/GCM/NoPadding").'
    if "static" in t and "iv" in t:
        return "Generate a unique random IV with SecureRandom for every encryption operation — never reuse a fixed IV."
    if "java.util.random" in t or "insecure random" in t:
        return "Replace java.util.Random with java.security.SecureRandom for all security-sensitive random values."
    if "md5" in t or "sha-1" in t or "sha1" in t or "broken hash" in t:
        return "Replace MD5/SHA-1 with SHA-256 for integrity checks, or Argon2/BCrypt for password hashing."
    if "javascript enabled" in t:
        return "Disable setJavaScriptEnabled unless strictly required; if required, restrict loaded URLs to a trusted allowlist."
    if "addjavascriptinterface" in t or "java object exposed" in t:
        return "Annotate all bridge methods with @JavascriptInterface and audit every exposed method — remove any that are not needed."
    if "ssl error" in t and "proceed" in t:
        return "Replace handler.proceed() in onReceivedSslError() with handler.cancel() — never silently accept invalid certificates."
    if "file access" in t and "webview" in t:
        return "Set setAllowFileAccess(false) and setAllowFileAccessFromFileURLs(false) on all WebView instances."
    if "universal" in t and "file url" in t:
        return "Set setAllowUniversalAccessFromFileURLs(false) immediately — this disables same-origin policy for file:// URLs."
    if "remote debugging" in t or "webcontentsdebugging" in t:
        return "Gate setWebContentsDebuggingEnabled(true) behind BuildConfig.DEBUG so it is never active in production builds."

    return ""


def build_scan_result(
    scan_id:            str,
    apk_path:           str,
    all_module_results: dict,
    ai_summary:         str,
    scan_duration:      float,
    package_name:       str = "unknown",
) -> ScanResult:
    """
    Assembles the final ScanResult from module outputs, a computed risk score,
    generated remediation steps, and an AI-written summary.
    Returns a fully populated ScanResult ready for serialisation.
    """
    app_name   = Path(apk_path).stem if apk_path else "Unknown"
    risk_score, risk_level = calculate_risk_score(all_module_results)
    remediation            = generate_remediation(all_module_results)

    # Serialise ModuleResult objects to plain dicts for the findings field
    findings_dict = {}
    for module_name, module_result in all_module_results.items():
        if isinstance(module_result, ModuleResult):
            findings_dict[module_name] = module_result.model_dump()
        else:
            findings_dict[module_name] = module_result

    return ScanResult(
        scan_id       = scan_id,
        app_name      = app_name,
        package_name  = package_name,
        risk_score    = risk_score,
        risk_level    = risk_level,
        scan_duration = scan_duration,
        status        = "complete",
        findings      = findings_dict,
        ai_summary    = ai_summary,
        remediation   = remediation,
    )
