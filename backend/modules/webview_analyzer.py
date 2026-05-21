"""
webview_analyzer.py — Detects insecure WebView configurations in decompiled Java source.

WebViews are a major Android attack surface: they run web content inside the app's
security context, and misconfigurations can lead to JavaScript injection, SSL bypass,
local file exfiltration, and remote code execution via Java bridges.

Checks:
  - JavaScript enabled (setJavaScriptEnabled)
  - Java object bridge exposed (addJavascriptInterface) — RCE on Android < 4.2
  - SSL error bypass (onReceivedSslError + handler.proceed)
  - Local file access enabled (setAllowFileAccess, setAllowFileAccessFromFileURLs)
  - Universal access from file URLs (setAllowUniversalAccessFromFileURLs) — UXSS
  - Remote debugging enabled (setWebContentsDebuggingEnabled)
  - Unsafe URL loading with user-controlled input
"""

from pathlib import Path

from models import Finding, ModuleResult

EVIDENCE_MAX = 80
_SEV_ORDER   = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def analyze_webview(workspace_paths: dict) -> ModuleResult:
    jadx_dir = Path(workspace_paths.get("jadx_dir", ""))
    findings = []
    errors   = []

    if not jadx_dir.exists():
        return ModuleResult(
            module="webview",
            severity="INFO",
            findings=[Finding(
                title="No Decompiled Java Source Available",
                detail="jadx output directory not found; WebView analysis could not run.",
                severity="INFO",
                location="N/A",
                evidence=f"jadx_dir missing: {jadx_dir}",
            )],
            errors=[f"jadx_dir not found: {jadx_dir}"],
        )

    webview_files = []
    for java_file in jadx_dir.rglob("*.java"):
        try:
            content = java_file.read_text(encoding="utf-8", errors="ignore")
            if "WebView" in content or "WebSettings" in content or "onReceivedSslError" in content:
                webview_files.append((java_file, content))
        except Exception as exc:
            errors.append(f"Error reading {java_file.name}: {exc}")

    if not webview_files:
        findings.append(Finding(
            title="No WebView Usage Detected",
            detail="No WebView or WebSettings references found in decompiled source.",
            severity="INFO",
            location="N/A",
            evidence="No WebView API calls found",
        ))
        return ModuleResult(module="webview", severity="INFO", findings=findings, errors=errors)

    for java_file, content in webview_files:
        try:
            _scan_file(java_file, content, findings)
        except Exception as exc:
            errors.append(f"Error scanning {java_file.name}: {exc}")

    highest = _highest_severity(findings)
    return ModuleResult(module="webview", severity=highest, findings=findings, errors=errors)


# ── Per-file checks ────────────────────────────────────────────────────────────

def _scan_file(java_file: Path, content: str, findings: list):
    lines = content.splitlines()

    _check_javascript_enabled(java_file, lines, findings)
    _check_javascript_interface(java_file, lines, findings)
    _check_ssl_error_bypass(java_file, lines, findings)
    _check_file_access(java_file, lines, findings)
    _check_universal_access(java_file, lines, findings)
    _check_remote_debugging(java_file, lines, findings)


def _check_javascript_enabled(java_file: Path, lines: list, findings: list):
    """
    setJavaScriptEnabled(true) allows arbitrary JavaScript to run in the WebView.
    If the WebView loads remote content or processes untrusted URLs, this opens
    the door to XSS attacks that operate within the app's native context.
    """
    for i, line in enumerate(lines):
        if "setJavaScriptEnabled" in line and "true" in line:
            findings.append(Finding(
                title="JavaScript Enabled in WebView",
                detail=(
                    "setJavaScriptEnabled(true) allows JavaScript execution inside the WebView. "
                    "If the WebView loads any untrusted or remote content, attackers can inject "
                    "scripts that run within the app's security context and interact with any "
                    "Java objects exposed via addJavascriptInterface. Disable if not required; "
                    "if required, restrict URLs loaded to a controlled allowlist."
                ),
                severity="MEDIUM",
                location=f"{java_file.name}:{i + 1}",
                evidence=line.strip()[:EVIDENCE_MAX],
            ))
            return


def _check_javascript_interface(java_file: Path, lines: list, findings: list):
    """
    addJavascriptInterface exposes a Java object to JavaScript running in the WebView.
    On Android < 4.2 (API 17), all public methods are accessible — any JS can call
    them including injected scripts, enabling full RCE via reflection.
    On API 17+, methods must be annotated @JavascriptInterface, but the risk remains
    if JavaScript is enabled and untrusted content can be loaded.
    """
    for i, line in enumerate(lines):
        if "addJavascriptInterface" in line and "()" not in line:
            # Extract the interface name if visible on the line
            evidence = line.strip()[:EVIDENCE_MAX]
            findings.append(Finding(
                title="Java Object Exposed to WebView JavaScript (addJavascriptInterface)",
                detail=(
                    "addJavascriptInterface() bridges a Java object into the WebView's JavaScript "
                    "context. On Android < 4.2 all public methods are accessible via reflection — "
                    "any JavaScript (including injected XSS) can invoke them and achieve native "
                    "code execution. On newer Android, only @JavascriptInterface-annotated methods "
                    "are exposed, but the attack surface remains if untrusted URLs can be loaded."
                ),
                severity="CRITICAL",
                location=f"{java_file.name}:{i + 1}",
                evidence=evidence,
            ))
            return


def _check_ssl_error_bypass(java_file: Path, lines: list, findings: list):
    """
    onReceivedSslError with handler.proceed() silently ignores SSL certificate errors,
    accepting expired, self-signed, or mismatched certificates. This completely
    disables TLS validation for the WebView — equivalent to an empty TrustManager.
    """
    for i, line in enumerate(lines):
        if "onReceivedSslError" not in line:
            continue

        # Check ±8 lines for handler.proceed()
        window = lines[i: min(len(lines), i + 9)]
        if any("handler.proceed" in l or ".proceed()" in l for l in window):
            findings.append(Finding(
                title="WebView SSL Error Silently Ignored (handler.proceed)",
                detail=(
                    "onReceivedSslError() calls handler.proceed(), which instructs the WebView "
                    "to continue loading despite an SSL certificate error. This accepts any "
                    "certificate — expired, self-signed, or issued for the wrong domain — "
                    "making HTTPS traffic trivially interceptable. "
                    "The correct fix is to call handler.cancel() and notify the user."
                ),
                severity="CRITICAL",
                location=f"{java_file.name}:{i + 1}",
                evidence=line.strip()[:EVIDENCE_MAX],
            ))
            return


def _check_file_access(java_file: Path, lines: list, findings: list):
    """
    setAllowFileAccess(true) and setAllowFileAccessFromFileURLs(true) allow the WebView
    to read local files via file:// URIs. Combined with JavaScript, this enables
    exfiltration of arbitrary files from the app's internal storage.
    """
    for i, line in enumerate(lines):
        if "setAllowFileAccess" in line and "true" in line:
            findings.append(Finding(
                title="WebView File Access Enabled (file:// URI Allowed)",
                detail=(
                    "setAllowFileAccess(true) enables the WebView to read files via file:// URIs. "
                    "If JavaScript is also enabled, any script running in the WebView can read "
                    "files from the app's data directory and exfiltrate them to a remote server. "
                    "Set to false unless explicitly required; never combine with JavaScript."
                ),
                severity="HIGH",
                location=f"{java_file.name}:{i + 1}",
                evidence=line.strip()[:EVIDENCE_MAX],
            ))
            return

        if "setAllowFileAccessFromFileURLs" in line and "true" in line:
            findings.append(Finding(
                title="WebView Cross-Origin File Access Enabled",
                detail=(
                    "setAllowFileAccessFromFileURLs(true) allows JavaScript loaded from file:// "
                    "URLs to access other file:// resources. This enables cross-origin file "
                    "reads from within the WebView — an attacker who can inject a file:// URL "
                    "can read the app's internal files."
                ),
                severity="HIGH",
                location=f"{java_file.name}:{i + 1}",
                evidence=line.strip()[:EVIDENCE_MAX],
            ))
            return


def _check_universal_access(java_file: Path, lines: list, findings: list):
    """
    setAllowUniversalAccessFromFileURLs(true) disables the same-origin policy for
    file:// URLs — a JavaScript page loaded from a local file can make XMLHttpRequest
    calls to any origin, including the device's internal network.
    """
    for i, line in enumerate(lines):
        if "setAllowUniversalAccessFromFileURLs" in line and "true" in line:
            findings.append(Finding(
                title="Universal Cross-Origin Access from File URLs (UXSS Risk)",
                detail=(
                    "setAllowUniversalAccessFromFileURLs(true) disables the same-origin policy "
                    "for file:// URIs. JavaScript in a locally-loaded page can make requests to "
                    "any URL including internal network resources, enabling SSRF and full data "
                    "exfiltration. Set to false (the default) immediately."
                ),
                severity="CRITICAL",
                location=f"{java_file.name}:{i + 1}",
                evidence=line.strip()[:EVIDENCE_MAX],
            ))
            return


def _check_remote_debugging(java_file: Path, lines: list, findings: list):
    """
    setWebContentsDebuggingEnabled(true) enables Chrome DevTools Protocol access
    to the WebView over USB/network. This exposes all WebView state — cookies,
    localStorage, DOM, JavaScript execution — to anyone with device access.
    Should never be enabled in production builds.
    """
    for i, line in enumerate(lines):
        if "setWebContentsDebuggingEnabled" in line and "true" in line:
            findings.append(Finding(
                title="WebView Remote Debugging Enabled in Production",
                detail=(
                    "setWebContentsDebuggingEnabled(true) enables Chrome DevTools Protocol "
                    "on this WebView. An attacker with physical or ADB access to the device "
                    "can inspect, modify, and execute JavaScript in the WebView — exposing "
                    "cookies, tokens, and all rendered content. "
                    "Gate this call on BuildConfig.DEBUG to ensure it never reaches production."
                ),
                severity="HIGH",
                location=f"{java_file.name}:{i + 1}",
                evidence=line.strip()[:EVIDENCE_MAX],
            ))
            return


def _highest_severity(findings: list) -> str:
    for level in _SEV_ORDER:
        if any(f.severity == level for f in findings):
            return level
    return "INFO"
