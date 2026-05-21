"""
summarizer.py — Generates an AI executive summary of APK scan findings using Groq.

Builds a condensed text representation of the scan results (to stay within token limits),
then asks Groq to write a 3-4 sentence executive summary. Returns a safe fallback string
if the API call fails — never raises.
"""

from groq import Groq

import config

_client   = Groq(api_key=config.GROQ_API_KEY)
_FALLBACK = "AI summary unavailable — review the individual findings sections below for details."

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def generate_summary(scan_result_dict: dict) -> str:
    """
    Accepts a scan result dict (the in-memory scan state) and returns a 3-4 sentence
    executive summary covering overall risk, critical issues, and recommendation.
    Returns a fallback string on any API failure.
    """
    condensed = _build_condensed_context(scan_result_dict)

    prompt = (
        "Analyze these Android APK scan findings. Respond with EXACTLY 5 lines using these prefixes:\n"
        "VERDICT: one sentence — overall risk level and whether the app is safe or dangerous\n"
        "CRITICAL: the single most dangerous finding and what an attacker can do with it\n"
        "EXPOSURE: what user data or device capabilities are at risk\n"
        "PATTERN: one interesting or unusual pattern in the findings (or 'No unusual patterns')\n"
        "ACTION: the first 2 things a developer must fix right now, separated by a comma\n\n"
        "Rules: each line must start with the prefix. No extra lines. No markdown. Be specific to this app.\n\n"
        f"Scan findings:\n{condensed}"
    )

    try:
        response = _client.chat.completions.create(
            model=config.GROQ_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a senior Android security engineer giving a real-time briefing. "
                        "Be direct, specific, and technical. Never say 'the application' — say 'this app'."
                    ),
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            max_tokens=350,
            temperature=0.25,
        )
        return response.choices[0].message.content.strip()
    except Exception as exc:
        return f"{_FALLBACK} (API error: {exc})"


def _build_condensed_context(scan_result_dict: dict) -> str:
    """
    Builds a compact text summary of the scan results.
    Includes app name, risk score, and up to 3 CRITICAL/HIGH findings per module.
    Keeps the total token count manageable.
    """
    lines = [
        f"App: {scan_result_dict.get('app_name', 'Unknown')}",
        f"Package: {scan_result_dict.get('package_name', 'unknown')}",
        f"Risk Score: {scan_result_dict.get('risk_score', 0)}/100",
        f"Risk Level: {scan_result_dict.get('risk_level', 'UNKNOWN')}",
        "",
    ]

    findings_dict = scan_result_dict.get("findings", {})
    for module_name, module_data in findings_dict.items():
        if isinstance(module_data, dict):
            module_severity = module_data.get("severity", "INFO")
            module_findings = module_data.get("findings", [])
        else:
            module_severity = getattr(module_data, "severity", "INFO")
            module_findings = getattr(module_data, "findings", [])

        lines.append(f"Module '{module_name}' — highest severity: {module_severity}")

        count = 0
        for finding in module_findings:
            if isinstance(finding, dict):
                sev   = finding.get("severity", "INFO")
                title = finding.get("title", "")
            else:
                sev   = finding.severity
                title = finding.title

            if sev in ("CRITICAL", "HIGH") and count < 3:
                lines.append(f"  [{sev}] {title}")
                count += 1

    return "\n".join(lines)
