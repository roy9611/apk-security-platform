# AppEX — Android Application Exposure Engine

A full-stack static analysis platform for Android APKs. Upload a binary, get a complete security report in under 60 seconds — vulnerabilities, hardcoded secrets, dangerous permissions, YARA pattern matches, and an AI analyst you can interrogate about the findings.

---

## The Problem

Manually auditing an Android APK means juggling apktool, jadx, grep commands, and your own knowledge of Android's security model. It takes hours and still misses things. AppEX automates the entire pipeline — decompilation, multi-vector analysis, risk scoring, and AI-assisted interpretation — into one terminal-style interface.

---

## What It Does

You drop an APK. AppEX:

1. **Unpacks it** using apktool (smali/manifest) and jadx (decompiled Java)
2. **Runs 7 detection modules** in parallel across the extracted output
3. **Scores the risk** from 0–100 using a weighted model (not a naive finding count)
4. **Generates an AI summary** via Groq — executive-level, not generic
5. **Opens a chat interface** where you can ask specific questions about the findings

---

## Detection Modules

| Module | What It Finds |
|---|---|
| **Manifest Analyzer** | `android:debuggable`, `allowBackup`, exported components with no permission guard, cleartext traffic enabled |
| **Permission Analyzer** | Dangerous permission combinations — `READ_SMS + INTERNET`, `RECORD_AUDIO + INTERNET`, `ACCESS_FINE_LOCATION + INTERNET` |
| **Secret Scanner** | Hardcoded AWS keys, GCP tokens, Stripe live keys, JWT secrets, private key blocks, Slack and GitHub tokens — 12 regex patterns + Shannon entropy check |
| **Firebase Checker** | Live HTTP probe against the app's Firebase Realtime Database URL — actually tests if the database is open, not just if the config exists |
| **SSL Checker** | Empty `checkServerTrusted` implementations, `HostnameVerifier` returning `true`, missing certificate pinning, cleartext URLs in source |
| **Storage Analyzer** | `MODE_WORLD_READABLE/WRITEABLE`, unencrypted SQLite databases, external storage misuse |
| **YARA Scanner** | 32 custom rules across 5 rulesets: manifest abuse, credential patterns, network bypass, insecure storage, and malware indicators (SMS exfiltration, accessibility service abuse, dynamic code loading) |

### Risk Scoring

The 0–100 score is weighted, not additive. YARA rule hits score at 1.5×. Confirmed credential exposure scores at 2.0×. High-entropy noise (near-misses on secret patterns) scores at 0.1× to avoid false inflation. Each module has a severity cap so one noisy module can't dominate the total.

---

## Interface

The frontend is a dense terminal dashboard — no cards, no gradients, no padding theater. Everything visible at once: module-by-module findings in the main panel, permission matrix and severity charts on the right, and the AI analyst at the bottom ready to answer questions like *"what can an attacker actually do with this?"* or *"how do I fix the exported content provider?"*

---

## Running Locally

### Requirements

```bash
# apktool and jadx must be on your PATH
sudo apt install apktool jadx        # Debian/Ubuntu
sudo dnf install apktool jadx        # Fedora

# YARA native library (required for yara-python)
sudo apt install gcc python3-dev yara-dev      # Debian/Ubuntu
sudo dnf install gcc python3-devel yara-devel  # Fedora
```

You also need a [Groq API key](https://console.groq.com) — free tier is sufficient.

### Backend

```bash
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# add your GROQ_API_KEY to .env

uvicorn main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
# runs at http://localhost:5173
```

---

## Stack

| | |
|---|---|
| Backend | Python 3.14, FastAPI, uvicorn |
| Analysis | apktool, jadx, YARA 4.5 |
| AI | Groq API — llama-3.3-70b-versatile |
| Frontend | React 18, Vite 5, JetBrains Mono |

---

## Changelog

**v1.3.0** — Cryptography and WebView analysis modules
- Cryptography analyzer: detects weak ciphers (DES, 3DES, RC4), ECB mode, static IVs, insecure random (java.util.Random), and broken hash algorithms (MD5, SHA-1)
- WebView analyzer: detects JavaScript enabled, Java bridge exposure (addJavascriptInterface), SSL error bypass, file:// access, universal cross-origin access (UXSS), and remote debugging in production
- Both modules wired into scoring engine with per-module caps and context bonuses
- Frontend updated: 11-step scan progress, 9-module sidebar, full report sections for new modules

**v1.2.0** — Terminal UI overhaul, project renamed AppEX
- Complete frontend redesign: dense terminal layout, JetBrains Mono, `#00ff88` accent system
- New component architecture: TitleBar, SectionBar, StatusBar, LeftSidebar, RightPanel
- AI analyst panel with boot sequence, contextual suggestion chips, scan-aware chat
- Animated risk score counter, 9-module scan progress timeline

**v1.1.0** — YARA engine + smart scoring
- YARA scanner: 32 compiled rules across 5 rulesets wired into the scan pipeline
- Risk scoring rewrite: per-module caps, finding-type multipliers, entropy-noise suppression
- YARA deduplication by `(rule, file_stem)` — credential rules always reported in full

**v1.0.0** — Initial release
- 6-module static analysis pipeline
- FastAPI backend with async scan queue
- Groq AI: risk summary, per-finding explanations, interactive chat
- React frontend with live scan progress

---

## License

MIT
