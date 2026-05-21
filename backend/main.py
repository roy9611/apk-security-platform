"""
main.py — FastAPI application for the APK Security Intelligence Platform.

Endpoints:
  GET  /api/health            — liveness check
  POST /api/scan              — upload APK, start background scan, return scan_id
  GET  /api/scan/{scan_id}    — poll scan status and current module
  GET  /api/report/{scan_id}  — fetch completed scan result
  POST /api/chat              — AI chat about a completed scan
"""

import time
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

import config
from models import ChatRequest, ChatResponse, ScanStatus
from modules.unpacker import APKUnpacker
from modules.manifest_analyzer import analyze_manifest
from modules.permission_analyzer import analyze_permissions
from modules.secret_scanner import analyze_secrets
from modules.firebase_checker import check_firebase
from modules.ssl_checker import analyze_ssl
from modules.storage_analyzer import analyze_storage
from modules.yara_scanner import analyze_yara
from modules.crypto_analyzer import analyze_crypto
from modules.webview_analyzer import analyze_webview
from modules.report_engine import calculate_risk_score, generate_remediation
from ai.summarizer import generate_summary
from ai.chat import chat_with_context


app = FastAPI(title=config.APP_NAME, version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        config.FRONTEND_URL,
        "http://localhost:5173",
        "http://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory scan store: scan_id -> scan state dict
# Each entry is a plain dict so it serialises directly to JSON in responses.
scans: dict = {}


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/api/health")
def health_check():
    """Returns application name, status, and version."""
    return {
        "app_name": config.APP_NAME,
        "status":   "ok",
        "version":  "1.0.0",
    }


@app.post("/api/scan")
async def start_scan(file: UploadFile, background_tasks: BackgroundTasks):
    """
    Accepts a multipart APK file upload.
    Validates the extension, saves the file, initialises scan state,
    and queues the background scan task.
    Returns scan_id and status immediately — the client should poll /api/scan/{id}.
    """
    if not file.filename or not file.filename.lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="Only .apk files are accepted.")

    # Read and size-check before saving
    contents = await file.read()
    if len(contents) > config.MAX_APK_SIZE_BYTES:
        raise HTTPException(
            status_code=400,
            detail=f"File exceeds the {config.MAX_APK_SIZE_MB} MB size limit.",
        )

    scan_id   = str(uuid.uuid4())[:8]
    upload_dir = config.WORKSPACE_DIR / scan_id / "upload"
    upload_dir.mkdir(parents=True, exist_ok=True)

    apk_path = upload_dir / file.filename
    apk_path.write_bytes(contents)

    # Initialise scan state
    scans[scan_id] = {
        "scan_id":        scan_id,
        "status":         ScanStatus.QUEUED,
        "app_name":       file.filename.replace(".apk", ""),
        "package_name":   "unknown",
        "current_module": None,
        "findings":       {},
        "risk_score":     0,
        "risk_level":     "INFO",
        "ai_summary":     "",
        "remediation":    [],
        "scan_duration":  0.0,
        "error_message":  "",
    }

    background_tasks.add_task(run_scan, scan_id, str(apk_path))

    return {
        "scan_id": scan_id,
        "status":  ScanStatus.QUEUED,
        "message": "Scan queued successfully.",
    }


@app.get("/api/scan/{scan_id}")
def get_scan_status(scan_id: str):
    """
    Returns the current scan state dict.
    The current_module field is set while the scan is running so the frontend
    can display live per-module progress.
    """
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scans[scan_id]


@app.get("/api/report/{scan_id}")
def get_report(scan_id: str):
    """
    Returns the full completed scan result.
    Returns 400 if the scan has not finished yet.
    """
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found.")

    scan_state = scans[scan_id]
    status     = scan_state.get("status")

    if status not in (ScanStatus.COMPLETE, "complete"):
        raise HTTPException(
            status_code=400,
            detail=f"Scan is not complete yet. Current status: {status}",
        )

    return scan_state


@app.post("/api/chat", response_model=ChatResponse)
def chat(request: ChatRequest):
    """
    Accepts a question from the user and returns an AI response grounded in
    the specified scan's results.
    """
    if request.scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found.")

    scan_state = scans[request.scan_id]
    if scan_state.get("status") not in (ScanStatus.COMPLETE, "complete"):
        raise HTTPException(
            status_code=400,
            detail="The scan must be complete before you can chat about it.",
        )

    response_text = chat_with_context(request.message, scan_state)
    return ChatResponse(response=response_text, scan_id=request.scan_id)


# ── Background scan task ───────────────────────────────────────────────────────

def run_scan(scan_id: str, apk_path: str):
    """
    Runs all analysis modules in sequence and assembles the final report.

    Updates scans[scan_id] in-place as each module completes so the frontend
    can show live progress via the current_module field.

    Individual module failures are captured and stored — they do not abort the scan.
    Only a failure in the unpacking step (which all other modules depend on)
    will mark the overall scan as FAILED.
    """
    start_time = time.time()
    scan_state = scans[scan_id]
    scan_state["status"] = ScanStatus.RUNNING

    workspace_paths = {}

    try:
        # ── Step 1: Unpack APK ─────────────────────────────────────────────────
        scan_state["current_module"] = "unpacking"
        unpacker        = APKUnpacker(apk_path, scan_id)
        workspace_paths = unpacker.unpack()

        if workspace_paths.get("errors"):
            # Unpack errors are non-fatal — log them but continue
            scan_state["error_message"] = "; ".join(workspace_paths["errors"])

        # Extract package name from decoded manifest
        try:
            manifest_path = Path(workspace_paths["apktool_dir"]) / "AndroidManifest.xml"
            if manifest_path.exists():
                root = ET.parse(manifest_path).getroot()
                scan_state["package_name"] = root.get("package", "unknown")
        except Exception:
            pass  # Package name is cosmetic — not worth failing the scan

        # ── Step 2: Run all 6 analysis modules ────────────────────────────────
        modules = [
            ("manifest",    analyze_manifest),
            ("permissions", analyze_permissions),
            ("secrets",     analyze_secrets),
            ("firebase",    check_firebase),
            ("ssl",         analyze_ssl),
            ("storage",     analyze_storage),
            ("yara",        analyze_yara),
            ("crypto",      analyze_crypto),
            ("webview",     analyze_webview),
        ]

        for module_key, module_func in modules:
            scan_state["current_module"] = module_key
            try:
                result = module_func(workspace_paths)
                scan_state["findings"][module_key] = result.model_dump()
            except Exception as exc:
                # Store a minimal error result so the frontend can show the module failed
                scan_state["findings"][module_key] = {
                    "module":   module_key,
                    "severity": "INFO",
                    "findings": [],
                    "errors":   [f"Module crashed: {exc}"],
                }

        # ── Step 3: Risk score and remediation ────────────────────────────────
        scan_state["current_module"] = "reporting"
        score, level = calculate_risk_score(scan_state["findings"])
        scan_state["risk_score"]  = score
        scan_state["risk_level"]  = level
        scan_state["remediation"] = generate_remediation(scan_state["findings"])

        # ── Step 4: AI summary ────────────────────────────────────────────────
        scan_state["current_module"] = "ai_summary"
        scan_state["ai_summary"]     = generate_summary(scan_state)

        # ── Step 5: Finalise ──────────────────────────────────────────────────
        scan_state["app_name"]      = Path(apk_path).stem
        scan_state["scan_duration"] = round(time.time() - start_time, 2)
        scan_state["status"]        = ScanStatus.COMPLETE
        scan_state["current_module"] = None

    except Exception as exc:
        scan_state["status"]        = ScanStatus.FAILED
        scan_state["error_message"] = str(exc)
        scan_state["current_module"] = None
        scan_state["scan_duration"] = round(time.time() - start_time, 2)
