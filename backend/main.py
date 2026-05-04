"""
ReversAI — Main FastAPI Server
AI-powered automated reverse engineering tool.
"""

import os
import sys
import uuid
import time
import json
import asyncio
import traceback
from pathlib import Path

from fastapi import FastAPI, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.config import Config
from backend.models.schemas import FileType, AnalysisReport
from backend.analyzers.file_detector import analyze_file
from backend.analyzers.string_analyzer import analyze_strings
from backend.analyzers.binary_analyzer import analyze_binary
from backend.analyzers.security_checker import check_security
from backend.analyzers.disassembler import disassemble
from backend.analyzers.decompiler import decompile_functions
from backend.analyzers.script_analyzer import analyze_script
from backend.ai.ai_engine import run_ai_analysis, convert_ai_findings
from backend.ai.prompts import build_analysis_prompt, build_script_analysis_prompt
from backend.ai.report_generator import compile_report


app = FastAPI(title="ReversAI", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Store active sessions and their progress
sessions = {}
progress_connections: dict[str, WebSocket] = {}


async def send_progress(session_id: str, step: str, detail: str, progress: int):
    """Send progress update via WebSocket."""
    if session_id in progress_connections:
        try:
            await progress_connections[session_id].send_json({
                "step": step,
                "detail": detail,
                "progress": progress,
            })
        except Exception:
            pass
    # Also store in session
    if session_id in sessions:
        sessions[session_id]["progress"] = {
            "step": step, "detail": detail, "progress": progress
        }


async def run_analysis_pipeline(session_id: str, filepath: str, filename: str):
    """Run the full analysis pipeline."""
    start_time = time.time()
    errors = []

    try:
        # Step 1: File Detection
        await send_progress(session_id, "detecting", "Detecting file type & computing hashes...", 5)
        file_info = analyze_file(filepath)
        await send_progress(session_id, "detected",
            f"Detected: {file_info.file_type.value.upper()} | {file_info.architecture}", 10)
        await asyncio.sleep(0.3)

        # Step 2: String Extraction
        await send_progress(session_id, "strings", "Extracting and classifying strings...", 15)
        strings = analyze_strings(filepath)
        interesting = len([s for s in strings if s.category != 'other'])
        await send_progress(session_id, "strings_done",
            f"Found {len(strings)} strings ({interesting} interesting)", 25)
        await asyncio.sleep(0.3)

        # Step 3: Binary Analysis / Script Analysis
        imports = []
        static_findings = []
        binary_result = {}

        if file_info.file_type in (FileType.PE, FileType.ELF, FileType.MACHO):
            # Binary analysis
            await send_progress(session_id, "binary", "Analyzing binary structure...", 30)
            binary_result = analyze_binary(filepath, file_info.file_type)
            imports = binary_result.get("imports", [])
            dangerous = len([i for i in imports if hasattr(i, 'is_dangerous') and i.is_dangerous])
            await send_progress(session_id, "binary_done",
                f"Analyzed {len(imports)} imports ({dangerous} dangerous)", 40)
            await asyncio.sleep(0.3)

            # Step 4: Security Checks
            await send_progress(session_id, "security", "Checking security mitigations...", 45)
            security_checks = check_security(filepath, file_info.file_type)
            disabled = len([c for c in security_checks if c.status in ("disabled", "violated")])
            await send_progress(session_id, "security_done",
                f"Checked {len(security_checks)} mitigations ({disabled} issues)", 55)
            await asyncio.sleep(0.3)

            # Step 5: Disassembly
            await send_progress(session_id, "disasm", "Disassembling binary functions...", 60)
            functions = disassemble(filepath, Config.MAX_FUNCTIONS_TO_DECOMPILE)
            await send_progress(session_id, "disasm_done",
                f"Disassembled {len(functions)} functions", 70)
            await asyncio.sleep(0.3)

            # Step 6: Decompilation
            await send_progress(session_id, "decompile", "Decompiling key functions...", 75)
            functions = decompile_functions(filepath, functions)
            decompiled_count = len([f for f in functions if f.decompiled])
            await send_progress(session_id, "decompile_done",
                f"Decompiled {decompiled_count} functions", 80)
            await asyncio.sleep(0.3)

        elif file_info.file_type in (FileType.PYTHON, FileType.SCRIPT):
            # Source code analysis
            await send_progress(session_id, "script", "Analyzing source code...", 40)
            static_findings = analyze_script(filepath, file_info.file_type.value)
            await send_progress(session_id, "script_done",
                f"Found {len(static_findings)} issues in source", 60)
            security_checks = []
            functions = []
            await asyncio.sleep(0.3)
        else:
            security_checks = []
            functions = []
            await send_progress(session_id, "basic", "Performing basic analysis...", 60)

        # Step 7: AI Analysis
        await send_progress(session_id, "ai", "Running AI security analysis...", 85)

        if Config.has_ai_key():
            # Build prompt based on file type
            if file_info.file_type in (FileType.PYTHON, FileType.SCRIPT):
                try:
                    with open(filepath, 'r', errors='ignore') as f:
                        source = f.read()[:15000]
                except Exception:
                    source = ""
                findings_text = "\n".join([f"- [{f.severity.value}] {f.title}: {f.description}" for f in static_findings])
                prompt = build_script_analysis_prompt(source, filename, findings_text)
            else:
                # Build comprehensive prompt for binaries
                sec_text = "\n".join([f"- {c.name}: {c.status} ({c.severity.value})" for c in security_checks])
                imp_text = "\n".join([
                    f"- {'⚠️ ' if i.is_dangerous else ''}{i.library}::{i.function}{' — ' + i.risk_note if i.risk_note else ''}"
                    for i in imports[:100]
                ])
                str_text = "\n".join([f"- [{s.category}] {s.value[:100]}" for s in strings if s.category != 'other'][:50])
                decomp_text = "\n\n".join([
                    f"### {f.name} (0x{f.address:x}, {f.size} bytes)\n```c\n{f.decompiled[:3000]}\n```"
                    for f in functions if f.decompiled
                ][:10])
                disasm_text = f"{len(functions)} functions analyzed"

                import dataclasses
                fi_dict = {f.name: getattr(file_info, f.name)
                          for f in dataclasses.fields(file_info)}
                fi_dict['file_type'] = fi_dict['file_type'].value

                prompt = build_analysis_prompt(fi_dict, str_text, sec_text, imp_text, decomp_text, disasm_text)

            ai_result = await run_ai_analysis(prompt)
            ai_findings, ai_summary, ai_risk_score = convert_ai_findings(ai_result)
            await send_progress(session_id, "ai_done",
                f"AI found {len(ai_findings)} additional findings", 95)
        else:
            ai_findings, ai_summary, ai_risk_score = [], "No AI API key configured.", 0
            await send_progress(session_id, "ai_skip",
                "AI analysis skipped — no API key configured", 95)

        # Step 8: Compile Report
        await send_progress(session_id, "report", "Compiling final report...", 98)
        duration = time.time() - start_time

        report = compile_report(
            session_id=session_id,
            file_info=file_info,
            strings=strings,
            functions=functions,
            security_checks=security_checks,
            imports=imports,
            static_findings=static_findings,
            ai_findings=ai_findings,
            ai_summary=ai_summary,
            ai_risk_score=ai_risk_score,
            duration=duration,
        )
        report.errors = errors

        # Store report
        sessions[session_id]["report"] = report.to_dict()
        sessions[session_id]["status"] = "complete"

        await send_progress(session_id, "complete",
            f"Analysis complete! Found {len(report.findings)} findings in {duration:.1f}s", 100)

    except Exception as e:
        error_msg = f"Pipeline error: {str(e)}\n{traceback.format_exc()}"
        sessions[session_id]["status"] = "error"
        sessions[session_id]["error"] = error_msg
        await send_progress(session_id, "error", str(e), -1)
    finally:
        # Cleanup uploaded file
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
        except Exception:
            pass


@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...)):
    """Upload a file for analysis."""
    # Validate file size
    content = await file.read()
    if len(content) > Config.MAX_FILE_SIZE_BYTES:
        return JSONResponse(
            status_code=413,
            content={"error": f"File too large. Max size: {Config.MAX_FILE_SIZE_MB}MB"}
        )

    # Save file
    session_id = str(uuid.uuid4())[:8]
    os.makedirs(Config.UPLOAD_DIR, exist_ok=True)
    filepath = os.path.join(Config.UPLOAD_DIR, f"{session_id}_{file.filename}")

    with open(filepath, 'wb') as f:
        f.write(content)

    # Initialize session
    sessions[session_id] = {
        "status": "analyzing",
        "filename": file.filename,
        "progress": {"step": "queued", "detail": "Starting analysis...", "progress": 0},
        "report": None,
        "error": None,
    }

    # Start analysis in background
    asyncio.create_task(run_analysis_pipeline(session_id, filepath, file.filename))

    return {"session_id": session_id, "status": "analyzing"}


@app.get("/api/report/{session_id}")
async def get_report(session_id: str):
    """Get analysis report."""
    if session_id not in sessions:
        return JSONResponse(status_code=404, content={"error": "Session not found"})

    session = sessions[session_id]
    return {
        "status": session["status"],
        "filename": session["filename"],
        "progress": session["progress"],
        "report": session["report"],
        "error": session["error"],
    }


@app.websocket("/ws/progress/{session_id}")
async def websocket_progress(websocket: WebSocket, session_id: str):
    """WebSocket endpoint for real-time progress updates."""
    await websocket.accept()
    progress_connections[session_id] = websocket

    try:
        while True:
            # Keep connection alive, wait for messages
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=1.0)
            except asyncio.TimeoutError:
                # Send current progress
                if session_id in sessions:
                    session = sessions[session_id]
                    await websocket.send_json({
                        "step": session["progress"]["step"],
                        "detail": session["progress"]["detail"],
                        "progress": session["progress"]["progress"],
                        "status": session["status"],
                    })
                    if session["status"] in ("complete", "error"):
                        await asyncio.sleep(0.5)
                        break
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        progress_connections.pop(session_id, None)


@app.get("/api/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "ok",
        "ai_configured": Config.has_ai_key(),
        "ai_provider": Config.get_active_provider(),
        "radare2": bool(__import__('shutil').which('radare2') or __import__('shutil').which('r2')),
    }


# Serve frontend
frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.isdir(frontend_dir):
    app.mount("/assets", StaticFiles(directory=os.path.join(frontend_dir, "assets")), name="assets")

    @app.get("/")
    async def serve_index():
        return FileResponse(os.path.join(frontend_dir, "index.html"))

    @app.get("/style.css")
    async def serve_css():
        return FileResponse(os.path.join(frontend_dir, "style.css"))

    @app.get("/app.js")
    async def serve_js():
        return FileResponse(os.path.join(frontend_dir, "app.js"))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host=Config.HOST, port=Config.PORT, reload=True)
