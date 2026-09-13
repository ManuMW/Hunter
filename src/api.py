import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Dict, Any, Optional

from fastapi import FastAPI, UploadFile, File, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, JSONResponse
from pydantic import BaseModel

from src.config import REPORTS_DIR
from src.quarantine import quarantine_sample
from src.runner import is_docker_available
from src.queue import worker

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("[*] Starting Threat Research Detonation API...")
    await worker.start()
    yield
    # Shutdown
    logger.info("[*] Shutting down Detonation API...")
    await worker.stop()


app = FastAPI(
    title="Automated Threat Research & Detonation Pipeline",
    description="API for ingesting untrusted samples, running air-gapped sandbox detonations, extracting Velociraptor DFIR artifacts, and synthesizing threat intelligence reports.",
    version="0.1.0",
    lifespan=lifespan
)

# Enable CORS for browser access from GitHub Pages or local testing
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class SubmissionResponse(BaseModel):
    task_id: str
    sha256: str
    filename: str
    file_type: str
    size_bytes: int
    status: str
    message: str


class TaskStatusResponse(BaseModel):
    task_id: str
    sha256: str
    filename: Optional[str]
    status: str
    created_at: str
    completed_at: Optional[str]
    error: Optional[str]
    report_url: Optional[str]


@app.get("/health", tags=["System"])
def health_check():
    """System health check and Docker daemon status."""
    return {
        "status": "healthy",
        "docker_available": is_docker_available(),
        "queued_tasks": worker._queue.qsize()
    }


@app.post("/api/samples", response_model=SubmissionResponse, status_code=status.HTTP_202_ACCEPTED, tags=["Samples"])
async def submit_sample(file: UploadFile = File(...)):
    """
    Submits an untrusted binary or script for air-gapped detonation analysis.
    The file is stored securely in the Quarantine Store and enqueued for sequential processing.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename in upload.")
        
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
        
    # Check max file size (e.g., 50MB)
    if len(content) > 50 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File exceeds maximum allowed size of 50MB.")
        
    sample_meta = quarantine_sample(content, file.filename)
    task = worker.submit_sample(sample_meta)
    
    return SubmissionResponse(
        task_id=task.task_id,
        sha256=sample_meta["sha256"],
        filename=sample_meta["filename"],
        file_type=sample_meta["file_type"],
        size_bytes=sample_meta["size_bytes"],
        status=task.status,
        message="Sample successfully received, quarantined, and enqueued for detonation."
    )


@app.get("/api/tasks/{task_id}", response_model=TaskStatusResponse, tags=["Tasks"])
def get_task_status(task_id: str):
    """Retrieves real-time status of a sample detonation task."""
    task = worker.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task ID not found.")
        
    report_url = f"/api/reports/{task.sha256}" if task.status == "completed" else None
    
    return TaskStatusResponse(
        task_id=task.task_id,
        sha256=task.sha256,
        filename=task.sample_meta.get("filename"),
        status=task.status,
        created_at=task.created_at,
        completed_at=task.completed_at,
        error=task.error,
        report_url=report_url
    )


@app.get("/api/reports/{sha256}", tags=["Reports"])
def get_threat_report(sha256: str, format: str = "markdown"):
    """
    Retrieves the generated Threat Analysis Report for a sample.
    - format=markdown: Returns the raw Markdown report.
    - format=json: Returns structured JSON synthesis data.
    """
    report_file = REPORTS_DIR / f"{sha256}.md"
    if not report_file.exists():
        # Check if task exists and still in progress
        task = worker.get_task_by_sha256(sha256)
        if task and task.status != "completed":
            return JSONResponse(
                status_code=202,
                content={"status": task.status, "message": "Report generation still in progress."}
            )
        raise HTTPException(status_code=404, detail=f"No report found for SHA256 {sha256}.")

    if format == "json":
        task = worker.get_task_by_sha256(sha256)
        if task and task.synthesis:
            return task.synthesis

    content = report_file.read_text(encoding="utf-8")
    return PlainTextResponse(content=content, media_type="text/markdown")


@app.get("/api/reports", tags=["Reports"])
def list_reports() -> List[Dict[str, Any]]:
    """Lists all published threat intelligence reports."""
    reports = []
    for p in REPORTS_DIR.glob("*.md"):
        sha256 = p.stem
        reports.append({
            "sha256": sha256,
            "filename": p.name,
            "path": str(p),
            "size_bytes": p.stat().st_size
        })
    return reports
