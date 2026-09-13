import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Dict, Any, Optional

from fastapi import FastAPI, UploadFile, File, HTTPException, status, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, JSONResponse
from pydantic import BaseModel, Field

from src.config import REPORTS_DIR, CLIENT_DAILY_QUOTA
from src.quarantine import quarantine_sample
from src.runner import is_docker_available
from src.queue import worker
from src.malwarebazaar import (
    get_sample_info,
    download_sample_binary,
    MalwareBazaarUnavailableError,
    SampleNotFoundError,
    UnsupportedArchitectureError
)
from src.rate_limiter import (
    build_client_identifier,
    check_client_quota,
    consume_client_quota,
    verify_turnstile_token
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("[*] Starting Threat Research Detonation API...")
    await worker.start()
    yield
    logger.info("[*] Shutting down Detonation API...")
    await worker.stop()


app = FastAPI(
    title="Automated Threat Research & Detonation Pipeline",
    description="API for hash lookup in MalwareBazaar, air-gapped sandbox detonation, Velociraptor triage, and AI threat intelligence reporting.",
    version="0.2.0",
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


def get_real_client_ip(request: Request) -> str:
    """Extracts client IP, respecting proxy forwarding headers."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


class HashSubmissionRequest(BaseModel):
    sha256: str = Field(description="SHA-256 hash of the Linux malware sample to analyze")
    turnstile_token: Optional[str] = Field(default=None, description="Cloudflare Turnstile verification token")


class HashSubmissionResponse(BaseModel):
    status: str
    sha256: str
    task_id: Optional[str] = None
    filename: Optional[str] = None
    file_type: Optional[str] = None
    message: str
    report_url: Optional[str] = None
    daily_quota_remaining: int


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
    """System health check, queue status, and Docker daemon status."""
    return {
        "status": "healthy",
        "docker_available": is_docker_available(),
        "queued_tasks": worker._queue.qsize()
    }


@app.post("/api/submissions", response_model=HashSubmissionResponse, status_code=status.HTTP_202_ACCEPTED, tags=["Submissions"])
async def submit_hash(
    sub_req: HashSubmissionRequest,
    request: Request,
    x_client_id: Optional[str] = Header(None, alias="X-Client-ID")
):
    """
    Submits a SHA-256 hash for analysis.
    1. Validates Cloudflare Turnstile token (if enabled).
    2. Checks Report Cache (returns existing report instantly with 0 compute & 0 quota consumed).
    3. Checks In-Flight Tasks (joins active detonation run if already queued).
    4. Enforces 5 detonations/day quota per client.
    5. Queries MalwareBazaar, validates Linux threat, downloads encrypted binary, and enqueues detonation.
    """
    client_ip = get_real_client_ip(request)
    client_identifier = build_client_identifier(client_ip, x_client_id)
    sha256 = sub_req.sha256.strip().lower()

    # Step 1: Cloudflare Turnstile Check
    if not verify_turnstile_token(sub_req.turnstile_token, client_ip):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Bot verification failed (Cloudflare Turnstile invalid)."
        )

    # Step 2: Quota Pre-check
    is_allowed, used_count, remaining_quota = check_client_quota(client_identifier)

    # Step 3: Check Report Cache (Deduplication)
    report_file = REPORTS_DIR / f"{sha256}.md"
    if report_file.exists():
        logger.info(f"[*] Cache hit for hash {sha256}. Returning existing report.")
        return HashSubmissionResponse(
            status="cached",
            sha256=sha256,
            message="Threat Analysis Report already generated. Served directly from cache.",
            report_url=f"/api/reports/{sha256}",
            daily_quota_remaining=remaining_quota
        )

    # Step 4: Check In-Flight Task (Deduplication)
    existing_task = worker.get_task_by_sha256(sha256)
    if existing_task and existing_task.status not in ["completed", "failed"]:
        logger.info(f"[*] In-flight join for hash {sha256}. Task: {existing_task.task_id}")
        return HashSubmissionResponse(
            status=existing_task.status,
            sha256=sha256,
            task_id=existing_task.task_id,
            filename=existing_task.sample_meta.get("filename"),
            message="Detonation run is currently in progress for this sample.",
            daily_quota_remaining=remaining_quota
        )

    # Step 5: Enforce Daily Quota (Only applies to new detonations)
    if not is_allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Daily quota exceeded. You are limited to {CLIENT_DAILY_QUOTA} fresh sample detonations per calendar day (UTC)."
        )

    # Step 6: MalwareBazaar Pre-flight Check
    try:
        sample_info = get_sample_info(sha256)
    except SampleNotFoundError as snfe:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(snfe))
    except UnsupportedArchitectureError as uae:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(uae))
    except MalwareBazaarUnavailableError as mbue:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(mbue))
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))

    # Step 7: Download and Decrypt Sample Binary
    try:
        raw_binary = download_sample_binary(sha256)
    except MalwareBazaarUnavailableError as mbue:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(mbue))

    # Step 8: Store in Quarantine and Enqueue Detonation
    sample_meta = quarantine_sample(raw_binary, sample_info["filename"])
    task = worker.submit_sample(sample_meta)

    # Step 9: Consume 1 quota point
    new_used = consume_client_quota(client_identifier)
    new_remaining = max(0, CLIENT_DAILY_QUOTA - new_used)

    return HashSubmissionResponse(
        status=task.status,
        sha256=sha256,
        task_id=task.task_id,
        filename=sample_meta["filename"],
        file_type=sample_meta["file_type"],
        message="Sample verified, acquired from MalwareBazaar, and enqueued for air-gapped detonation.",
        daily_quota_remaining=new_remaining
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
    sha256 = sha256.strip().lower()
    report_file = REPORTS_DIR / f"{sha256}.md"
    if not report_file.exists():
        task = worker.get_task_by_sha256(sha256)
        if task and task.status not in ["completed", "failed"]:
            return JSONResponse(
                status_code=202,
                content={"status": task.status, "message": "Detonation and analysis still in progress."}
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
    """Lists all published threat intelligence reports in the Report Hub."""
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
