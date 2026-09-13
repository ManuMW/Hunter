import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List

from src.runner import run_detonation
from src.triage import extract_triage_data
from src.ai_synthesis import synthesize_threat_report
from src.report_generator import generate_threat_report

logger = logging.getLogger(__name__)


class DetonationTask:
    def __init__(self, sample_meta: Dict[str, Any]):
        self.task_id = str(uuid.uuid4())
        self.sample_meta = sample_meta
        self.sha256 = sample_meta["sha256"]
        self.status = "queued"
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.completed_at: Optional[str] = None
        self.error: Optional[str] = None
        self.report_markdown: Optional[str] = None
        self.report_path: Optional[str] = None
        self.synthesis: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "sha256": self.sha256,
            "filename": self.sample_meta.get("filename"),
            "status": self.status,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "error": self.error,
            "report_path": self.report_path
        }


class DetonationWorker:
    def __init__(self):
        self._queue: asyncio.Queue[DetonationTask] = asyncio.Queue()
        self._tasks: Dict[str, DetonationTask] = {}
        self._sha256_to_task: Dict[str, str] = {}
        self._worker_task: Optional[asyncio.Task] = None
        self._running = False

    async def start(self):
        """Starts the sequential background worker loop."""
        if self._running:
            return
        self._running = True
        self._worker_task = asyncio.create_task(self._worker_loop())
        logger.info("[*] Detonation sequential worker loop started.")

    async def stop(self):
        """Stops the worker cleanly."""
        self._running = False
        if self._worker_task:
            self._worker_task.cancel()

    def submit_sample(self, sample_meta: Dict[str, Any]) -> DetonationTask:
        """Enqueues a sample for sequential processing."""
        task = DetonationTask(sample_meta)
        self._tasks[task.task_id] = task
        self._sha256_to_task[task.sha256] = task.task_id
        self._queue.put_nowait(task)
        logger.info(f"[*] Enqueued sample {task.sha256} with task ID: {task.task_id}")
        return task

    def get_task(self, task_id: str) -> Optional[DetonationTask]:
        return self._tasks.get(task_id)

    def get_task_by_sha256(self, sha256: str) -> Optional[DetonationTask]:
        task_id = self._sha256_to_task.get(sha256)
        return self._tasks.get(task_id) if task_id else None

    def list_tasks(self) -> List[Dict[str, Any]]:
        return [t.to_dict() for t in self._tasks.values()]

    async def _worker_loop(self):
        while self._running:
            task = await self._queue.get()
            try:
                logger.info(f"[*] Processing task {task.task_id} (SHA256: {task.sha256})")
                
                # Phase 1: Detonation in Docker
                task.status = "detonating"
                detonation_result = await asyncio.to_thread(
                    run_detonation,
                    sample_path=task.sample_meta["quarantine_path"],
                    sha256=task.sha256
                )
                
                # Phase 2: Triage Extraction
                task.status = "extracting_artifacts"
                triage_data = await asyncio.to_thread(
                    extract_triage_data,
                    output_dir=detonation_result["output_dir"]
                )
                
                # Phase 3: AI Synthesis
                task.status = "analyzing"
                synthesis = await asyncio.to_thread(
                    synthesize_threat_report,
                    sample_meta=task.sample_meta,
                    triage_data=triage_data
                )
                task.synthesis = synthesis.model_dump()
                
                # Phase 4: Report Generation
                task.status = "generating_report"
                report_md = await asyncio.to_thread(
                    generate_threat_report,
                    sample_meta=task.sample_meta,
                    triage_data=triage_data,
                    synthesis=synthesis
                )
                task.report_markdown = report_md
                task.report_path = f"reports/{task.sha256}.md"
                
                task.status = "completed"
                task.completed_at = datetime.now(timezone.utc).isoformat()
                logger.info(f"[+] Task {task.task_id} finished successfully. Report generated at {task.report_path}")

            except Exception as e:
                logger.error(f"[!] Task {task.task_id} failed: {e}", exc_info=True)
                task.status = "failed"
                task.error = str(e)
                task.completed_at = datetime.now(timezone.utc).isoformat()
            finally:
                self._queue.task_done()


# Global Singleton Worker Instance
worker = DetonationWorker()
