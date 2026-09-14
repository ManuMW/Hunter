import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List

from src.runner import run_detonation
from src.triage import extract_triage_data
from src.ai_synthesis import synthesize_threat_report
from src.report_generator import generate_threat_report

logger = logging.getLogger(__name__)


def synthesis_to_report_dict(
    sha256: str,
    filename: str,
    synthesis: Dict[str, Any],
    triage_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    score = synthesis.get("threat_severity_score", 7)
    classification = synthesis.get("threat_classification", "MALWARE").upper()
    family = synthesis.get("malware_family", "Generic")
    severity = "CRITICAL" if score >= 8 else "HIGH" if score >= 6 else "MEDIUM"

    mitre_list = [
        {"id": t.get("technique_id", ""), "name": t.get("technique_name", ""), "tactic": t.get("tactic", "")}
        for t in synthesis.get("mitre_attack_techniques", [])
    ]
    ioc_list = [
        {"type": i.get("type", "indicator"), "value": i.get("value", ""), "description": i.get("description", "")}
        for i in synthesis.get("indicators_of_compromise", [])
    ]
    process_tree = []
    dropped_payloads = []
    if triage_data:
        for p in triage_data.get("spawned_processes", []):
            process_tree.append(f"PID {p.get('pid', '?')}: {p.get('command', '')}")
        for d in triage_data.get("dropped_files", []):
            dropped_payloads.append({
                "path": d.get("path", ""),
                "size": str(d.get("size", "")),
                "magic": d.get("permissions", ""),
                "strings": []
            })
    if not process_tree:
        for b in synthesis.get("observed_behaviors", []):
            process_tree.append(f"{b.get('category', 'Behavior')}: {b.get('evidence', '')}")

    return {
        "id": sha256,
        "sha256": sha256,
        "title": f"Threat Analysis Report: {filename} ({family})",
        "family": family,
        "category": classification,
        "severity": severity,
        "severityScore": f"{score}/10",
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "author": "Hunter Research Team",
        "readTime": "4 min read",
        "summary": synthesis.get("executive_summary", ""),
        "tags": [classification, family.upper(), f"SEVERITY_{score}"],
        "mitre": mitre_list,
        "iocs": ioc_list,
        "behavior": {
            "processTree": process_tree or ["Analysis completed."],
            "droppedPayloads": dropped_payloads
        },
        "yaraRule": synthesis.get("yara_rule_candidate", "")
    }


def append_to_catalog(report_dict: Dict[str, Any]):
    """Appends newly detonated report to data/reports.js and web/data/reports.js."""
    for file_path in [Path("data/reports.js"), Path("web/data/reports.js")]:
        if not file_path.exists():
            continue
        try:
            content = file_path.read_text(encoding="utf-8")
            if report_dict["sha256"] in content:
                continue
            prefix = "const THREAT_REPORTS = [\n"
            idx = content.find(prefix)
            if idx != -1:
                json_str = json.dumps(report_dict, indent=4)
                indented = "\n".join("    " + line for line in json_str.splitlines()) + ",\n"
                new_content = content[:idx + len(prefix)] + indented + content[idx + len(prefix):]
                file_path.write_text(new_content, encoding="utf-8")
                logger.info(f"[+] Appended report {report_dict['sha256']} to {file_path}")
        except Exception as e:
            logger.warning(f"Failed to append report to {file_path}: {e}")


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
        self.report_data: Optional[Dict[str, Any]] = None

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
                
                # Phase 1: Detonation in Docker (or Static Decomposition fallback)
                task.status = "detonating"
                detonation_result = await asyncio.to_thread(
                    run_detonation,
                    sample_path=task.sample_meta["quarantine_path"],
                    sha256=task.sha256,
                    raw_bytes=task.sample_meta.get("raw_bytes")
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
                from src.config import REPORTS_DIR
                report_path = REPORTS_DIR / f"{task.sha256}.md"
                report_path.write_text(report_md, encoding="utf-8")
                task.report_path = str(report_path)
                
                # Format catalog report and append to web catalogs
                report_dict = synthesis_to_report_dict(
                    sha256=task.sha256,
                    filename=task.sample_meta.get("filename", "sample"),
                    synthesis=task.synthesis,
                    triage_data=triage_data
                )
                task.report_data = report_dict
                append_to_catalog(report_dict)
                
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
