"""Job metadata store — one JSON file per job under data/jobs/."""

import json
from datetime import datetime, timezone
from pathlib import Path

from flask import abort

from . import config


def job_path(job_id: str) -> Path:
    return config.JOBS_DIR / f"{job_id}.json"


def load_job(job_id: str) -> dict | None:
    p = job_path(job_id)
    if not p.exists():
        return None
    with open(p) as fh:
        return json.load(fh)


def save_job(job: dict) -> None:
    p = job_path(job["job_id"])
    tmp = p.with_suffix(".tmp")
    with open(tmp, "w") as fh:
        json.dump(job, fh, indent=2)
    tmp.replace(p)


def valid_job_id(job_id: str) -> str:
    if not config.JOB_ID_RE.match(job_id or ""):
        abort(400, description="invalid job id")
    return job_id


def now() -> str:
    return datetime.now(timezone.utc).isoformat()
