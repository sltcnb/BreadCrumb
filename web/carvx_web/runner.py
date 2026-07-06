"""Carvx subprocess orchestration: command building, live watching, cancel.

Runs the real carvx package from the repo root via `python -m carvx
--machine` and streams its JSON-lines events into persisted job progress.
Live process handles live here in memory; job metadata lives on disk.
"""

import json
import subprocess
import threading
from pathlib import Path

from . import config
from .jobs import load_job, now, save_job

# live process handles (in-memory only; job metadata lives on disk)
procs: dict[str, subprocess.Popen] = {}
_lock = threading.Lock()
_canceled: set[str] = set()


def get_supported_types() -> list[dict]:
    result = subprocess.run(
        [config.PYTHON, "-m", "carvx", "--list-types"],
        capture_output=True, text=True, cwd=config.REPO_ROOT, timeout=30)
    types = []
    for line in result.stdout.splitlines()[1:]:          # skip header
        parts = line.split()
        if parts:
            types.append({"name": parts[0],
                          "description": " ".join(parts[1:])})
    return types


def build_command(data: dict, source: str, output_dir: Path) -> list[str]:
    cmd = [config.PYTHON, "-m", "carvx", source,
           "-o", str(output_dir), "--machine"]
    mode = data.get("mode", "carve")
    flag = config.MODES.get(mode)
    if flag:
        cmd.append(flag)
    if mode in ("carve", "auto") and data.get("types"):
        cmd.extend(["-t", ",".join(data["types"])])
    for opt, flag in (("offset", "--offset"), ("length", "--length"),
                      ("align", "--align")):
        val = str(data.get(opt) or "").strip()
        if val and val != "0":
            cmd.extend([flag, val])
    if int(data.get("jobs") or 1) != 1:
        cmd.extend(["-j", str(int(data["jobs"]))])
    if data.get("validate"):
        cmd.append("--validate")
    if data.get("drop_failed"):
        cmd.append("--drop-failed")
    if data.get("dry_run"):
        cmd.append("--dry-run")
    if data.get("csv"):
        cmd.extend(["--csv", str(output_dir / "results.csv")])
    if data.get("html"):
        cmd.extend(["--html", str(output_dir / "report.html")])
    if data.get("timeline"):
        cmd.extend(["--timeline", str(output_dir / "timeline.csv")])
    return cmd


def start_job(job: dict, cmd: list[str], env: dict) -> None:
    proc = subprocess.Popen(cmd, cwd=config.REPO_ROOT, env=env, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    with _lock:
        procs[job["job_id"]] = proc
    threading.Thread(target=watch_job, args=(job["job_id"], proc),
                     daemon=True).start()


def watch_job(job_id: str, proc: subprocess.Popen) -> None:
    """Consume --machine JSON-lines from stdout, persist progress as we go."""
    job = load_job(job_id)
    stderr_buf = []
    t = threading.Thread(target=lambda: stderr_buf.append(proc.stderr.read()),
                         daemon=True)
    t.start()

    events_tail = []
    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except ValueError:
            events_tail.append(line)
            continue
        kind = ev.get("event")
        if kind == "progress":
            total = ev.get("total") or 0
            job["progress"] = {
                "done": ev.get("done", 0), "total": total,
                "percent": round(100 * ev.get("done", 0) / total, 1)
                           if total else None,
                "eta_s": ev.get("eta_s"), "rate_mibs": ev.get("rate_mibs"),
            }
            if "carved" in ev:
                job["carved"] = ev["carved"]
        elif kind == "carve":
            job["carved"] = job.get("carved", 0) + 1
        elif kind == "summary":
            job["summary"] = {k: v for k, v in ev.items() if k != "event"}
        save_job(job)

    proc.wait()
    t.join(timeout=10)
    canceled = job_id in _canceled
    _canceled.discard(job_id)
    job["returncode"] = proc.returncode
    job["error"] = (stderr_buf[0] if stderr_buf else "")[-20000:]
    job["output"] = "\n".join(events_tail)[-20000:]
    job["finished"] = now()
    if canceled:
        job["status"] = "canceled"
    else:
        job["status"] = "completed" if proc.returncode == 0 else "failed"
    if not job.get("carved"):
        # fs-undelete modes don't emit per-file events; count the output
        job["carved"] = len(collect_files(config.CARVED_DIR / job_id))
    if job.get("progress") and job["status"] == "completed":
        job["progress"]["percent"] = 100.0
    save_job(job)
    with _lock:
        procs.pop(job_id, None)


def cancel(job_id: str) -> bool:
    with _lock:
        proc = procs.get(job_id)
    if proc is None or proc.poll() is not None:
        return False
    _canceled.add(job_id)
    proc.terminate()
    return True


def is_running(job_id: str) -> bool:
    with _lock:
        proc = procs.get(job_id)
    return proc is not None and proc.poll() is None


def collect_files(output_dir: Path) -> list[dict]:
    """Carved files on disk, enriched from any manifest.json found."""
    meta = {}
    for mf in output_dir.rglob("manifest.json"):
        try:
            manifest = json.loads(mf.read_text())
        except ValueError:
            continue
        base = mf.parent
        for rec in manifest.get("files", []):
            if rec.get("path"):
                p = (base / rec["path"]).resolve()
                meta[str(p)] = rec

    files = []
    skip = {"manifest.json", "results.csv", "report.html", "timeline.csv"}
    for f in sorted(output_dir.rglob("*")):
        if not f.is_file() or f.name in skip:
            continue
        rel = f.relative_to(output_dir)
        rec = meta.get(str(f.resolve()), {})
        files.append({
            "path": str(rel), "name": f.name, "size": f.stat().st_size,
            "ext": (rec.get("ext") or f.suffix.lstrip(".") or "?").lower(),
            "offset": rec.get("offset"), "sha256": rec.get("sha256", ""),
            "confidence": rec.get("confidence", ""),
            "validated": rec.get("validated", False),
        })
    return files
