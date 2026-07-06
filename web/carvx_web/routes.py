"""HTTP routes — all endpoints registered on a single blueprint."""

import json
import os
import shutil
import tempfile
import uuid
import zipfile
from pathlib import Path

from flask import (Blueprint, abort, jsonify, render_template, request,
                   send_file, send_from_directory)
from werkzeug.utils import secure_filename

from . import config, runner
from .jobs import job_path, load_job, now, save_job, valid_job_id

bp = Blueprint("carvx", __name__)


# ---------------------------------------------------------------- helpers

def allowed_file(filename: str) -> bool:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    return ext in config.ALLOWED_EXTENSIONS or bool(config.SEGMENT_RE.match(ext))


def _primary_segment(paths: list[Path]) -> Path:
    """First segment of a (possibly split) image: .e01/.001 before .e02/.002."""
    return sorted(paths, key=lambda p: p.name.lower())[0]


# ---------------------------------------------------------------- routes

@bp.route("/")
def index():
    return render_template("index.html",
                           job_id=str(uuid.uuid4()),
                           types=runner.get_supported_types())


@bp.route("/upload", methods=["POST"])
def upload_file():
    files = [f for f in request.files.getlist("file") if f.filename]
    if not files:
        return jsonify({"error": "No file provided"}), 400
    for f in files:
        if not allowed_file(f.filename):
            return jsonify({"error": f"File type not allowed: {f.filename}. "
                            f"Allowed: {', '.join(sorted(config.ALLOWED_EXTENSIONS))} "
                            "and split segments (.001, .e02, ...)"}), 400

    job_id = valid_job_id(request.form.get("job_id") or str(uuid.uuid4()))
    job_dir = config.UPLOAD_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)

    saved = []
    for f in files:
        dest = job_dir / secure_filename(f.filename)
        f.save(dest)
        saved.append(dest)

    primary = _primary_segment(list(job_dir.iterdir()))
    job = load_job(job_id) or {"job_id": job_id}
    job.update(source=str(primary), status="uploaded",
               files=[p.name for p in job_dir.iterdir()])
    save_job(job)
    return jsonify({"success": True, "job_id": job_id,
                    "filename": primary.name,
                    "size": sum(p.stat().st_size for p in saved)})


@bp.route("/upload/path", methods=["POST"])
def upload_path():
    data = request.get_json(silent=True) or {}
    filepath = data.get("path", "")
    job_id = valid_job_id(data.get("job_id") or str(uuid.uuid4()))
    if not filepath:
        return jsonify({"error": "No path provided"}), 400

    path = Path(filepath).expanduser()
    if not path.is_file():
        return jsonify({"error": f"Not a readable file: {path}"}), 404
    if not allowed_file(path.name):
        return jsonify({"error": f"File type not allowed. Allowed: "
                        f"{', '.join(sorted(config.ALLOWED_EXTENSIONS))}"}), 400

    # reference in place — a disk image can be 50 GB, never copy it
    job = load_job(job_id) or {"job_id": job_id}
    job.update(source=str(path.resolve()), status="uploaded",
               files=[path.name])
    save_job(job)
    return jsonify({"success": True, "job_id": job_id,
                    "filename": path.name, "size": path.stat().st_size})


@bp.route("/run", methods=["POST"])
def run_carvx():
    data = request.get_json(silent=True) or {}
    job_id = valid_job_id(data.get("job_id", ""))
    job = load_job(job_id)
    if job is None or not job.get("source"):
        return jsonify({"error": "No file uploaded for this job"}), 404
    if job.get("status") == "running":
        return jsonify({"error": "Job already running"}), 409
    if not Path(job["source"]).exists():
        return jsonify({"error": f"Source vanished: {job['source']}"}), 410

    output_dir = config.CARVED_DIR / job_id
    output_dir.mkdir(parents=True, exist_ok=True)
    cmd = runner.build_command(data, job["source"], output_dir)

    # BitLocker credentials go through the environment (CARVX_BITLOCKER),
    # never through argv, so they are not visible in `ps` or job records.
    env = os.environ.copy()
    creds = {}
    if data.get("bitlocker_recovery_key"):
        creds["recovery"] = data["bitlocker_recovery_key"]
    if data.get("bitlocker_password"):
        creds["password"] = data["bitlocker_password"]
    if creds:
        env["CARVX_BITLOCKER"] = json.dumps(creds)

    job.update(status="running", mode=data.get("mode", "carve"),
               command=" ".join(c for c in cmd), started=now(),
               finished=None, returncode=None, output="", error="",
               progress=None, carved=0, bitlocker=bool(creds))
    save_job(job)

    runner.start_job(job, cmd, env)
    return jsonify({"success": True, "job_id": job_id, "status": "running"})


@bp.route("/cancel/<job_id>", methods=["POST"])
def cancel_job(job_id):
    valid_job_id(job_id)
    if not runner.cancel(job_id):
        return jsonify({"error": "Job not running"}), 409
    return jsonify({"success": True, "status": "canceling"})


@bp.route("/status/<job_id>")
def job_status(job_id):
    valid_job_id(job_id)
    job = load_job(job_id)
    if job is None:
        return jsonify({"error": "Job not found"}), 404
    result = {k: job.get(k) for k in
              ("job_id", "status", "started", "finished", "progress",
               "carved", "summary", "mode")}
    if job.get("status") in ("completed", "failed", "canceled"):
        result["output"] = job.get("output", "")
        result["error"] = job.get("error", "")
        result["returncode"] = job.get("returncode")
    return jsonify(result)


@bp.route("/results/<job_id>")
def results(job_id):
    valid_job_id(job_id)
    output_dir = config.CARVED_DIR / job_id
    if not output_dir.exists():
        abort(404, description="No results found")

    manifest = None
    mf = output_dir / "manifest.json"
    if mf.exists():
        try:
            manifest = json.loads(mf.read_text())
        except ValueError:
            pass

    files = runner.collect_files(output_dir)
    limit = min(int(request.args.get("limit", 200)), 2000)
    reports = [n for n in ("report.html", "results.csv", "timeline.csv")
               if (output_dir / n).exists()]
    return render_template("results.html", job_id=job_id, manifest=manifest,
                           files=files[:limit], total_files=len(files),
                           reports=reports)


@bp.route("/download/<job_id>/<path:filename>")
def download_file(job_id, filename):
    valid_job_id(job_id)
    # send_from_directory refuses paths that escape output_dir
    return send_from_directory(config.CARVED_DIR / job_id, filename,
                               as_attachment=True)


@bp.route("/view/<job_id>/<path:filename>")
def view_file(job_id, filename):
    """Inline display, images only — carved HTML/SVG must never render
    from this origin."""
    valid_job_id(job_id)
    if Path(filename).suffix.lower() not in config.INLINE_EXTS:
        abort(403, description="Inline view is limited to images")
    return send_from_directory(config.CARVED_DIR / job_id, filename)


@bp.route("/download-manifest/<job_id>")
def download_manifest(job_id):
    valid_job_id(job_id)
    return send_from_directory(config.CARVED_DIR / job_id, "manifest.json",
                               as_attachment=True)


@bp.route("/download-all/<job_id>")
def download_all(job_id):
    valid_job_id(job_id)
    output_dir = config.CARVED_DIR / job_id
    if not output_dir.exists():
        abort(404, description="Results not found")

    # zip to a temp file (results can be many GB — never buffer in RAM),
    # unlink immediately and stream from the open handle
    fd, tmp = tempfile.mkstemp(suffix=".zip", dir=config.DATA_DIR)
    try:
        with os.fdopen(fd, "wb") as raw, \
                zipfile.ZipFile(raw, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in output_dir.rglob("*"):
                if f.is_file():
                    zf.write(f, f.relative_to(output_dir))
        fh = open(tmp, "rb")
    finally:
        os.unlink(tmp)
    return send_file(fh, mimetype="application/zip", as_attachment=True,
                     download_name=f"carvx_{job_id}.zip")


@bp.route("/delete/<job_id>", methods=["POST", "DELETE"])
def delete_job(job_id):
    valid_job_id(job_id)
    if runner.is_running(job_id):
        return jsonify({"error": "Job is running — cancel it first"}), 409
    for p in (config.UPLOAD_DIR / job_id, config.CARVED_DIR / job_id):
        shutil.rmtree(p, ignore_errors=True)
    job_path(job_id).unlink(missing_ok=True)
    return jsonify({"success": True})
