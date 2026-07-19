"""Route-level security behavior: allowed_file()/secure_filename() on
upload, job_id enforcement, and send_from_directory's escape protection
on the download/view/manifest routes."""

import io
import uuid

import pytest

from carvx_web.routes import allowed_file


# ------------------------------------------------------------- allowed_file

@pytest.mark.parametrize("filename,expected", [
    ("image.dd", True),
    ("image.img", True),
    ("image.ISO", True),                 # case-insensitive
    ("image.e01", True),
    ("image.E02", True),                 # split segment, uppercase
    ("image.s01", True),                 # split segment
    ("image.001", True),                 # numeric segment
    ("image.999", True),
    ("image.exe", False),
    ("image.txt", False),
    ("noextension", False),
    ("", False),
])
def test_allowed_file(filename, expected):
    assert allowed_file(filename) is expected


# -------------------------------------------------------- upload / secure_filename

def test_upload_sanitizes_path_traversal_filename(client, isolated_dirs):
    job_id = str(uuid.uuid4())
    resp = client.post("/upload", data={
        "job_id": job_id,
        "file": (io.BytesIO(b"evil-payload"), "../../evil.dd"),
    }, content_type="multipart/form-data")
    assert resp.status_code == 200
    assert resp.get_json()["success"] is True

    job_dir = isolated_dirs["uploads"] / job_id
    saved = list(job_dir.iterdir())
    assert len(saved) == 1
    # secure_filename() must have stripped the directory traversal
    assert "/" not in saved[0].name and ".." not in saved[0].name
    # and the payload must not have escaped the job directory
    assert not (isolated_dirs["uploads"] / "evil.dd").exists()
    assert not (isolated_dirs["uploads"].parent / "evil.dd").exists()


def test_upload_rejects_disallowed_extension(client):
    resp = client.post("/upload", data={
        "file": (io.BytesIO(b"x"), "payload.exe"),
    }, content_type="multipart/form-data")
    assert resp.status_code == 400
    assert "not allowed" in resp.get_json()["error"]


# -------------------------------------------------------------- job id enforcement
#
# Job ids with a "/" (e.g. "../../etc/passwd") never even reach the view —
# Flask's default <job_id> converter refuses slashes and 404s first. What
# valid_job_id() must guard against is a same-length, no-slash string that
# is not a real uuid4 (wrong charset/case), so that's what these exercise.

@pytest.mark.parametrize("bad_id", [
    "not-a-uuid",
    "12345678-1234-1234-1234-1234567890zz",
    "12345678-1234-1234-1234-1234567890AB",
])
def test_status_rejects_invalid_job_id(client, bad_id):
    resp = client.get(f"/status/{bad_id}")
    assert resp.status_code == 400


@pytest.mark.parametrize("bad_id", [
    "not-a-uuid",
    "12345678-1234-1234-1234-1234567890zz",
])
def test_download_rejects_invalid_job_id(client, bad_id):
    resp = client.get(f"/download/{bad_id}/whatever.txt")
    assert resp.status_code == 400


def test_cancel_rejects_invalid_job_id(client):
    resp = client.post("/cancel/not-a-uuid")
    assert resp.status_code == 400


def test_job_id_with_path_separator_is_blocked_by_routing_before_view(client):
    """Belt-and-suspenders: even if valid_job_id() were ever bypassed,
    Flask's own routing already refuses a job_id segment containing '/'."""
    resp = client.get("/status/../../etc/passwd")
    assert resp.status_code == 404


# --------------------------------------------------- send_from_directory escaping

def test_download_serves_file_inside_job_dir(client, isolated_dirs):
    job_id = str(uuid.uuid4())
    job_dir = isolated_dirs["carved"] / job_id
    job_dir.mkdir(parents=True)
    (job_dir / "carved.bin").write_bytes(b"carved-bytes")

    resp = client.get(f"/download/{job_id}/carved.bin")
    assert resp.status_code == 200
    assert resp.data == b"carved-bytes"


@pytest.mark.parametrize("escape_path", [
    "../secret.txt",
    "..%2Fsecret.txt",
    "..%2f..%2fsecret.txt",
    "sub/../../secret.txt",
])
def test_download_cannot_escape_job_dir(client, isolated_dirs, escape_path):
    job_id = str(uuid.uuid4())
    job_dir = isolated_dirs["carved"] / job_id
    job_dir.mkdir(parents=True)
    (job_dir / "carved.bin").write_bytes(b"carved-bytes")

    # a secret file that lives next to (not inside) the job directory
    (isolated_dirs["carved"] / "secret.txt").write_text("TOP SECRET")

    resp = client.get(f"/download/{job_id}/{escape_path}")
    assert resp.status_code == 404


def test_view_rejects_non_image_extension(client, isolated_dirs):
    job_id = str(uuid.uuid4())
    job_dir = isolated_dirs["carved"] / job_id
    job_dir.mkdir(parents=True)
    (job_dir / "page.html").write_text("<script>alert(1)</script>")

    resp = client.get(f"/view/{job_id}/page.html")
    assert resp.status_code == 403


def test_view_serves_allowed_image_extension(client, isolated_dirs):
    job_id = str(uuid.uuid4())
    job_dir = isolated_dirs["carved"] / job_id
    job_dir.mkdir(parents=True)
    (job_dir / "pic.png").write_bytes(b"\x89PNG\r\n\x1a\n")

    resp = client.get(f"/view/{job_id}/pic.png")
    assert resp.status_code == 200


