"""Static configuration: paths, allowed inputs, carve modes, id patterns."""

import re
import sys
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent          # carvx_web/
WEB_ROOT = PACKAGE_ROOT.parent                          # web/
REPO_ROOT = WEB_ROOT.parent                             # carvX/ (contains carvx/)

DATA_DIR = WEB_ROOT / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
CARVED_DIR = DATA_DIR / "carved"
JOBS_DIR = DATA_DIR / "jobs"

MAX_CONTENT_LENGTH = 50 * 1024 * 1024 * 1024            # 50 GB

ALLOWED_EXTENSIONS = {"dd", "img", "iso", "e01", "raw", "bin", "aff",
                      "vmdk", "qcow2", "vdi"}
# split segments: image.001/.002…, image.e01/.e02…, image.dd.000…
SEGMENT_RE = re.compile(r"^(e\d{2}|s\d{2}|\d{3})$", re.IGNORECASE)

MODES = {"carve": None, "ntfs": "--ntfs", "ext4": "--ext4", "fat": "--fat",
         "hfs": "--hfs", "apfs": "--apfs", "auto": "--auto"}

JOB_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

INLINE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico"}

PYTHON = sys.executable
