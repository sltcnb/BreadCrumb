"""Static configuration: paths, allowed inputs, carve modes, id patterns."""

import re
import sys
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent          # breadcrumb_web/
WEB_ROOT = PACKAGE_ROOT.parent                          # web/
REPO_ROOT = WEB_ROOT.parent                             # BreadCrumb/ (contains breadcrumb/)

# The core carver is invoked as `python -m <CORE_PACKAGE>` from REPO_ROOT, and
# BitLocker credentials are handed to it through BITLOCKER_ENV. Both names are
# owned by the core package; tests/test_core_coupling.py checks they still fit.
CORE_PACKAGE = "breadcrumb"
BITLOCKER_ENV = "BREADCRUMB_BITLOCKER"

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
