"""build_command() assembles the argv handed to `python -m carvx`; every
option must land in the right argv slot (or be omitted) since this is the
only thing standing between the web form and a subprocess invocation."""

from pathlib import Path

from carvx_web import config
from carvx_web.runner import build_command

SOURCE = "/evidence/image.dd"
OUT = Path("/tmp/out")


def _base():
    return [config.PYTHON, "-m", "carvx", SOURCE, "-o", str(OUT), "--machine"]


def test_defaults_to_plain_carve_with_no_extra_flags():
    cmd = build_command({}, SOURCE, OUT)
    assert cmd == _base()


def test_mode_flag_is_appended_for_non_carve_modes():
    for mode, flag in (("ntfs", "--ntfs"), ("ext4", "--ext4"),
                       ("fat", "--fat"), ("hfs", "--hfs"),
                       ("apfs", "--apfs"), ("auto", "--auto")):
        cmd = build_command({"mode": mode}, SOURCE, OUT)
        assert cmd == _base() + [flag], mode


def test_types_only_applied_in_carve_or_auto_mode():
    cmd = build_command({"mode": "carve", "types": ["png", "jpg"]},
                        SOURCE, OUT)
    assert cmd == _base() + ["-t", "png,jpg"]

    cmd = build_command({"mode": "auto", "types": ["pdf"]}, SOURCE, OUT)
    assert cmd == _base() + ["--auto", "-t", "pdf"]

    # types are meaningless (and ignored) outside carve/auto
    cmd = build_command({"mode": "ntfs", "types": ["png"]}, SOURCE, OUT)
    assert cmd == _base() + ["--ntfs"]


def test_offset_length_align_are_passed_through_when_set():
    cmd = build_command(
        {"offset": "512", "length": "4096", "align": "16"}, SOURCE, OUT)
    assert cmd == _base() + [
        "--offset", "512", "--length", "4096", "--align", "16"]


def test_offset_length_align_omitted_when_blank_or_zero():
    for val in ("0", "", "  ", None):
        cmd = build_command(
            {"offset": val, "length": val, "align": val}, SOURCE, OUT)
        assert cmd == _base()


def test_jobs_flag_only_added_when_not_one():
    assert build_command({"jobs": 1}, SOURCE, OUT) == _base()
    assert build_command({}, SOURCE, OUT) == _base()
    assert (build_command({"jobs": 4}, SOURCE, OUT)
            == _base() + ["-j", "4"])


def test_boolean_flags():
    cmd = build_command(
        {"validate": True, "drop_failed": True, "dry_run": True},
        SOURCE, OUT)
    assert cmd == _base() + ["--validate", "--drop-failed", "--dry-run"]

    cmd = build_command(
        {"validate": False, "drop_failed": False, "dry_run": False},
        SOURCE, OUT)
    assert cmd == _base()


def test_report_output_paths_are_relative_to_output_dir():
    cmd = build_command({"csv": True, "html": True, "timeline": True},
                        SOURCE, OUT)
    assert cmd == _base() + [
        "--csv", str(OUT / "results.csv"),
        "--html", str(OUT / "report.html"),
        "--timeline", str(OUT / "timeline.csv"),
    ]


def test_full_option_set_wires_argv_in_declared_order():
    data = {
        "mode": "carve", "types": ["png", "bmp"], "offset": "1024",
        "length": "2048", "align": "4", "jobs": 2, "validate": True,
        "drop_failed": True, "dry_run": True, "csv": True, "html": True,
        "timeline": True,
    }
    cmd = build_command(data, SOURCE, OUT)
    assert cmd == _base() + [
        "-t", "png,bmp",
        "--offset", "1024", "--length", "2048", "--align", "4",
        "-j", "2",
        "--validate", "--drop-failed", "--dry-run",
        "--csv", str(OUT / "results.csv"),
        "--html", str(OUT / "report.html"),
        "--timeline", str(OUT / "timeline.csv"),
    ]
