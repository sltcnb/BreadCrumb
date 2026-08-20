"""The web app drives the core carver as a subprocess, so nothing in Python's
import machinery catches a rename of the core package. These tests exercise
the three couplings directly: the module name in argv, the flag output the
runner parses, and the environment variable BitLocker credentials travel in.

A rename like carvx -> breadcrumb broke all three silently; each of these
fails loudly instead.
"""

from breadcrumb_web import config, runner


def test_core_package_is_present_where_the_app_expects_it():
    core = config.REPO_ROOT / config.CORE_PACKAGE
    assert (core / "__main__.py").is_file(), \
        f"create_app() refuses to start without {core}/__main__.py"


def test_list_types_output_parses_into_supported_types():
    """`python -m <core> --list-types` really runs, and its table parses."""
    types = runner.get_supported_types()
    assert types, "no types parsed from --list-types output"
    names = {t["name"] for t in types}
    for expected in ("png", "jpg", "pdf", "zip"):
        assert expected in names, f"{expected} missing from {sorted(names)}"
    assert all(t["description"] for t in types)


def test_bitlocker_env_var_is_the_one_the_core_package_reads():
    """routes.py hands credentials over in config.BITLOCKER_ENV; the core
    package has to be the one reading that same name."""
    core = config.REPO_ROOT / config.CORE_PACKAGE
    assert any(config.BITLOCKER_ENV in p.read_text(errors="ignore")
               for p in core.rglob("*.py")), \
        f"{config.BITLOCKER_ENV} is not read anywhere in {core}"
