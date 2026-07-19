import os
import sys

WEB_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, WEB_ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest  # noqa: E402

from carvx_web import config, create_app  # noqa: E402


@pytest.fixture
def isolated_dirs(tmp_path, monkeypatch):
    """Redirect all on-disk job state under a throwaway tmp_path so tests
    never touch (or depend on) the real web/data/ directory."""
    upload_dir = tmp_path / "uploads"
    carved_dir = tmp_path / "carved"
    jobs_dir = tmp_path / "jobs"
    for d in (upload_dir, carved_dir, jobs_dir):
        d.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(config, "UPLOAD_DIR", upload_dir)
    monkeypatch.setattr(config, "CARVED_DIR", carved_dir)
    monkeypatch.setattr(config, "JOBS_DIR", jobs_dir)
    return {"uploads": upload_dir, "carved": carved_dir, "jobs": jobs_dir}


@pytest.fixture
def app(isolated_dirs):
    application = create_app()
    application.config.update(TESTING=True)
    return application


@pytest.fixture
def client(app):
    return app.test_client()
