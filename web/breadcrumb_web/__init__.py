"""BreadCrumb Web — Flask front-end for the BreadCrumb carver.

Runs the real breadcrumb package from the repo root (no bundled copy) via
`python -m breadcrumb --machine` and streams its JSON-lines events into live
job progress. Job state is persisted per job under web/data/jobs/ so a
server restart does not lose history.
"""

import sys

from flask import Flask

from . import config


def create_app() -> Flask:
    core = config.REPO_ROOT / config.CORE_PACKAGE
    if not (core / "__main__.py").exists():
        sys.exit(f"error: {config.CORE_PACKAGE} package not found at {core} "
                 "— the web app must live inside the BreadCrumb repo (web/)")

    for d in (config.UPLOAD_DIR, config.CARVED_DIR, config.JOBS_DIR):
        d.mkdir(parents=True, exist_ok=True)

    app = Flask(__name__)                      # templates/ & static/ in package
    app.config["MAX_CONTENT_LENGTH"] = config.MAX_CONTENT_LENGTH

    from .routes import bp
    app.register_blueprint(bp)
    return app
