"""CarvX Web — Flask front-end for the carvx carver.

Runs the real carvx package from the repo root (no bundled copy) via
`python -m carvx --machine` and streams its JSON-lines events into live
job progress. Job state is persisted per job under web/data/jobs/ so a
server restart does not lose history.
"""

import sys

from flask import Flask

from . import config


def create_app() -> Flask:
    if not (config.REPO_ROOT / "carvx" / "__main__.py").exists():
        sys.exit(f"error: carvx package not found at "
                 f"{config.REPO_ROOT / 'carvx'} — the web app must live "
                 "inside the carvX repo (web/)")

    for d in (config.UPLOAD_DIR, config.CARVED_DIR, config.JOBS_DIR):
        d.mkdir(parents=True, exist_ok=True)

    app = Flask(__name__)                      # templates/ & static/ in package
    app.config["MAX_CONTENT_LENGTH"] = config.MAX_CONTENT_LENGTH

    from .routes import bp
    app.register_blueprint(bp)
    return app
