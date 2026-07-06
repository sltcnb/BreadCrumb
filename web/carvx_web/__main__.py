"""CLI entry: `python -m carvx_web` runs the dev server.

Env: CARVX_WEB_HOST (default 127.0.0.1), PORT (5050), CARVX_WEB_DEBUG=1.
"""

import os

from . import create_app


def main() -> None:
    app = create_app()
    host = os.environ.get("CARVX_WEB_HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", 5050))
    debug = os.environ.get("CARVX_WEB_DEBUG") == "1"
    app.run(host=host, port=port, debug=debug, threaded=True)


if __name__ == "__main__":
    main()
