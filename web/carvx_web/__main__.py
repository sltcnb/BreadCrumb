"""CLI entry: `python -m carvx_web` runs the dev server.

Env: CARVX_WEB_HOST (default 127.0.0.1), PORT (5050), CARVX_WEB_DEBUG=1,
CARVX_WEB_ALLOW_REMOTE=1 (required to bind a non-loopback host).
"""

import ipaddress
import os
import sys

from . import create_app


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False                                # hostname, 0.0.0.0, etc.


def main() -> None:
    host = os.environ.get("CARVX_WEB_HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", 5050))
    debug = os.environ.get("CARVX_WEB_DEBUG") == "1"

    if not _is_loopback(host):
        warning = (
            f"carvx-web: binding to non-loopback address {host!r}. This "
            "app has no authentication and POST /upload/path will read "
            "any file path readable by the server process. Only run it "
            "this way on a trusted, isolated network."
        )
        if os.environ.get("CARVX_WEB_ALLOW_REMOTE") != "1":
            sys.exit(
                warning + "\nRefusing to start. Set CARVX_WEB_ALLOW_REMOTE=1 "
                "to acknowledge the risk and bind anyway."
            )
        print(f"WARNING: {warning}", file=sys.stderr)

    app = create_app()
    app.run(host=host, port=port, debug=debug, threaded=True)


if __name__ == "__main__":
    main()
