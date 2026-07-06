"""WSGI entry point for gunicorn/uwsgi: `gunicorn wsgi:app`."""

from carvx_web import create_app

app = create_app()
