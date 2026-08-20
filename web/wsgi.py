"""WSGI entry point for gunicorn/uwsgi: `gunicorn wsgi:app`."""

from breadcrumb_web import create_app

app = create_app()
