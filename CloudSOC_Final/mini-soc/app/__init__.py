from flask import Flask, request
from werkzeug.middleware.proxy_fix import ProxyFix

from config import Config

from .cli import register_cli
from .extensions import csrf, db, limiter
from .logging_setup import setup_logging


# Admin console: only our own files + Chart.js. Public login page: also Google Fonts and Font Awesome.
ADMIN_CSP = (
    "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self'; "
    "img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
)
PUBLIC_CSP = (
    "default-src 'self'; script-src 'self'; "
    "style-src 'self' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
    "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
    "img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
)


def create_app(config_object=Config):
    app = Flask(__name__)
    app.config.from_object(config_object)
    setup_logging(app.config["LOG_FILE"])

    hops = app.config["PROXY_HOPS"]
    if hops > 0:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=hops, x_proto=1)

    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    from .admin import bp as admin_bp
    from .public import bp as public_bp

    app.register_blueprint(public_bp)
    app.register_blueprint(admin_bp)
    register_cli(app)

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "same-origin"
        strict = request.blueprint == "admin" and resp.status_code < 400
        resp.headers["Content-Security-Policy"] = ADMIN_CSP if strict else PUBLIC_CSP
        if request.endpoint != "static":
            resp.headers["Cache-Control"] = "no-store"
        if app.config["SESSION_COOKIE_SECURE"]:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000"
        return resp

    return app
