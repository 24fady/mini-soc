"""Public side: the honeypot login that attackers see. No link to the admin console."""
import logging

from flask import Blueprint, current_app, redirect, render_template, request, url_for

from .extensions import csrf, db, limiter
from .logging_setup import log_event
from .models import BlockedIP, utcnow
from .security import (format_duration, get_active_block, get_client_ip,
                       is_whitelisted, register_failed_attempt)

bp = Blueprint("public", __name__)


@bp.before_request
def block_gate():
    """Deny blocked IPs before anything on the public side runs."""
    if request.endpoint == "public.health":
        return None
    ip = get_client_ip()
    if is_whitelisted(ip):
        return None
    rec = get_active_block(ip)
    if rec:
        BlockedIP.query.filter_by(id=rec.id).update({"hits": BlockedIP.hits + 1})
        db.session.commit()
        log_event("blocked_request", level=logging.WARNING, ip=ip,
                  path=request.path, method=request.method)
        retry = format_duration((rec.expires_at - utcnow()).total_seconds())
        return render_template("blocked_ip.html", ip=ip, retry=retry), 403
    return None


@bp.get("/")
def index():
    return redirect(url_for("public.login"))


@bp.get("/health")
def health():
    return "ok", 200


@bp.route("/login", methods=["GET", "POST"])
@csrf.exempt  # the trap must accept raw POSTs from attack tools
@limiter.limit(lambda: current_app.config["LOGIN_RATE_LIMIT"], methods=["POST", "GET"])
def login():
    error = None
    if request.method == "POST":
        ip = get_client_ip()
        register_failed_attempt(
            ip,
            request.form.get("username", ""),
            request.form.get("password", ""),
            request.headers.get("User-Agent", ""),
        )
        error = "Invalid username or password."
    return render_template("login.html", error=error)


@bp.app_errorhandler(429)
def too_many(e):
    log_event("rate_limited", level=logging.WARNING, ip=get_client_ip(), path=request.path)
    return render_template("error.html", code=429, title="Too many requests",
                           message="Invalid request rate. Please wait a minute and try again."), 429


@bp.app_errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, title="Page not found",
                           message="The page you requested does not exist."), 404
