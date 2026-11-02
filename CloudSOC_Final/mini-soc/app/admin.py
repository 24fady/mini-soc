"""Admin side: SOC console under /admin. Separate login, separate layout, separate theme.

The honeypot ban does not apply here, so an analyst can still reach the console from an
IP that was blocked on the public side. The console is protected by its own login
(bcrypt), CSRF tokens, a strict rate limit and a short session.
"""
import logging
from datetime import timedelta
from functools import wraps

from flask import (Blueprint, abort, current_app, flash, jsonify, redirect,
                   render_template, request, session, url_for)
from sqlalchemy import func

from .extensions import db, limiter
from .logging_setup import log_event
from .models import AdminUser, BlockedIP, LoginAttempt, utcnow
from .security import format_duration, get_client_ip, verify_password

bp = Blueprint("admin", __name__, url_prefix="/admin")


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin_id"):
            if request.path.startswith("/admin/api/"):
                return jsonify(error="unauthorized"), 401
            return redirect(url_for("admin.login"))
        return view(*args, **kwargs)

    return wrapped


@bp.get("/")
def home():
    return redirect(url_for("admin.dashboard"))


@bp.route("/login", methods=["GET", "POST"])
@limiter.limit(lambda: current_app.config["ADMIN_LOGIN_RATE_LIMIT"], methods=["POST"])
def login():
    if session.get("admin_id"):
        return redirect(url_for("admin.dashboard"))
    error = None
    if request.method == "POST":
        ip = get_client_ip()
        username = (request.form.get("username") or "").strip()[:100]
        password = request.form.get("password") or ""
        user = AdminUser.query.filter_by(username=username).first()
        if verify_password(password, user.password_hash if user else None):
            session.clear()
            session.permanent = True
            session["admin_id"] = user.id
            session["admin_name"] = user.username
            log_event("admin_login_success", ip=ip, username=user.username)
            return redirect(url_for("admin.dashboard"))
        log_event("admin_login_failed", level=logging.WARNING, ip=ip, username=username)
        error = "Authentication failed."
    return render_template("admin_login.html", error=error)


@bp.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("admin.login"))


@bp.get("/dashboard")
@admin_required
def dashboard():
    return render_template("dashboard.html")


@bp.get("/api/stats")
@admin_required
def api_stats():
    now = utcnow()
    total = LoginAttempt.query.count()
    last_hour = LoginAttempt.query.filter(
        LoginAttempt.created_at >= now - timedelta(hours=1)).count()
    unique_ips = db.session.query(func.count(func.distinct(LoginAttempt.ip))).scalar() or 0

    active = BlockedIP.query.filter(BlockedIP.active.is_(True), BlockedIP.expires_at > now).all()
    active_ips = {b.ip for b in active}
    denied = int(db.session.query(func.coalesce(func.sum(BlockedIP.hits), 0)).scalar() or 0)

    cnt = func.count(LoginAttempt.id)
    top_rows = (db.session.query(LoginAttempt.ip, cnt, func.max(LoginAttempt.country))
                .group_by(LoginAttempt.ip).order_by(cnt.desc()).limit(10).all())
    country_rows = (db.session.query(LoginAttempt.country, cnt)
                    .group_by(LoginAttempt.country).order_by(cnt.desc()).limit(8).all())

    start = (now - timedelta(minutes=59)).replace(second=0, microsecond=0)
    buckets = {start + timedelta(minutes=i): 0 for i in range(60)}
    for (ts,) in db.session.query(LoginAttempt.created_at).filter(LoginAttempt.created_at >= start):
        key = ts.replace(second=0, microsecond=0)
        if key in buckets:
            buckets[key] += 1

    recent = LoginAttempt.query.order_by(LoginAttempt.id.desc()).limit(20).all()

    return jsonify(
        totals={"attempts": total, "last_hour": last_hour, "unique_ips": unique_ips,
                "active_blocks": len(active_ips), "denied_requests": denied},
        timeline={"labels": [k.isoformat() + "Z" for k in buckets], "values": list(buckets.values())},
        top_ips=[{"ip": ip, "count": c, "country": country, "blocked": ip in active_ips}
                 for ip, c, country in top_rows],
        countries=[{"country": c or "Unknown", "count": n} for c, n in country_rows],
        recent=[{"time": r.created_at.isoformat() + "Z", "ip": r.ip, "username": r.username,
                 "password_hint": r.password_hint, "country": r.country,
                 "user_agent": r.user_agent} for r in recent],
    )


@bp.get("/blocked")
@admin_required
def blocked():
    now = utcnow()
    rows = BlockedIP.query.order_by(BlockedIP.blocked_at.desc()).limit(200).all()
    items = []
    for r in rows:
        is_active = r.active and r.expires_at > now
        items.append({
            "id": r.id, "ip": r.ip, "reason": r.reason, "blocked_at": r.blocked_at,
            "ban_count": r.ban_count, "hits": r.hits, "active": is_active,
            "remaining": format_duration((r.expires_at - now).total_seconds()) if is_active else "-",
        })
    return render_template("blocked.html", items=items)


@bp.post("/blocked/<int:block_id>/unblock")
@admin_required
def unblock(block_id):
    rec = db.session.get(BlockedIP, block_id)
    if rec is None:
        abort(404)
    rec.active = False
    db.session.commit()
    log_event("ip_unblocked", ip=rec.ip, by=session.get("admin_name"))
    flash(f"{rec.ip} was unblocked.")
    return redirect(url_for("admin.blocked"))
