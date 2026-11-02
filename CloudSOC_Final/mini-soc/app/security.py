"""Detection, blocking and helper logic for the Mini SOC."""
import ipaddress
import logging
from datetime import timedelta

import bcrypt
from flask import current_app, request

from .extensions import db
from .logging_setup import log_event
from .models import BlockedIP, LoginAttempt, utcnow

_DUMMY_HASH = bcrypt.hashpw(b"dummy-password", bcrypt.gensalt(rounds=12))
_geo_reader = None
_geo_failed = False


# ---------- passwords ----------
def hash_password(password):
    return bcrypt.hashpw(password.encode()[:72], bcrypt.gensalt(rounds=12)).decode()


def verify_password(password, stored_hash):
    """Always runs bcrypt, even for unknown users, to avoid timing leaks."""
    target = stored_hash.encode() if stored_hash else _DUMMY_HASH
    try:
        ok = bcrypt.checkpw(password.encode()[:72], target)
    except ValueError:
        return False
    return ok and stored_hash is not None


def mask_password(password):
    """Attempted passwords are never stored in clear text."""
    if not password:
        return "(empty)"
    shown = password[0] if len(password) > 1 else ""
    hidden = min(len(password) - len(shown), 8)
    return f"{shown}{'*' * hidden} (len={len(password)})"


# ---------- client info ----------
def get_client_ip():
    # ProxyFix (configured in create_app) already resolved the real client IP.
    return request.remote_addr or "0.0.0.0"


def is_whitelisted(ip):
    return ip in current_app.config["WHITELIST_IPS"]


def lookup_country(ip):
    global _geo_reader, _geo_failed
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "Unknown"
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return "Local/Private"
    if _geo_reader is None and not _geo_failed:
        try:
            import geoip2.database

            _geo_reader = geoip2.database.Reader(current_app.config["GEOIP_DB_PATH"])
        except Exception:
            _geo_failed = True
    if _geo_reader is None:
        return "Unknown"
    try:
        return (_geo_reader.country(ip).country.name or "Unknown")[:64]
    except Exception:
        return "Unknown"


# ---------- blocking ----------
def get_active_block(ip):
    rec = BlockedIP.query.filter_by(ip=ip, active=True).first()
    if rec and rec.expires_at <= utcnow():
        rec.active = False
        db.session.commit()
        log_event("ip_unblocked", ip=ip, by="expiry")
        return None
    return rec


def block_ip(ip, reason):
    """Progressive ban: base * 2^(previous_bans), capped at MAX_BAN_SECONDS."""
    cfg = current_app.config
    now = utcnow()
    rec = BlockedIP.query.filter_by(ip=ip).first()
    if rec and rec.active and rec.expires_at > now:
        return rec  # already blocked (concurrent request)
    if rec:
        rec.ban_count += 1
    else:
        rec = BlockedIP(ip=ip, ban_count=1, hits=0)
        db.session.add(rec)
    duration = min(cfg["BASE_BAN_SECONDS"] * 2 ** (rec.ban_count - 1), cfg["MAX_BAN_SECONDS"])
    rec.reason = reason[:255]
    rec.blocked_at = now
    rec.expires_at = now + timedelta(seconds=duration)
    rec.active = True
    db.session.commit()
    log_event(
        "ip_blocked", level=logging.WARNING, ip=ip, reason=reason,
        ban_count=rec.ban_count, duration_seconds=duration,
    )
    return rec


def register_failed_attempt(ip, username, password, user_agent):
    """Store the attempt, then decide whether the IP crossed the threshold.

    Returns True if this attempt caused a new block.
    """
    cfg = current_app.config
    country = lookup_country(ip)
    db.session.add(
        LoginAttempt(
            ip=ip,
            username=username[:100],
            password_hint=mask_password(password),
            user_agent=(user_agent or "")[:255],
            country=country,
            outcome="failed",
        )
    )
    db.session.commit()
    log_event(
        "failed_login", level=logging.WARNING, ip=ip, username=username[:100],
        country=country, user_agent=(user_agent or "")[:255],
    )

    if is_whitelisted(ip):
        return False

    since = utcnow() - timedelta(seconds=cfg["ATTEMPT_WINDOW_SECONDS"])
    previous = BlockedIP.query.filter_by(ip=ip).first()
    if previous and previous.blocked_at > since:
        since = previous.blocked_at  # ignore attempts made before the last ban
    count = LoginAttempt.query.filter(
        LoginAttempt.ip == ip,
        LoginAttempt.outcome == "failed",
        LoginAttempt.created_at >= since,
    ).count()

    if count >= cfg["MAX_FAILED_ATTEMPTS"] and not get_active_block(ip):
        reason = (
            f"{count} failed logins within {cfg['ATTEMPT_WINDOW_SECONDS']}s "
            f"(threshold {cfg['MAX_FAILED_ATTEMPTS']})"
        )
        block_ip(ip, reason)
        return True
    return False


def format_duration(seconds):
    seconds = max(int(seconds), 0)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m}m"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"
