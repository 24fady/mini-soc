from datetime import datetime, timezone

from .extensions import db


def utcnow():
    """Naive UTC datetime (stored as UTC in the database)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class LoginAttempt(db.Model):
    __tablename__ = "login_attempts"

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), nullable=False, index=True)
    username = db.Column(db.String(100), nullable=False, default="")
    password_hint = db.Column(db.String(50), nullable=False, default="")
    user_agent = db.Column(db.String(255), nullable=False, default="")
    country = db.Column(db.String(64), nullable=False, default="Unknown")
    outcome = db.Column(db.String(10), nullable=False, default="failed")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)


class BlockedIP(db.Model):
    __tablename__ = "blocked_ips"

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), nullable=False, unique=True)
    reason = db.Column(db.String(255), nullable=False, default="")
    blocked_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    ban_count = db.Column(db.Integer, nullable=False, default=1)
    hits = db.Column(db.Integer, nullable=False, default=0)
    active = db.Column(db.Boolean, nullable=False, default=True)


class AdminUser(db.Model):
    __tablename__ = "admin_users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    password_hash = db.Column(db.String(100), nullable=False)
