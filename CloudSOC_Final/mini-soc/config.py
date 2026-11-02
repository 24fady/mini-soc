import os
from datetime import timedelta


def _bool(name, default=False):
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def _int(name, default):
    return int(os.environ.get(name, default))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-change-me")

    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///minisoc.db")
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True, "pool_recycle": 280}
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session / cookies
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _bool("SESSION_COOKIE_SECURE", False)
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    WTF_CSRF_TIME_LIMIT = None

    # Detection and blocking
    MAX_FAILED_ATTEMPTS = _int("MAX_FAILED_ATTEMPTS", 5)
    ATTEMPT_WINDOW_SECONDS = _int("ATTEMPT_WINDOW_SECONDS", 120)
    BASE_BAN_SECONDS = _int("BASE_BAN_SECONDS", 900)
    MAX_BAN_SECONDS = _int("MAX_BAN_SECONDS", 86400)
    WHITELIST_IPS = {
        ip.strip() for ip in os.environ.get("WHITELIST_IPS", "").split(",") if ip.strip()
    }

    # Rate limiting (Flask-Limiter)
    LOGIN_RATE_LIMIT = os.environ.get("LOGIN_RATE_LIMIT", "10 per minute")
    ADMIN_LOGIN_RATE_LIMIT = os.environ.get("ADMIN_LOGIN_RATE_LIMIT", "5 per minute")
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_HEADERS_ENABLED = True

    # Reverse proxy hops (ALB + Nginx = 2)
    PROXY_HOPS = _int("PROXY_HOPS", 0)

    GEOIP_DB_PATH = os.environ.get("GEOIP_DB_PATH", "GeoLite2-Country.mmdb")
    LOG_FILE = os.environ.get("LOG_FILE", "")
