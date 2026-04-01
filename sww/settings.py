"""
Django settings for django-sample project.

本番 (SWWEB1) との主な差分:
  - DB: MySQL → SQLite（外部サービス不要）
  - django-allauth → Django 標準 LoginView
  - Vault Transit → base64（デモ用途）
  - Telegram API → コンソールログ出力

設定の読み込み方針（本番と同じパターン）:
  - 秘密情報: 環境変数 または .env ファイル
  - 実行時設定: config.ini（configparser）
"""

import os
import configparser
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent

# .env ファイルを読み込む（開発用）
load_dotenv(BASE_DIR / ".env")

# --- configparser ヘルパー ---
_cfgp = configparser.ConfigParser()
_cfg_path = os.environ.get("DJANGO_SAMPLE_CONFIG", str(BASE_DIR / "config.ini"))
_cfgp.read(_cfg_path, encoding="utf-8")


def cfg(section: str, key: str, default=None) -> str | None:
    """config.ini から文字列値を取得する。存在しなければ default を返す。"""
    try:
        return _cfgp.get(section, key)
    except (configparser.NoSectionError, configparser.NoOptionError):
        return default


def cfg_int(section: str, key: str, default: int) -> int:
    """config.ini から整数値を取得する。存在しなければ default を返す。"""
    v = cfg(section, key)
    return int(v) if v is not None else default


def cfg_bool(section: str, key: str, default: bool = False) -> bool:
    """config.ini から真偽値を取得する。存在しなければ default を返す。"""
    v = cfg(section, key)
    if v is None:
        return default
    return v.strip().lower() in ("true", "1", "yes", "on")


# --- 基本設定 ---

SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]

DEBUG = cfg_bool("DJANGO", "debug", default=True)

ALLOWED_HOSTS = cfg("DJANGO", "allowed_hosts", default="127.0.0.1,localhost").split(",")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "signup",
    "portal",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "sww.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "sww.wsgi.application"

# --- データベース（SQLite）---

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

# --- 認証 ---

AUTHENTICATION_BACKENDS = [
    # USER_ID (U00000001) でのログインをサポート
    "signup.auth_backend.AccountLoginBackend",
    # 標準のユーザー名/パスワード認証（フォールバック）
    "django.contrib.auth.backends.ModelBackend",
]

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
]

LOGIN_URL = "/portal/login/"
LOGIN_REDIRECT_URL = "/portal/mypage/"
LOGOUT_REDIRECT_URL = "/portal/login/"

# --- Telegram Bot 設定 ---

TELEGRAM_BOT_TOKEN      = cfg("TELEGRAM", "bot_token",      default="") or ""
TELEGRAM_WEBHOOK_SECRET = cfg("TELEGRAM", "webhook_secret", default="") or ""
PORTAL_BASE_URL         = cfg("TELEGRAM", "portal_base_url", default="http://127.0.0.1:8000") or "http://127.0.0.1:8000"

# --- OTP / Signup 設定 ---

# TimestampSigner の salt（用途別に必ず分ける — クロス利用を防ぐ）
SIGNUP_VERIFIED_TOKEN_SALT = "signup.verified_token.v1"
KYC_PREVIEW_TOKEN_SALT = "kyc.preview_token.v1"

SNS_OTP_TTL_SECONDS = cfg_int("OTP", "ttl_seconds", 300)          # OTPセッション有効期間
SNS_OTP_MAX_ATTEMPTS = cfg_int("OTP", "max_attempts", 5)           # 最大試行回数
SNS_OTP_COOLDOWN = cfg_int("OTP", "cooldown_seconds", 60)          # 連打抑止
SNS_OTP_REQUIRE_SAME_SESSION = False   # demo では無効（curl でもテスト可能にする）
SNS_VERIFY_TOKEN_MAX_AGE_SEC = 600     # verified_token の最大有効期間

# --- KYC 設定 ---

KYC_UPLOAD_MAX_BYTES = cfg_int("KYC", "max_upload_bytes", 5 * 1024 * 1024)
KYC_MAX_IMAGES_PER_USER = cfg_int("KYC", "max_images_per_user", 5)
KYC_PREVIEW_TOKEN_MAX_AGE_SEC = cfg_int("KYC", "blob_token_ttl_seconds", 60)
KYC_WATERMARK_FONT_SIZE = cfg_int("KYC", "watermark_font_size", 22)
KYC_WATERMARK_MARGIN_PX = cfg_int("KYC", "watermark_margin_px", 16)
KYC_ALLOWED_MIME_TYPES = ["image/jpeg", "image/png"]

# --- 国際化 ---

LANGUAGE_CODE = "ja"
TIME_ZONE = "Asia/Tokyo"
USE_I18N = True
USE_TZ = True

# --- 静的ファイル ---

STATIC_URL = "static/"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# --- ロギング ---

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
    },
    "formatters": {
        "verbose": {
            "format": "[{levelname}] {name}: {message}",
            "style": "{",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "INFO",
    },
    "loggers": {
        "signup": {
            "handlers": ["console"],
            "level": "DEBUG",
            "propagate": False,
        },
    },
}
