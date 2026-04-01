"""
signup/telegram_client.py

Telegram Bot API の薄いラッパー。
TELEGRAM_BOT_TOKEN が未設定の場合は ImproperlyConfigured を送出するが、
呼び出し元でキャッチしてコンソールログへフォールバックできる。
"""

import logging

import requests
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

logger = logging.getLogger(__name__)


def _get_token() -> str:
    token = getattr(settings, "TELEGRAM_BOT_TOKEN", "") or ""
    if not token:
        raise ImproperlyConfigured(
            "TELEGRAM_BOT_TOKEN が未設定です。config.ini の [TELEGRAM] bot_token を設定してください。"
        )
    return token


def send_message(chat_id: str, text: str) -> None:
    """
    Telegram Bot API の sendMessage を呼ぶ。

    :param chat_id: Telegram の chat_id（数値を文字列化したもの）
    :param text: 送信するメッセージ本文
    :raises ImproperlyConfigured: bot_token が未設定
    :raises RuntimeError: API がエラーレスポンスを返した場合
    """
    token = _get_token()
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        resp = requests.post(url, json={"chat_id": chat_id, "text": text}, timeout=10)
    except requests.RequestException as e:
        raise RuntimeError(f"Telegram API への接続に失敗しました: {e}") from e

    if not resp.ok:
        raise RuntimeError(f"Telegram API HTTP {resp.status_code}: {resp.text[:200]}")

    data = resp.json()
    if not data.get("ok"):
        raise RuntimeError(f"Telegram API エラー: {data.get('description', resp.text[:200])}")


def send_otp(chat_id: str, otp: str, ttl: int) -> None:
    """OTP 通知メッセージを送る。"""
    text = f"認証コードは {otp} です。{ttl}秒以内に入力してください。"
    send_message(chat_id, text)


def send_welcome(chat_id: str, user_id: str) -> None:
    """会員登録完了通知を送る。"""
    text = (
        f"ShiningWish へようこそ！\n"
        f"アカウント登録が完了しました。\n\n"
        f"あなたの USER ID: {user_id}\n\n"
        "「ログイン」と送ると、ログインページのURLをお送りします。"
    )
    send_message(chat_id, text)


def send_kyc_received(chat_id: str) -> None:
    """KYC 書類受付通知を送る。"""
    text = "本人確認書類をお受け取りしました。審査が完了しましたらご連絡いたします。"
    send_message(chat_id, text)
