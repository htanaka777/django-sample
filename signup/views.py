"""
signup アプリのビュー

エンドポイント一覧:
  GET  /signup/register/         会員登録フォーム（ブラウザ向け）
  POST /signup/sns/start         OTP 発行
  POST /signup/sns/verify        OTP 検証 → verified_token 発行
  POST /signup/complete          会員登録完了
  POST /signup/kyc/upload        KYC 画像アップロード（要ログイン）
  GET  /signup/kyc/blob/<token>  KYC 画像プレビュー（透かし付き）
  POST /signup/tg/webhook        Telegram Bot webhook

本番 (SWWEB1) との主な差分:
  - OTP 送信: TELEGRAM_BOT_TOKEN があれば Telegram 送信、なければコンソールログへ出力
  - KYC 暗号化: HashiCorp Vault Transit → base64 エンコード（デモ）
  - セッション束縛: SNS_OTP_REQUIRE_SAME_SESSION=False（curl でも確認可能）
"""

import base64
import json
import logging
import random
from datetime import timedelta

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.models import User
from django.core.exceptions import ImproperlyConfigured
from django.core.signing import BadSignature, SignatureExpired, TimestampSigner
from django.db import transaction
from django.http import HttpResponse, HttpResponseNotAllowed, JsonResponse
from django.shortcuts import render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt

from . import telegram_client
from .kyc_utils import add_watermark
from .models import (
    AccountUser,
    IdDocument,
    LoginAudit,
    SnsOtpSession,
    SnsOutbox,
    UserIdSequence,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 設定定数（settings.py で上書き可能）
# ---------------------------------------------------------------------------

SIGNUP_VERIFIED_TOKEN_SALT = getattr(
    settings, "SIGNUP_VERIFIED_TOKEN_SALT", "signup.verified_token.v1"
)
KYC_PREVIEW_TOKEN_SALT = getattr(
    settings, "KYC_PREVIEW_TOKEN_SALT", "kyc.preview_token.v1"
)

OTP_TTL_SECONDS         = getattr(settings, "SNS_OTP_TTL_SECONDS", 300)
OTP_MAX_ATTEMPTS        = getattr(settings, "SNS_OTP_MAX_ATTEMPTS", 5)
OTP_RESEND_COOLDOWN_SEC = getattr(settings, "SNS_OTP_COOLDOWN", 60)
VERIFY_TOKEN_MAX_AGE    = getattr(settings, "SNS_VERIFY_TOKEN_MAX_AGE_SEC", 600)
KYC_PREVIEW_MAX_AGE     = getattr(settings, "KYC_PREVIEW_TOKEN_MAX_AGE_SEC", 60)
KYC_UPLOAD_MAX_BYTES    = getattr(settings, "KYC_UPLOAD_MAX_BYTES", 5 * 1024 * 1024)
KYC_MAX_IMAGES          = getattr(settings, "KYC_MAX_IMAGES_PER_USER", 5)
KYC_ALLOWED_MIME_TYPES  = getattr(settings, "KYC_ALLOWED_MIME_TYPES", ["image/jpeg", "image/png"])

# 監査ログ イベントタイプ定数
EVT_OTP_START   = 101
EVT_OTP_VERIFY  = 102
EVT_OTP_FAIL    = 103
EVT_SIGNUP_DONE = 111
EVT_KYC_UPLOAD  = 201


# ---------------------------------------------------------------------------
# ヘルパー関数
# ---------------------------------------------------------------------------

def _audit(request, event_type: int, result: int, reason: str | None = None,
           user_id: str | None = None, django_user_id: int | None = None) -> None:
    """全認証イベントを LoginAudit テーブルへ記録する。"""
    LoginAudit.objects.create(
        user_id=user_id,
        django_user_id=django_user_id,
        event_type=event_type,
        result=result,
        event_at=timezone.now(),
        ip_address=request.META.get("REMOTE_ADDR"),
        user_agent=(request.META.get("HTTP_USER_AGENT") or "")[:255] or None,
        session_id=getattr(request.session, "session_key", None),
        reason=reason,
    )


def _make_otp() -> str:
    """6桁の数字 OTP を生成する。"""
    return f"{random.randint(0, 999999):06d}"


def _ensure_session_key(request) -> str | None:
    """セッションキーを確保して返す（セッション束縛に使用）。"""
    if not request.session.session_key:
        request.session.create()
    return request.session.session_key


def _deliver_otp(login_id: str, otp: str, ttl: int) -> None:
    """
    OTP を配信する。

    TELEGRAM_BOT_TOKEN が設定されており、login_id が数値（chat_id）の場合は
    Telegram Bot API で直接送信する。
    それ以外はコンソールログへ出力してフォールバック。

    本番では SnsOutbox 経由で SWMES ワーカーが配信するが、
    OTP は時間的に即時性が必要なため、デモではビュー内で直接送信する。
    """
    logger.info("=" * 52)
    logger.info("[OTP] 宛先  : %s", login_id)
    logger.info("[OTP] コード: %s  (有効期間 %d 秒)", otp, ttl)
    logger.info("=" * 52)

    # chat_id が数値文字列なら Telegram に直接送信を試みる
    token = getattr(settings, "TELEGRAM_BOT_TOKEN", "") or ""
    if token and login_id.lstrip("-").isdigit():
        try:
            telegram_client.send_otp(login_id, otp, ttl)
            logger.info("[OTP] Telegram 送信完了 → chat_id=%s", login_id)
        except Exception as e:
            logger.warning("[OTP] Telegram 送信失敗（コンソールにフォールバック）: %s", e)


def _new_user_id() -> str:
    """
    UserIdSequence テーブルへ INSERT し、生成された pk から USER_ID を導出する。

    MAX(id)+1 ではなく独立したシーケンステーブルを使うことで、
    並行 INSERT 時の重複を防ぐ。
    """
    seq = UserIdSequence.objects.create()
    return f"U{seq.pk:08d}"


def _make_unique_username(login_id: str) -> str:
    """Django auth.User の username 用に内部ユーザー名を生成する（公開しない）。"""
    base = f"u_{login_id[:30]}"
    if not User.objects.filter(username=base).exists():
        return base
    suffix = 2
    while User.objects.filter(username=f"{base}_{suffix}").exists():
        suffix += 1
    return f"{base}_{suffix}"


# ---------------------------------------------------------------------------
# OTP フロー
# ---------------------------------------------------------------------------

@csrf_exempt
def sns_start(request):
    """
    POST /signup/sns/start

    OTP を発行し、送信先へ 6桁コードを届ける。
    本デモでは Django コンソールにログ出力する。

    リクエスト:
        {"sns_type": 1, "login_id": "demo_user"}

    レスポンス:
        {"ok": true, "otp_session_id": 1, "expires_at": "...", "ttl_seconds": 300}
    """
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    try:
        data = json.loads(request.body.decode("utf-8") or "{}")
    except Exception:
        return JsonResponse({"ok": False, "error": "invalid_json"}, status=400)

    sns_type = data.get("sns_type")
    login_id = data.get("login_id")

    if sns_type not in (1, 2):
        return JsonResponse({"ok": False, "error": "sns_type は 1 か 2 を指定してください"}, status=400)
    if not login_id or not isinstance(login_id, str) or len(login_id) > 191:
        return JsonResponse({"ok": False, "error": "login_id は必須（191文字以内）"}, status=400)

    session_key = _ensure_session_key(request)
    now = timezone.now()

    # 連打抑止: 同じ sns_type / login_id で直近 COOLDOWN 秒以内に発行済みなら拒否
    recent = (
        SnsOtpSession.objects
        .filter(sns_type=sns_type, login_id=login_id)
        .order_by("-created_at")
        .first()
    )
    if recent and (now - recent.created_at).total_seconds() < OTP_RESEND_COOLDOWN_SEC:
        retry_after = int(OTP_RESEND_COOLDOWN_SEC - (now - recent.created_at).total_seconds())
        return JsonResponse(
            {"ok": False, "error": "cooldown", "retry_after_sec": max(retry_after, 1)},
            status=429,
        )

    otp = _make_otp()
    expires_at = now + timedelta(seconds=OTP_TTL_SECONDS)

    with transaction.atomic():
        sess = SnsOtpSession.objects.create(
            sns_type=sns_type,
            login_id=login_id,
            session_key=session_key,
            otp_hash=make_password(otp),     # PBKDF2 ハッシュ。平文は保存しない
            max_attempts=OTP_MAX_ATTEMPTS,
            expires_at=expires_at,
            status=SnsOtpSession.Status.PENDING,
        )
        # Transactional Outbox: ビジネストランザクションと同一 atomic ブロック内に書く
        SnsOutbox.objects.create(
            message_type=20,
            delivery_channel=sns_type,
            payload={
                "otp_session_id": sess.id,
                "login_id": login_id,
                "otp": otp,           # ワーカーが配信に使用。デモでは Admin で確認可能。
                "ttl_seconds": OTP_TTL_SECONDS,
            },
        )

    _audit(request, EVT_OTP_START, 1, reason=f"login_id={login_id}")
    _deliver_otp(login_id, otp, OTP_TTL_SECONDS)

    return JsonResponse({
        "ok": True,
        "otp_session_id": sess.id,
        "expires_at": expires_at.isoformat(),
        "ttl_seconds": OTP_TTL_SECONDS,
        "max_attempts": OTP_MAX_ATTEMPTS,
    })


@csrf_exempt
def sns_verify(request):
    """
    POST /signup/sns/verify

    OTP を検証し、成功時に verified_token（TimestampSigner 署名）を発行する。
    この verified_token を signup_complete に渡してアカウント作成を完了させる。

    リクエスト:
        {"otp_session_id": 1, "otp": "123456"}

    レスポンス（成功）:
        {"ok": true, "verified_token": "...:...:..:.."}

    セキュリティ:
      - select_for_update() で並行 POST による二重検証を防ぐ
      - attempt_count が max_attempts に達したらセッションを LOCKED に遷移
      - TimestampSigner の salt を用途ごとに分けることでトークン流用を防ぐ
    """
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    try:
        data = json.loads(request.body.decode("utf-8") or "{}")
    except Exception:
        return JsonResponse({"ok": False, "error": "invalid_json"}, status=400)

    otp_session_id = data.get("otp_session_id")
    otp = data.get("otp")

    if not otp_session_id or not isinstance(otp_session_id, int):
        return JsonResponse({"ok": False, "error": "otp_session_id（整数）は必須"}, status=400)
    if not otp or not re_otp_format(otp):
        return JsonResponse({"ok": False, "error": "otp は6桁の数字"}, status=400)

    now = timezone.now()

    with transaction.atomic():
        try:
            sess = (
                SnsOtpSession.objects
                .select_for_update()
                .get(id=otp_session_id)
            )
        except SnsOtpSession.DoesNotExist:
            _audit(request, EVT_OTP_FAIL, 0, reason="session_not_found")
            return JsonResponse({"ok": False, "error": "セッションが見つかりません"}, status=404)

        # 状態チェック
        if sess.consumed_at is not None:
            return JsonResponse({"ok": False, "error": "このセッションは使用済みです"}, status=400)
        if sess.status == SnsOtpSession.Status.LOCKED:
            return JsonResponse({"ok": False, "error": "試行回数超過によりロックされています"}, status=403)
        if sess.status == SnsOtpSession.Status.EXPIRED or sess.expires_at <= now:
            sess.status = SnsOtpSession.Status.EXPIRED
            sess.save(update_fields=["status"])
            return JsonResponse({"ok": False, "error": "OTP の有効期限が切れています"}, status=400)
        if sess.status == SnsOtpSession.Status.VERIFIED:
            # 冪等: すでに検証済みなら verified_token を再発行して返す
            pass
        else:
            # OTP 検証
            if not check_password(otp, sess.otp_hash):
                sess.attempt_count += 1
                if sess.attempt_count >= sess.max_attempts:
                    sess.status = SnsOtpSession.Status.LOCKED
                    sess.save(update_fields=["attempt_count", "status"])
                    _audit(request, EVT_OTP_FAIL, 0, reason="max_attempts_exceeded")
                    return JsonResponse(
                        {"ok": False, "error": "試行回数上限に達しました。セッションをロックしました"},
                        status=403,
                    )
                sess.save(update_fields=["attempt_count"])
                remaining = sess.max_attempts - sess.attempt_count
                _audit(request, EVT_OTP_FAIL, 0, reason=f"wrong_otp remaining={remaining}")
                return JsonResponse(
                    {"ok": False, "error": "OTP が正しくありません", "remaining_attempts": remaining},
                    status=400,
                )

            # 検証成功
            sess.status = SnsOtpSession.Status.VERIFIED
            sess.verified_at = now
            sess.save(update_fields=["status", "verified_at"])

    # verified_token 発行
    # ペイロード: "{session_id}:{sns_type}:{login_id}"
    # salt を用途別に固定することで、別用途のトークンを流用できないようにする
    signer = TimestampSigner(salt=SIGNUP_VERIFIED_TOKEN_SALT)
    payload = f"{sess.id}:{sess.sns_type}:{sess.login_id}"
    verified_token = signer.sign(payload)

    _audit(request, EVT_OTP_VERIFY, 1, reason=f"session_id={sess.id}")

    return JsonResponse({
        "ok": True,
        "verified_token": verified_token,
        "sns_type": sess.sns_type,
        "login_id": sess.login_id,
    })


def re_otp_format(v) -> bool:
    """OTP が6桁の数字文字列かどうか確認する。"""
    return isinstance(v, str) and len(v) == 6 and v.isdigit()


@csrf_exempt
def signup_complete(request):
    """
    POST /signup/complete

    verified_token を使って会員登録を完了させる。
    Django User + AccountUser を作成し、OTP セッションを consumed 状態にする。

    リクエスト:
        {
            "verified_token": "...",
            "password": "min8chars",
            "personal_name": "山田太郎",
            "personal_name_kana": "ヤマダタロウ",
            "personal_zip": "100-0001",
            "personal_address": "東京都千代田区...",
            "personal_phone_number": "090-1234-5678"
        }

    レスポンス:
        {"ok": true, "user_id": "U00000001"}

    セキュリティ:
      - TimestampSigner.unsign(max_age=600) でトークンの改ざん・期限切れを検証
      - select_for_update() でセッションの競合二重作成を防ぐ
      - User + UserIdSequence + AccountUser の作成を同一 atomic ブロックで行う
    """
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    try:
        data = json.loads(request.body.decode("utf-8") or "{}")
    except Exception:
        return JsonResponse({"ok": False, "error": "invalid_json"}, status=400)

    verified_token = data.get("verified_token", "")
    password       = data.get("password", "")
    personal_name         = data.get("personal_name", "").strip()
    personal_name_kana    = data.get("personal_name_kana", "").strip()
    personal_zip          = data.get("personal_zip", "").strip()
    personal_address      = data.get("personal_address", "").strip()
    personal_phone_number = data.get("personal_phone_number", "").strip()

    # 入力検証
    if not verified_token:
        return JsonResponse({"ok": False, "error": "verified_token は必須"}, status=400)
    if not password or len(password) < 8:
        return JsonResponse({"ok": False, "error": "password は8文字以上"}, status=400)
    for field_name, value in [
        ("personal_name", personal_name),
        ("personal_name_kana", personal_name_kana),
        ("personal_zip", personal_zip),
        ("personal_address", personal_address),
        ("personal_phone_number", personal_phone_number),
    ]:
        if not value:
            return JsonResponse({"ok": False, "error": f"{field_name} は必須"}, status=400)

    # verified_token 検証
    signer = TimestampSigner(salt=SIGNUP_VERIFIED_TOKEN_SALT)
    try:
        payload = signer.unsign(verified_token, max_age=VERIFY_TOKEN_MAX_AGE)
    except SignatureExpired:
        return JsonResponse({"ok": False, "error": "verified_token の有効期限が切れています"}, status=400)
    except BadSignature:
        return JsonResponse({"ok": False, "error": "verified_token が不正です"}, status=400)

    try:
        session_id_str, sns_type_str, login_id = payload.split(":", 2)
        session_id = int(session_id_str)
        sns_type   = int(sns_type_str)
    except (ValueError, AttributeError):
        return JsonResponse({"ok": False, "error": "verified_token の形式が不正です"}, status=400)

    now = timezone.now()

    with transaction.atomic():
        try:
            sess = (
                SnsOtpSession.objects
                .select_for_update()
                .get(id=session_id)
            )
        except SnsOtpSession.DoesNotExist:
            return JsonResponse({"ok": False, "error": "セッションが見つかりません"}, status=404)

        # セッション状態チェック
        if sess.status != SnsOtpSession.Status.VERIFIED:
            return JsonResponse({"ok": False, "error": "OTP 未検証です"}, status=400)
        if sess.consumed_at is not None:
            return JsonResponse({"ok": False, "error": "このセッションは使用済みです"}, status=400)
        if sess.expires_at <= now:
            return JsonResponse({"ok": False, "error": "セッションの有効期限が切れています"}, status=400)
        # トークンの整合性確認（改ざん検知）
        if sess.sns_type != sns_type or sess.login_id != login_id:
            return JsonResponse({"ok": False, "error": "verified_token が不正です"}, status=400)

        # Django User 作成
        username = _make_unique_username(login_id)
        django_user = User.objects.create_user(
            username=username,
            password=password,
        )

        # USER_ID 採番 & AccountUser 作成
        user_id = _new_user_id()
        AccountUser.objects.create(
            user_id=user_id,
            django_user=django_user,
            login_id=login_id,
            sns_type=sns_type,
            sns_contact_id=login_id,
            personal_name=personal_name,
            personal_name_kana=personal_name_kana,
            personal_zip=personal_zip,
            personal_address=personal_address,
            personal_phone_number=personal_phone_number,
        )

        # OTP セッションを consumed 状態に遷移
        sess.consumed_at = now
        sess.consumed_django_user_id = django_user.id
        sess.save(update_fields=["consumed_at", "consumed_django_user_id"])

        # Transactional Outbox: 会員登録完了通知（ワーカーが Telegram へ送信）
        SnsOutbox.objects.create(
            user_id=user_id,
            message_type=30,
            delivery_channel=sns_type,
            payload={
                "user_id": user_id,
                "login_id": login_id,
                "sns_type": sns_type,
                "sns_contact_id": login_id,  # chat_id として使用
            },
        )

    _audit(
        request, EVT_SIGNUP_DONE, 1,
        user_id=user_id, django_user_id=django_user.id,
        reason=f"login_id={login_id}",
    )
    logger.info("[SIGNUP] 新規会員登録完了: user_id=%s login_id=%s", user_id, login_id)

    return JsonResponse({"ok": True, "user_id": user_id})


# ---------------------------------------------------------------------------
# KYC ドキュメントアップロード
# ---------------------------------------------------------------------------

@csrf_exempt
@login_required
def kyc_upload(request):
    """
    POST /signup/kyc/upload  (multipart/form-data, 要ログイン)

    KYC 本人確認書類の画像をアップロードする。

    フォームデータ:
        file     : 画像ファイル（JPEG/PNG, 最大 5MB）
        doc_type : 書類種別（1=運転免許証, 2=パスポート, 3=マイナンバーカード, 4=その他）

    レスポンス:
        {"ok": true, "user_id": "U00000001", "image_id": 0, "preview_url": "/signup/kyc/blob/<token>"}

    本番との差分:
        本番: HashiCorp Vault Transit AES-256-GCM で暗号化して保存
        デモ: base64 エンコードして保存（key_id = "local-base64-demo"）
    """
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    try:
        au = AccountUser.objects.get(django_user=request.user)
    except AccountUser.DoesNotExist:
        return JsonResponse({"ok": False, "error": "アカウントプロファイルが見つかりません"}, status=404)

    f = request.FILES.get("file")
    doc_type_str = request.POST.get("doc_type", "")

    if not f:
        return JsonResponse({"ok": False, "error": "file は必須"}, status=400)
    if not doc_type_str.isdigit() or int(doc_type_str) not in (1, 2, 3, 4):
        return JsonResponse({"ok": False, "error": "doc_type は 1〜4 の整数"}, status=400)

    doc_type = int(doc_type_str)
    mime_type = f.content_type or ""

    if mime_type not in KYC_ALLOWED_MIME_TYPES:
        return JsonResponse(
            {"ok": False, "error": f"対応フォーマット: {', '.join(KYC_ALLOWED_MIME_TYPES)}"},
            status=400,
        )
    if f.size > KYC_UPLOAD_MAX_BYTES:
        mb = KYC_UPLOAD_MAX_BYTES // (1024 * 1024)
        return JsonResponse({"ok": False, "error": f"ファイルサイズは {mb}MB 以内"}, status=400)

    raw = f.read()

    # 暗号化（本番: Vault Transit / デモ: base64）
    ciphertext = base64.b64encode(raw).decode("ascii")
    key_id = "local-base64-demo"

    with transaction.atomic():
        # 既存枚数チェック + image_id 採番
        existing = (
            IdDocument.objects
            .select_for_update()
            .filter(user_id=au.user_id)
            .order_by("image_id")
        )
        if existing.count() >= KYC_MAX_IMAGES:
            return JsonResponse(
                {"ok": False, "error": f"アップロード上限は {KYC_MAX_IMAGES} 枚"},
                status=400,
            )
        used_ids = set(d.image_id for d in existing)
        image_id = next(i for i in range(KYC_MAX_IMAGES) if i not in used_ids)

        doc = IdDocument.objects.create(
            user_id=au.user_id,
            image_id=image_id,
            doc_type=doc_type,
            file_name=f.name or "upload",
            mime_type=mime_type,
            ciphertext=ciphertext,
            key_id=key_id,
        )

        # KYC ステータスを「審査中」へ更新
        au.kyc_status = 1
        au.kyc_last_update = timezone.now()
        au.save(update_fields=["kyc_status", "kyc_last_update"])

        # Transactional Outbox: KYC アップロード通知（ワーカーが Telegram へ送信）
        SnsOutbox.objects.create(
            user_id=au.user_id,
            message_type=40,
            delivery_channel=0,
            payload={
                "user_id": au.user_id,
                "image_id": image_id,
                "doc_type": doc_type,
                "sns_contact_id": au.sns_contact_id,
                "sns_type": au.sns_type,
            },
        )

    # プレビュートークン発行（短命: 60 秒）
    signer = TimestampSigner(salt=KYC_PREVIEW_TOKEN_SALT)
    preview_token = signer.sign(f"{au.user_id}:{image_id}")
    preview_url = f"/signup/kyc/blob/{preview_token}"

    _audit(
        request, EVT_KYC_UPLOAD, 1,
        user_id=au.user_id, django_user_id=request.user.id,
        reason=f"image_id={image_id} doc_type={doc_type}",
    )

    return JsonResponse({
        "ok": True,
        "user_id": au.user_id,
        "image_id": image_id,
        "preview_url": preview_url,
        "expires_in_sec": KYC_PREVIEW_MAX_AGE,
    })


def kyc_blob(request, token: str):
    """
    GET /signup/kyc/blob/<token>

    KYC 画像を透かし付きで返す。

    - トークンは TimestampSigner で署名・有効期限付き（デフォルト 60 秒）
    - 復号後すぐに透かしを合成して返す。透かし付き画像は保存しない。
    - Cache-Control: no-store でブラウザキャッシュを禁止する。
    """
    if request.method != "GET":
        return HttpResponseNotAllowed(["GET"])

    signer = TimestampSigner(salt=KYC_PREVIEW_TOKEN_SALT)
    try:
        payload = signer.unsign(token, max_age=KYC_PREVIEW_MAX_AGE)
    except SignatureExpired:
        return JsonResponse({"ok": False, "error": "プレビュートークンの有効期限が切れています"}, status=400)
    except BadSignature:
        return JsonResponse({"ok": False, "error": "プレビュートークンが不正です"}, status=400)

    try:
        user_id, image_id_str = payload.split(":", 1)
        image_id = int(image_id_str)
    except (ValueError, AttributeError):
        return JsonResponse({"ok": False, "error": "トークン形式が不正です"}, status=400)

    try:
        doc = IdDocument.objects.get(user_id=user_id, image_id=image_id)
    except IdDocument.DoesNotExist:
        return JsonResponse({"ok": False, "error": "ドキュメントが見つかりません"}, status=404)

    # 復号（本番: Vault Transit / デモ: base64 デコード）
    raw = base64.b64decode(doc.ciphertext)

    # 透かし合成（Pillow）
    watermarked, mime, _ = add_watermark(raw, user_id)

    resp = HttpResponse(watermarked, content_type=mime)
    resp["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return resp


# ---------------------------------------------------------------------------
# 会員登録フォーム（ブラウザ向け）
# ---------------------------------------------------------------------------

def register(request):
    """
    GET /signup/register/

    ステップ式の会員登録フォームを返す。
    JavaScript から JSON API（sns/start → sns/verify → complete）を呼ぶ SPA 構成。
    """
    return render(request, "signup/register.html", {
        "portal_base_url": getattr(settings, "PORTAL_BASE_URL", "http://127.0.0.1:8000"),
    })


# ---------------------------------------------------------------------------
# Telegram Bot Webhook
# ---------------------------------------------------------------------------

@csrf_exempt
def tg_webhook(request):
    """
    POST /signup/tg/webhook

    Telegram が送ってくる Update を受け取り、コマンドに応じて返信する。

    認識するコマンド:
      /start          → あなたの chat_id を返信（サインアップ時に使う）
      /login ログイン → ログインページ URL を返信
      /help  ヘルプ   → コマンド一覧を返信

    セキュリティ:
      - TELEGRAM_WEBHOOK_SECRET が設定されている場合、
        X-Telegram-Bot-Api-Secret-Token ヘッダーを検証する
      - 署名が一致しない場合は 403 を返す

    本番との対応:
      SWMES.py の /telegram_webhook エンドポイント + _command_handlers() に相当。
      本番は FastAPI + 非同期だが、デモは Django の同期ビューで実装。
    """
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    # Webhook secret 検証
    webhook_secret = getattr(settings, "TELEGRAM_WEBHOOK_SECRET", "") or ""
    if webhook_secret:
        received = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
        if received != webhook_secret:
            return JsonResponse({"ok": False, "error": "forbidden"}, status=403)

    try:
        update = json.loads(request.body.decode("utf-8"))
    except Exception:
        return JsonResponse({"ok": False, "error": "invalid_json"}, status=400)

    msg      = (update or {}).get("message") or {}
    text     = (msg.get("text") or "").strip()
    chat     = msg.get("chat") or {}
    chat_id  = chat.get("id")
    username = (chat.get("username") or "").strip()

    if not chat_id or not text:
        return JsonResponse({"ok": True})

    try:
        _handle_tg_command(chat_id=chat_id, username=username, text=text)
    except Exception as e:
        logger.error("[tg_webhook] 処理エラー: %s", e, exc_info=True)

    return JsonResponse({"ok": True})


def _handle_tg_command(chat_id: int, username: str, text: str) -> None:
    """
    受信テキストを解析してコマンドを実行し、Telegram へ返信する。
    SWMES.py の _classify_command() + _command_handlers() に相当。
    """
    token = getattr(settings, "TELEGRAM_BOT_TOKEN", "") or ""
    if not token:
        logger.warning("[tg_webhook] TELEGRAM_BOT_TOKEN が未設定のため返信できません。")
        return

    t = text.strip()
    chat_id_str = str(chat_id)

    # /start — chat_id を案内する
    if t.startswith("/start"):
        reply = (
            f"ShiningWish へようこそ！\n\n"
            f"あなたの Telegram チャット ID は:\n"
            f"  {chat_id}\n\n"
            "サインアップ時に「チャット ID」欄へこの番号を入力してください。\n\n"
            "コマンド一覧は「ヘルプ」または /help で確認できます。"
        )
        telegram_client.send_message(chat_id_str, reply)
        return

    # /login または「ログイン」
    if t in ("ログイン",) or t.startswith("/login"):
        au = (
            AccountUser.objects
            .filter(sns_type=1, sns_contact_id=chat_id_str)
            .first()
        )
        if not au:
            # @username でも検索
            if username:
                au = AccountUser.objects.filter(
                    sns_type=1, login_id=f"@{username}"
                ).first()

        if not au:
            telegram_client.send_message(
                chat_id_str,
                "アカウントが見つかりませんでした。\n先にサインアップページでアカウントを作成してください。",
            )
            return

        base = getattr(settings, "PORTAL_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
        login_url = f"{base}/portal/login/"
        telegram_client.send_message(
            chat_id_str,
            f"ログインページはこちらです:\n{login_url}\n\nUSER ID: {au.user_id}",
        )
        return

    # /help または「ヘルプ」
    if t in ("ヘルプ",) or t.startswith("/help"):
        reply = (
            "ShiningWish Bot コマンド一覧\n\n"
            "/start  — あなたの chat_id を確認する\n"
            "ログイン / /login — ログインページ URL を送る\n"
            "ヘルプ  / /help  — このメッセージを表示する"
        )
        telegram_client.send_message(chat_id_str, reply)
        return

    # 未認識コマンド
    telegram_client.send_message(
        chat_id_str,
        "コマンドを認識できませんでした。「ヘルプ」または /help でコマンド一覧を確認してください。",
    )
