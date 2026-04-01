"""
signup アプリのモデル定義

本番 (SWWEB1) と同一の設計。
外部依存（MySQL固有構文, Vault等）を持たないため、SQLite でそのまま動作する。
"""

from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


# ---------------------------------------------------------------------------
# OTP セッション
# ---------------------------------------------------------------------------

class SnsOtpSession(models.Model):
    """
    SNS（Telegram/Signal）経由の OTP 認証セッション。

    状態遷移: PENDING → VERIFIED → (consumed_at が設定される)
                        └→ LOCKED  （試行超過）
              PENDING → EXPIRED    （TTL切れ）

    セキュリティ設計:
      - otp_hash: Django の make_password() で PBKDF2 ハッシュ化して保存。
                  平文 OTP はメモリと SnsOutbox.payload にのみ存在する。
      - attempt_count / max_attempts: ブルートフォース対策のロックアウト。
    """

    class Status(models.IntegerChoices):
        PENDING  = 0, "PENDING"
        VERIFIED = 1, "VERIFIED"
        EXPIRED  = 2, "EXPIRED"
        LOCKED   = 3, "LOCKED"

    id            = models.BigAutoField(primary_key=True)
    sns_type      = models.PositiveSmallIntegerField()          # 1=デモ（本番: 1=Telegram, 2=Signal）
    login_id      = models.CharField(max_length=191)            # ユーザーが入力したハンドル名等
    session_key   = models.CharField(max_length=64, null=True, blank=True)  # ブラウザセッションの束縛用
    otp_hash      = models.CharField(max_length=256)            # PBKDF2 ハッシュ（平文非保存）
    max_attempts  = models.PositiveSmallIntegerField(default=5)
    attempt_count = models.PositiveSmallIntegerField(default=0)
    expires_at    = models.DateTimeField()
    status        = models.PositiveSmallIntegerField(
        default=Status.PENDING, choices=Status.choices
    )
    created_at    = models.DateTimeField(default=timezone.now)
    verified_at   = models.DateTimeField(null=True, blank=True)
    consumed_at   = models.DateTimeField(null=True, blank=True)
    consumed_django_user_id = models.BigIntegerField(null=True, blank=True)

    class Meta:
        db_table = "sns_otp_sessions"
        indexes = [
            models.Index(fields=["sns_type", "login_id", "status", "expires_at"]),
            models.Index(fields=["created_at"]),
        ]

    def __str__(self):
        return f"OtpSession(id={self.id}, login_id={self.login_id}, status={self.get_status_display()})"


# ---------------------------------------------------------------------------
# SNS 送信アウトボックス（Transactional Outbox パターン）
# ---------------------------------------------------------------------------

class SnsOutbox(models.Model):
    """
    Transactional Outbox パターンの実装。

    ビジネスロジック（OTP発行・会員登録）と同一トランザクション内に書き込む。
    → トランザクションがロールバックされれば、このレコードも消える。
    → コミットされれば、ワーカーが確実に配信する。

    本番環境では外部ワーカー (SWMES.py) がこのテーブルをポーリングし、
    Telegram / Signal へメッセージを配信する。
    本デモでは Django Admin でレコードを確認できる。

    message_type:
      20 = OTP 送信
      30 = 会員登録完了通知
      40 = KYC ドキュメントアップロード通知
    """

    id               = models.BigAutoField(primary_key=True)
    user_id          = models.CharField(max_length=9, null=True, blank=True)
    message_type     = models.PositiveSmallIntegerField()
    delivery_channel = models.PositiveSmallIntegerField(default=0)  # 0=AUTO, 1=Telegram, 2=Signal
    priority         = models.PositiveSmallIntegerField(default=1)
    status           = models.PositiveSmallIntegerField(default=0)  # 0=PENDING, 1=SENT, 2=FAILED
    retry_count      = models.PositiveIntegerField(default=0)
    payload          = models.JSONField()
    correlation_id   = models.CharField(max_length=64, null=True, blank=True)
    error_message    = models.CharField(max_length=255, null=True, blank=True)
    created_at       = models.DateTimeField(default=timezone.now)
    sent_at          = models.DateTimeField(null=True, blank=True)
    updated_at       = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "sns_outbox"
        indexes = [
            models.Index(fields=["status", "created_at"]),
            models.Index(fields=["user_id", "status"]),
        ]

    def __str__(self):
        return f"SnsOutbox(id={self.id}, type={self.message_type}, status={self.status})"


# ---------------------------------------------------------------------------
# ログイン監査ログ
# ---------------------------------------------------------------------------

class LoginAudit(models.Model):
    """
    認証系イベントの監査ログ。

    セキュリティ・コンプライアンス要件を満たすため、
    OTP 送信・検証・会員登録・ログイン等の全イベントを記録する。

    event_type の値:
      101 = OTP 送信
      102 = OTP 検証成功
      103 = OTP 検証失敗
      110 = 会員登録開始（verified_token 発行）
      111 = 会員登録完了
      201 = KYC ドキュメントアップロード
      301 = ログイン成功
      302 = ログイン失敗
    """

    id             = models.BigAutoField(primary_key=True)
    user_id        = models.CharField(max_length=9, null=True, blank=True)
    django_user_id = models.BigIntegerField(null=True, blank=True)
    event_type     = models.PositiveSmallIntegerField()
    result         = models.PositiveSmallIntegerField()          # 1=成功, 0=失敗
    event_at       = models.DateTimeField(default=timezone.now)
    ip_address     = models.CharField(max_length=45, null=True, blank=True)
    user_agent     = models.CharField(max_length=255, null=True, blank=True)
    session_id     = models.CharField(max_length=64, null=True, blank=True)
    reason         = models.CharField(max_length=255, null=True, blank=True)
    created_at     = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "login_audit"
        indexes = [
            models.Index(fields=["user_id", "event_at"]),
            models.Index(fields=["event_type", "event_at"]),
        ]

    def __str__(self):
        return f"LoginAudit(type={self.event_type}, result={self.result}, user={self.user_id})"


# ---------------------------------------------------------------------------
# ユーザーID 採番テーブル
# ---------------------------------------------------------------------------

class UserIdSequence(models.Model):
    """
    ユーザーID (U00000001 形式) の採番用テーブル。

    INSERT → 生成された pk を使って "U" + str(pk).zfill(8) を導出する。
    MAX(id)+1 ではなく独立したシーケンステーブルを使うことで、
    並行INSERT時の重複を防ぐ。（SQLite の AUTOINCREMENT 保証を利用）
    """

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "user_id_sequence"


# ---------------------------------------------------------------------------
# アカウントユーザー（ドメインユーザープロファイル）
# ---------------------------------------------------------------------------

class AccountUser(models.Model):
    """
    Django の auth.User を 1:1 で拡張するドメインプロファイル。

    user_id (U00000001) を主キーとして使用する。
    ログインは login_id（SNS ハンドル名等）または user_id で行う。
    """

    user_id        = models.CharField(max_length=9, primary_key=True, db_column="USER_ID")
    django_user    = models.OneToOneField(
        User, on_delete=models.CASCADE, db_column="DJANGO_USER_ID"
    )
    login_id       = models.CharField(max_length=191, db_column="LOGIN_ID")
    sns_type       = models.PositiveSmallIntegerField(db_column="SNS_TYPE")
    sns_contact_id = models.CharField(max_length=128, db_column="SNS_CONTACT_ID")

    # 個人情報
    personal_name         = models.CharField(max_length=128, db_column="PERSONAL_NAME")
    personal_name_kana    = models.CharField(max_length=128, db_column="PERSONAL_NAME_KANA")
    personal_zip          = models.CharField(max_length=8,   db_column="PERSONAL_ZIP")
    personal_address      = models.CharField(max_length=512, db_column="PERSONAL_ADDRESS")
    personal_phone_number = models.CharField(max_length=20,  db_column="PERSONAL_PHONE_NUMBER")

    permission  = models.PositiveSmallIntegerField(default=1, db_column="PERMISSION")
    is_active   = models.PositiveSmallIntegerField(default=1, db_column="IS_ACTIVE")

    # KYC ステータス
    kyc_status      = models.PositiveSmallIntegerField(default=0, db_column="KYC_STATUS")
    kyc_level       = models.PositiveSmallIntegerField(default=0, db_column="KYC_LEVEL")
    kyc_last_update = models.DateTimeField(null=True, blank=True, db_column="KYC_LAST_UPDATE")

    last_login  = models.DateTimeField(null=True, blank=True, db_column="LAST_LOGIN")
    created_at  = models.DateTimeField(auto_now_add=True, db_column="CREATED_AT")
    updated_at  = models.DateTimeField(auto_now=True,     db_column="UPDATED_AT")

    class Meta:
        db_table = "account_users"

    def __str__(self):
        return f"{self.user_id} ({self.login_id})"

    @property
    def kyc_status_label(self):
        return {0: "未提出", 1: "審査中", 2: "承認済", 9: "否認"}.get(self.kyc_status, "不明")


# ---------------------------------------------------------------------------
# KYC ドキュメント
# ---------------------------------------------------------------------------

class IdDocument(models.Model):
    """
    KYC（本人確認）書類の保管テーブル。

    本番環境では ciphertext フィールドに HashiCorp Vault Transit の暗号文を保存する。
    本デモでは base64(生バイト) を保存する（key_id = "local-base64-demo" で識別可能）。

    doc_type:
      1 = 運転免許証
      2 = パスポート
      3 = マイナンバーカード
      4 = その他
    """

    user_id    = models.CharField(max_length=9)
    image_id   = models.PositiveSmallIntegerField()         # 0〜4（ユーザー内の連番）
    doc_type   = models.PositiveSmallIntegerField()
    file_name  = models.CharField(max_length=255)
    mime_type  = models.CharField(max_length=50)
    ciphertext = models.TextField()                         # 本番: Vault Transit 暗号文 / デモ: base64
    key_id     = models.CharField(max_length=64, default="local-base64-demo")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "id_documents"
        unique_together = (("user_id", "image_id"),)

    def __str__(self):
        return f"IdDocument(user={self.user_id}, image_id={self.image_id}, type={self.doc_type})"
