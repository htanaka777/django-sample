from django.contrib import admin
from .models import SnsOtpSession, SnsOutbox, LoginAudit, AccountUser, IdDocument, UserIdSequence


@admin.register(SnsOtpSession)
class SnsOtpSessionAdmin(admin.ModelAdmin):
    list_display  = ("id", "sns_type", "login_id", "status", "attempt_count", "expires_at", "verified_at", "consumed_at")
    list_filter   = ("status", "sns_type")
    search_fields = ("login_id",)
    readonly_fields = ("otp_hash",)   # ハッシュは表示するが編集不可（平文復元不可であることを示す）
    ordering = ("-created_at",)


@admin.register(SnsOutbox)
class SnsOutboxAdmin(admin.ModelAdmin):
    list_display  = ("id", "user_id", "message_type", "delivery_channel", "status", "retry_count", "created_at", "sent_at")
    list_filter   = ("status", "message_type")
    search_fields = ("user_id", "correlation_id")
    readonly_fields = ("payload",)
    ordering = ("-created_at",)


@admin.register(LoginAudit)
class LoginAuditAdmin(admin.ModelAdmin):
    list_display  = ("id", "event_type", "result", "user_id", "ip_address", "reason", "event_at")
    list_filter   = ("result", "event_type")
    search_fields = ("user_id", "reason", "ip_address")
    ordering = ("-event_at",)


@admin.register(AccountUser)
class AccountUserAdmin(admin.ModelAdmin):
    list_display  = ("user_id", "login_id", "sns_type", "kyc_status", "is_active", "created_at")
    list_filter   = ("sns_type", "kyc_status", "is_active")
    search_fields = ("user_id", "login_id", "personal_name")
    readonly_fields = ("user_id", "created_at", "updated_at")


@admin.register(IdDocument)
class IdDocumentAdmin(admin.ModelAdmin):
    list_display  = ("user_id", "image_id", "doc_type", "file_name", "mime_type", "key_id", "created_at")
    list_filter   = ("doc_type", "mime_type")
    search_fields = ("user_id",)
    readonly_fields = ("ciphertext",)   # 暗号文は読み取り専用（デモでは base64）


@admin.register(UserIdSequence)
class UserIdSequenceAdmin(admin.ModelAdmin):
    list_display = ("id", "created_at")
    readonly_fields = ("id", "created_at")
