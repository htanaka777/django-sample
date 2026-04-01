from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="UserIdSequence",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
            ],
            options={"db_table": "user_id_sequence"},
        ),
        migrations.CreateModel(
            name="SnsOtpSession",
            fields=[
                ("id", models.BigAutoField(primary_key=True, serialize=False)),
                ("sns_type", models.PositiveSmallIntegerField()),
                ("login_id", models.CharField(max_length=191)),
                ("session_key", models.CharField(blank=True, max_length=64, null=True)),
                ("otp_hash", models.CharField(max_length=256)),
                ("max_attempts", models.PositiveSmallIntegerField(default=5)),
                ("attempt_count", models.PositiveSmallIntegerField(default=0)),
                ("expires_at", models.DateTimeField()),
                ("status", models.PositiveSmallIntegerField(
                    choices=[(0, "PENDING"), (1, "VERIFIED"), (2, "EXPIRED"), (3, "LOCKED")],
                    default=0,
                )),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("verified_at", models.DateTimeField(blank=True, null=True)),
                ("consumed_at", models.DateTimeField(blank=True, null=True)),
                ("consumed_django_user_id", models.BigIntegerField(blank=True, null=True)),
            ],
            options={"db_table": "sns_otp_sessions"},
        ),
        migrations.AddIndex(
            model_name="snsotpsession",
            index=models.Index(
                fields=["sns_type", "login_id", "status", "expires_at"],
                name="sns_otp_ses_sns_typ_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="snsotpsession",
            index=models.Index(fields=["created_at"], name="sns_otp_ses_created_idx"),
        ),
        migrations.CreateModel(
            name="SnsOutbox",
            fields=[
                ("id", models.BigAutoField(primary_key=True, serialize=False)),
                ("user_id", models.CharField(blank=True, max_length=9, null=True)),
                ("message_type", models.PositiveSmallIntegerField()),
                ("delivery_channel", models.PositiveSmallIntegerField(default=0)),
                ("priority", models.PositiveSmallIntegerField(default=1)),
                ("status", models.PositiveSmallIntegerField(default=0)),
                ("retry_count", models.PositiveIntegerField(default=0)),
                ("payload", models.JSONField()),
                ("correlation_id", models.CharField(blank=True, max_length=64, null=True)),
                ("error_message", models.CharField(blank=True, max_length=255, null=True)),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("sent_at", models.DateTimeField(blank=True, null=True)),
                ("updated_at", models.DateTimeField(default=django.utils.timezone.now)),
            ],
            options={"db_table": "sns_outbox"},
        ),
        migrations.AddIndex(
            model_name="snsoutbox",
            index=models.Index(fields=["status", "created_at"], name="sns_outbox_status_idx"),
        ),
        migrations.AddIndex(
            model_name="snsoutbox",
            index=models.Index(fields=["user_id", "status"], name="sns_outbox_user_idx"),
        ),
        migrations.CreateModel(
            name="LoginAudit",
            fields=[
                ("id", models.BigAutoField(primary_key=True, serialize=False)),
                ("user_id", models.CharField(blank=True, max_length=9, null=True)),
                ("django_user_id", models.BigIntegerField(blank=True, null=True)),
                ("event_type", models.PositiveSmallIntegerField()),
                ("result", models.PositiveSmallIntegerField()),
                ("event_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("ip_address", models.CharField(blank=True, max_length=45, null=True)),
                ("user_agent", models.CharField(blank=True, max_length=255, null=True)),
                ("session_id", models.CharField(blank=True, max_length=64, null=True)),
                ("reason", models.CharField(blank=True, max_length=255, null=True)),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now)),
            ],
            options={"db_table": "login_audit"},
        ),
        migrations.AddIndex(
            model_name="loginaudit",
            index=models.Index(fields=["user_id", "event_at"], name="login_audit_user_idx"),
        ),
        migrations.AddIndex(
            model_name="loginaudit",
            index=models.Index(fields=["event_type", "event_at"], name="login_audit_type_idx"),
        ),
        migrations.CreateModel(
            name="AccountUser",
            fields=[
                ("user_id", models.CharField(db_column="USER_ID", max_length=9, primary_key=True, serialize=False)),
                ("django_user", models.OneToOneField(
                    db_column="DJANGO_USER_ID",
                    on_delete=django.db.models.deletion.CASCADE,
                    to=settings.AUTH_USER_MODEL,
                )),
                ("login_id", models.CharField(db_column="LOGIN_ID", max_length=191)),
                ("sns_type", models.PositiveSmallIntegerField(db_column="SNS_TYPE")),
                ("sns_contact_id", models.CharField(db_column="SNS_CONTACT_ID", max_length=128)),
                ("personal_name", models.CharField(db_column="PERSONAL_NAME", max_length=128)),
                ("personal_name_kana", models.CharField(db_column="PERSONAL_NAME_KANA", max_length=128)),
                ("personal_zip", models.CharField(db_column="PERSONAL_ZIP", max_length=8)),
                ("personal_address", models.CharField(db_column="PERSONAL_ADDRESS", max_length=512)),
                ("personal_phone_number", models.CharField(db_column="PERSONAL_PHONE_NUMBER", max_length=20)),
                ("permission", models.PositiveSmallIntegerField(db_column="PERMISSION", default=1)),
                ("is_active", models.PositiveSmallIntegerField(db_column="IS_ACTIVE", default=1)),
                ("kyc_status", models.PositiveSmallIntegerField(db_column="KYC_STATUS", default=0)),
                ("kyc_level", models.PositiveSmallIntegerField(db_column="KYC_LEVEL", default=0)),
                ("kyc_last_update", models.DateTimeField(blank=True, db_column="KYC_LAST_UPDATE", null=True)),
                ("last_login", models.DateTimeField(blank=True, db_column="LAST_LOGIN", null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_column="CREATED_AT")),
                ("updated_at", models.DateTimeField(auto_now=True, db_column="UPDATED_AT")),
            ],
            options={"db_table": "account_users"},
        ),
        migrations.CreateModel(
            name="IdDocument",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ("user_id", models.CharField(max_length=9)),
                ("image_id", models.PositiveSmallIntegerField()),
                ("doc_type", models.PositiveSmallIntegerField()),
                ("file_name", models.CharField(max_length=255)),
                ("mime_type", models.CharField(max_length=50)),
                ("ciphertext", models.TextField()),
                ("key_id", models.CharField(default="local-base64-demo", max_length=64)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"db_table": "id_documents"},
        ),
        migrations.AlterUniqueTogether(
            name="iddocument",
            unique_together={("user_id", "image_id")},
        ),
    ]
