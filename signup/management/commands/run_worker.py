"""
signup/management/commands/run_worker.py

SnsOutbox テーブルをポーリングし、Telegram Bot API でメッセージを配信するワーカー。

起動:
    python manage.py run_worker

本番 SWMES.py との対応:
  - SWMES.py の _worker_loop() / _process_one() / _send_message() に相当
  - 本番は FastAPI + 複数スレッド構成だが、デモは Django 管理コマンドの単一ループで実装
  - 楽観的ロック（status 0→1）で複数起動時の二重送信を防ぐ設計は同じ

message_type:
  20 = OTP 送信
  30 = 会員登録完了通知
  40 = KYC アップロード通知

status:
  0 = PENDING
  1 = PROCESSING (ロック取得中)
  2 = SENT
  9 = FAILED
"""

import logging
import signal
import time

from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from signup.models import SnsOutbox
from signup import telegram_client

logger = logging.getLogger("signup")

POLL_INTERVAL   = 5    # 秒
MAX_RETRY       = 3    # 送信失敗リトライ上限
BATCH_SIZE      = 20   # 1ポーリングあたりの最大処理件数

STATUS_PENDING    = 0
STATUS_PROCESSING = 1
STATUS_SENT       = 2
STATUS_FAILED     = 9

MSG_OTP     = 20
MSG_WELCOME = 30
MSG_KYC     = 40


class Command(BaseCommand):
    help = "SnsOutbox をポーリングして Telegram でメッセージを配信するワーカー"

    def handle(self, *args, **options):
        self._stop = False

        # Ctrl+C / SIGTERM でグレースフルシャットダウン
        signal.signal(signal.SIGINT,  self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

        self.stdout.write(
            self.style.SUCCESS(
                f"[run_worker] 起動しました (poll_interval={POLL_INTERVAL}秒, batch={BATCH_SIZE})"
            )
        )

        while not self._stop:
            try:
                rows = self._poll_pending()
                for row in rows:
                    if self._stop:
                        break
                    self._process_one(row)
            except Exception as e:
                logger.error("[run_worker] ポーリングエラー: %s", e, exc_info=True)

            # インターバル待機（SIGINT を受けたらすぐ抜ける）
            for _ in range(POLL_INTERVAL * 10):
                if self._stop:
                    break
                time.sleep(0.1)

        self.stdout.write(self.style.WARNING("[run_worker] 停止しました"))

    def _handle_signal(self, signum, frame):
        self.stdout.write(self.style.WARNING("\n[run_worker] 停止シグナルを受信しました。終了します..."))
        self._stop = True

    # ------------------------------------------------------------------
    # ポーリング
    # ------------------------------------------------------------------

    def _poll_pending(self) -> list:
        """PENDING 行を優先度・時刻順に取得する。"""
        return list(
            SnsOutbox.objects
            .filter(status=STATUS_PENDING)
            .order_by("priority", "created_at")[:BATCH_SIZE]
        )

    # ------------------------------------------------------------------
    # 1行処理
    # ------------------------------------------------------------------

    def _process_one(self, row: SnsOutbox) -> None:
        """
        楽観的ロックで行を取得し、送信 → 結果を記録する。

        SWMES.py の _claim_row() + _process_one() に相当。
        status=0 → 1 の UPDATE が 0件なら他プロセスが先取り済みなのでスキップ。
        """
        # 楽観的ロック: status=PENDING → PROCESSING
        updated = SnsOutbox.objects.filter(
            id=row.id, status=STATUS_PENDING
        ).update(status=STATUS_PROCESSING, updated_at=timezone.now())

        if not updated:
            logger.debug("[run_worker] id=%d は他プロセスが取得済み。スキップ。", row.id)
            return

        row.refresh_from_db()
        logger.info(
            "[run_worker] 処理開始 id=%d type=%d channel=%d",
            row.id, row.message_type, row.delivery_channel,
        )

        try:
            self._send_message(row)
            SnsOutbox.objects.filter(id=row.id).update(
                status=STATUS_SENT,
                sent_at=timezone.now(),
                updated_at=timezone.now(),
            )
            logger.info("[run_worker] 送信完了 id=%d", row.id)
        except Exception as e:
            err = str(e)[:255]
            logger.warning("[run_worker] 送信失敗 id=%d: %s", row.id, err)
            new_status = STATUS_PENDING if row.retry_count < MAX_RETRY else STATUS_FAILED
            SnsOutbox.objects.filter(id=row.id).update(
                status=new_status,
                retry_count=row.retry_count + 1,
                error_message=err,
                updated_at=timezone.now(),
            )
            if new_status == STATUS_FAILED:
                logger.error("[run_worker] id=%d が最大リトライに達しました (FAILED)。", row.id)

    # ------------------------------------------------------------------
    # メッセージ送信ディスパッチ
    # ------------------------------------------------------------------

    def _send_message(self, row: SnsOutbox) -> None:
        """
        message_type に応じて適切な送信メソッドへディスパッチする。
        SWMES.py の _send_message() + _format_message_body() に相当。
        """
        payload = row.payload or {}
        chat_id = str(payload.get("sns_contact_id") or payload.get("chat_id") or "")

        if not chat_id:
            # sns_contact_id がない場合は送信不要（ログのみ）
            logger.info("[run_worker] sns_contact_id なし id=%d type=%d → スキップ", row.id, row.message_type)
            return

        if row.message_type == MSG_OTP:
            otp = payload.get("otp", "------")
            ttl = payload.get("ttl_seconds", 300)
            telegram_client.send_otp(chat_id, otp, ttl)

        elif row.message_type == MSG_WELCOME:
            user_id = payload.get("user_id", "")
            telegram_client.send_welcome(chat_id, user_id)

        elif row.message_type == MSG_KYC:
            telegram_client.send_kyc_received(chat_id)

        else:
            # 未知タイプは payload をそのまま文字列化して送信
            import json
            text = payload.get("text") or json.dumps(payload, ensure_ascii=False)
            telegram_client.send_message(chat_id, text)
