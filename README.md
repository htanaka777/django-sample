# django-sample

Django 5.2 による会員登録・KYC システムのサンプル実装です。

**Telegram Bot 連携付き**のフル動作デモ:  
ブラウザで登録フォームを開き → Telegram で OTP を受信 → アカウント作成 → ログイン
という一連のフローを実際に体験できます。

---

## 実証しているアーキテクチャパターン

| パターン | 実装箇所 |
|---|---|
| OTP 状態機械（PENDING → VERIFIED → consumed） | `signup/models.py` `SnsOtpSession` |
| PBKDF2 ハッシュによる OTP 保存（平文非保存） | `signup/views.py` `make_password()` / `check_password()` |
| TimestampSigner トークンフロー（用途別 salt） | `signup/views.py` `sns_verify` → `signup_complete` |
| Transactional Outbox パターン | `SnsOutbox` + `transaction.atomic()` |
| `select_for_update()` による競合防止 | `sns_verify`, `signup_complete` |
| カスタム認証バックエンド（USER_ID 形式ログイン） | `signup/auth_backend.py` |
| 全認証イベントの監査ログ | `signup/models.py` `LoginAudit` |
| Pillow による透かし処理（RGBA 合成） | `signup/kyc_utils.py` |
| configparser + dotenv による設定分離 | `sww/settings.py` |
| Telegram Bot webhook ハンドラ | `signup/views.py` `tg_webhook` |
| メッセージワーカー（楽観的ロック + リトライ） | `signup/management/commands/run_worker.py` |

---

## セットアップ・起動方法

### 1. 依存パッケージのインストール

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. 環境変数の設定

```bash
cp .env.example .env
# .env を開いて DJANGO_SECRET_KEY に任意の50文字以上の文字列を設定
```

### 3. Telegram Bot の準備

1. Telegram で **@BotFather** を開き `/newbot` でボットを作成
2. 発行された **Bot Token** をコピー
3. `config.ini` を開いて設定:

```ini
[TELEGRAM]
bot_token     = 1234567890:ABCDefGhIJKlmNOpqrSTUvwxYZ
webhook_secret = (任意のランダム文字列)
portal_base_url = https://your-ngrok-url.ngrok-free.app
```

### 4. ngrok でローカルサーバーを公開（Webhook 受信に必要）

Telegram Webhook はインターネットから到達できる URL が必要なため、
ローカル開発では ngrok を使います。

```bash
# ngrok をインストール後:
ngrok http 8000
```

表示された `https://xxxx.ngrok-free.app` を `config.ini` の `portal_base_url` に設定。

### 5. Webhook を Telegram に登録

```bash
# Bot Token と ngrok URL を使って Webhook を登録
curl "https://api.telegram.org/bot<TOKEN>/setWebhook" \
  -d "url=https://xxxx.ngrok-free.app/signup/tg/webhook" \
  -d "secret_token=<webhook_secret と同じ値>"
```

### 6. マイグレーション & 起動

```bash
python manage.py migrate
python manage.py createsuperuser   # Django Admin 用（任意）

# ターミナル 1: Django 開発サーバー
python manage.py runserver

# ターミナル 2: メッセージワーカー（SnsOutbox を Telegram へ配信）
python manage.py run_worker
```

---

## 使い方（実際のデモフロー）

### 1. チャット ID の確認

作成した Telegram Bot に **`/start`** と送る  
→ ボットが「あなたの Telegram チャット ID は: `1234567890`」と返信

### 2. 会員登録

ブラウザで `http://localhost:8000/` を開く（自動的に登録フォームへリダイレクト）

1. チャット ID を入力して「OTP を送信」
2. Telegram に届いた 6桁コードを入力
3. 氏名・住所・パスワードを入力して「登録を完了する」
4. **USER_ID（例: U00000001）** が発行される  
   → Telegram にも「ShiningWish へようこそ！」通知が届く

### 3. ログイン

`http://localhost:8000/portal/login/` で USER_ID + パスワードでログイン  
→ マイページ表示

### 4. Bot コマンド

| コマンド | 動作 |
|---|---|
| `/start` | チャット ID を確認 |
| `ログイン` または `/login` | ログインページ URL を受信 |
| `ヘルプ` または `/help` | コマンド一覧を表示 |

---

## 本番環境との差分

| 本デモ | 本番相当の実装 |
|---|---|
| SQLite | MySQL 8 (utf8mb4) |
| base64 エンコードして DB に保存 | HashiCorp Vault Transit AES-256-GCM 暗号化 |
| Django 標準 LoginView | django-allauth + TOTP / WebAuthn (FIDO2) MFA |
| セッション束縛なし | `SNS_OTP_REQUIRE_SAME_SESSION=True` でブラウザ Cookie 束縛 |
| run_worker 管理コマンド（単一ループ） | FastAPI + マルチスレッド（SWMES.py） |

---

## ディレクトリ構成

```
django-sample/
├── manage.py
├── requirements.txt              # Django, Pillow, python-dotenv, requests
├── config.ini                    # [TELEGRAM] セクション含む実行時設定
├── .env.example                  # 秘密情報テンプレート
├── sww/
│   ├── settings.py               # configparser + dotenv パターン
│   └── urls.py
├── signup/
│   ├── models.py                 # 6モデル
│   ├── views.py                  # OTP/signup/KYC/webhook エンドポイント
│   ├── auth_backend.py           # USER_ID ログインバックエンド
│   ├── kyc_utils.py              # Pillow 透かし処理
│   ├── telegram_client.py        # Telegram Bot API ラッパー
│   ├── admin.py
│   ├── management/commands/
│   │   └── run_worker.py         # SnsOutbox ポーリングワーカー
│   └── templates/signup/
│       └── register.html         # ステップ式登録フォーム（SPA）
└── portal/
    ├── views.py                  # ログイン・マイページ
    └── templates/portal/
        ├── login.html
        └── mypage.html           # KYC アップロード・監査ログ表示
```

---

## 動作環境

- Python 3.11+
- Django 5.2
- Pillow 10+
- requests 2.31+
