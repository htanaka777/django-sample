from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import User
from .models import AccountUser


class AccountLoginBackend(BaseBackend):
    """
    username 欄に USER_ID（U00000001 形式）を入れてログインできるようにする。

    Django 標準の ModelBackend はユーザー名（username フィールド）でしか
    認証できないため、ドメイン固有の USER_ID ログインにはカスタムバックエンドが必要。

    settings.py の AUTHENTICATION_BACKENDS に登録することで有効になる:
        AUTHENTICATION_BACKENDS = [
            "signup.auth_backend.AccountLoginBackend",
            "django.contrib.auth.backends.ModelBackend",  # フォールバック
        ]
    """

    def authenticate(self, request, username=None, password=None, **kwargs):
        if not username or not password:
            return None

        au = (
            AccountUser.objects
            .filter(user_id=username)
            .select_related("django_user")
            .first()
        )
        if not au:
            return None

        user = au.django_user
        if user.check_password(password) and user.is_active:
            return user
        return None

    def get_user(self, user_id):
        return User.objects.filter(id=user_id).first()
