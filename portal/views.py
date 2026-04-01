from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView
from django.shortcuts import render

from signup.models import AccountUser, IdDocument, LoginAudit


class PortalLoginView(LoginView):
    """
    カスタムテンプレートを使用したログインビュー。

    AUTHENTICATION_BACKENDS の AccountLoginBackend により、
    USER_ID（U00000001）またはユーザー名でのログインが可能。
    """
    template_name = "portal/login.html"


@login_required
def mypage(request):
    """
    マイページ: ログインユーザーのプロファイル・KYCステータス・監査ログを表示する。
    """
    au = (
        AccountUser.objects
        .filter(django_user=request.user)
        .select_related("django_user")
        .first()
    )
    docs = (
        IdDocument.objects
        .filter(user_id=au.user_id)
        .order_by("image_id")
        if au else []
    )
    recent_audit = (
        LoginAudit.objects
        .filter(django_user_id=request.user.id)
        .order_by("-event_at")[:10]
    )
    return render(request, "portal/mypage.html", {
        "au": au,
        "docs": docs,
        "recent_audit": recent_audit,
    })
