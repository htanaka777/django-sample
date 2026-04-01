from django.urls import path
from . import views

app_name = "signup"

urlpatterns = [
    path("register/",            views.register,        name="register"),
    path("sns/start",            views.sns_start,       name="sns_start"),
    path("sns/verify",           views.sns_verify,      name="sns_verify"),
    path("complete",             views.signup_complete, name="signup_complete"),
    path("kyc/upload",           views.kyc_upload,      name="kyc_upload"),
    path("kyc/blob/<str:token>", views.kyc_blob,        name="kyc_blob"),
    path("tg/webhook",           views.tg_webhook,      name="tg_webhook"),
]
