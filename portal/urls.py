from django.contrib.auth.views import LogoutView
from django.urls import path
from . import views

app_name = "portal"

urlpatterns = [
    path("login/",  views.PortalLoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(next_page="/portal/login/"), name="logout"),
    path("mypage/", views.mypage, name="mypage"),
]
