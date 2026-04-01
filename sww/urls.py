from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView

urlpatterns = [
    path("", RedirectView.as_view(url="/signup/register/", permanent=False)),
    path("admin/", admin.site.urls),
    path("portal/", include("portal.urls")),
    path("signup/", include("signup.urls")),
]
