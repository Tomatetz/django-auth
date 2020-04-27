from django.urls import path, include
from .views import (
    RegistrationView,
    LoginView,
    ConfirmEmailView,
    UserDetailView,
    LogoutView,
)
from djangoauthproject.decorators import forbidden_without_login

urlpatterns = [
    path("register", RegistrationView.as_view(), name="registration_register"),
    path("login", LoginView.as_view(), name="auth_login"),
    path("activate/<token>/", ConfirmEmailView.as_view(), name="confirm_email"),
    path("me", forbidden_without_login(UserDetailView.as_view()), name="auth_me"),
    path("logout", LogoutView.as_view(), name="auth_logout"),
]
