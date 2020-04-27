from django.shortcuts import render
from django.contrib.auth import get_user_model, login, logout
from django.shortcuts import get_object_or_404
from django.contrib.auth import views as auth_views
from django.views.generic import View
from django.views.generic.edit import BaseFormView, FormView
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.http import HttpResponse, HttpResponseForbidden, HttpResponseNotAllowed, JsonResponse
from .forms import UserForm, UserAuthenticationForm
from .errors import ErrorResponse
from .models import APIManagerUser, EmailAddress, ConfirmationToken
from .mixins import JsonFormMixin
from .serializers import UserSerializer


from django.core.mail import send_mail


class LoginView(JsonFormMixin, auth_views.LoginView):
    def get_form_class(self):
        return UserAuthenticationForm

    def form_valid(self, form):
        """Security check complete. Log the user in."""
        user = form.get_user()
        login(self.request, user)
        two_factor_enabled = user.two_factor_enabled
        # if not two_factor_enabled:
        #     send_login_success_email(self.request)
        # recorder.incr("user.login", userid=user.uuid)

        return JsonResponse({"two_factor_enabled": two_factor_enabled}, status=200)

    def form_invalid(self, form):
        return JsonResponse({}, status=403)


class RegistrationView(JsonFormMixin, BaseFormView):
    """
    The first step for a user is to give us their email address.
    This will then send them an email to allow them to activate their
    account and then set a password and be able to log in.
    """

    def get_form_class(self):
        return UserForm

    def form_invalid(self, form):
        return ErrorResponse.from_form(400, form)

    def form_valid(self, form):
        email_address = form.cleaned_data["email"]

        # we have a valid email, now test if it already exists
        try:
            email = EmailAddress.objects.get(address=email_address)
            return HttpResponse(status=200)
        except EmailAddress.DoesNotExist:
            user = APIManagerUser.objects.create_user(
                password=form.cleaned_data["password"], email=email_address)
        user.primary_email.send_confirmation_email()

        return JsonResponse({"token": user.primary_email.confirmation_token.token}, status=200)


class ConfirmEmailView(View):
    def get(self, request, *args, **kwargs):
        token_string = kwargs["token"]
        token = get_object_or_404(ConfirmationToken, token=token_string)

        if token.expired:
            return ErrorResponse(401, {"token": "This confirmation token has expired"})

        user = token.email.user

        send_welcome = not user.emailaddress_set.exclude(
            pk=token.email.pk).filter(confirmed=True).exists()
        # this means that the user has never activated an email before, so this is the first one
        # and we can send the welcome email

        # deactivate all other emails and make the new one primary
        token.email.confirm()

        print('********welcome******')

        return JsonResponse({}, status=200)


class UserDetailView(JsonFormMixin, BaseFormView):

    form_class = UserForm

    def dispatch(self, request, *args, **kwargs):
        if request.method == "GET":
            return self.get(request, *args, **kwargs)
        return HttpResponseNotAllowed(["GET"])

    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return HttpResponseForbidden()
        return JsonResponse(UserSerializer(request.user).data)


class LogoutView(View):
    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        # if request.user.is_authenticated:
        #     recorder.incr("user.logout", userid=request.user.uuid)

        # note: accepts anything
        logout(request)
        # no redirects from standard Django, just logout and get on with it
        return JsonResponse({}, status=200)
