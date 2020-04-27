from django.contrib.auth import get_user_model, password_validation, authenticate
from django import forms
from .models import EmailAddress
from django.contrib.auth.forms import PasswordResetForm as DjangoPasswordResetForm


class UserForm(forms.ModelForm):

    new_password = forms.CharField(required=False)
    """ This is only used in the password update view """
    token = forms.CharField(required=False)
    """ This is only needed when a user has 2fa enabled """

    class Meta:
        model = get_user_model()
        fields = ["email", "password", "new_password", "token"]

    def __init__(self, *args, patch_only=False, two_factor_enabled=False, **kwargs):
        super().__init__(*args, **kwargs)
        if two_factor_enabled:
            self.fields["token"].required = True
        if patch_only:
            # the password must be valid, otherwise in a PATCH we are just
            # updating whatever (valid) values we are given for other fields
            self.fields["email"].required = False

    def clean_new_password(self):
        if "new_password" not in self.data:
            return ""
        new_password = self.data["new_password"]
        password_validation.validate_password(new_password, self.instance)
        return new_password

    def _post_clean(self):
        super()._post_clean()
        password = self.cleaned_data.get("password")
        if password:
            try:
                password_validation.validate_password(password, self.instance)
            except forms.ValidationError as error:
                self.add_error("password", error)
        return password


class PasswordResetForm(forms.Form):
    password = forms.CharField()

    def clean_password(self):
        password = self.data["password"]
        password_validation.validate_password(password)
        return password


class UserAuthenticationForm(forms.Form):

    email = forms.EmailField()
    password = forms.CharField()

    def __init__(self, *args, request=None, **kwargs):
        """
        The 'request' parameter is set for custom auth use by subclasses.
        The form data comes in via the standard 'data' kwarg.
        """
        self.request = request
        self.user = None
        super().__init__(*args, **kwargs)

    def clean(self):
        email_address = self.cleaned_data.get("email")
        password = self.cleaned_data.get("password")

        try:
            email = EmailAddress.objects.get(
                address=email_address, primary=True, confirmed=True)
            username = email.user.username
            self.user = authenticate(
                self.request, username=username, password=password)
            if self.user is None:
                raise self.get_invalid_login_error()
            else:
                self.confirm_login_allowed(self.user)
        except EmailAddress.DoesNotExist:
            raise self.get_invalid_login_error()

        return self.cleaned_data

    def get_user(self):
        return self.user

    def confirm_login_allowed(self, user):
        """
        Controls whether the given User may log in. This is a policy setting,
        independent of end-user authentication. This default behavior is to
        allow login by active users, and reject login by inactive users.
        If the given user cannot log in, this method should raise a
        ``forms.ValidationError``.
        If the given user may log in, this method should return None.
        """
        if not user.is_active:
            raise forms.ValidationError("inactive", code="inactive")

    def get_invalid_login_error(self):
        return forms.ValidationError("invalid_login", code="invalid_login")
