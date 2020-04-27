import uuid
from urllib.parse import urljoin

import string

from datetime import timedelta
import hashlib

from django.contrib.auth.models import BaseUserManager, AbstractUser
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.conf import settings


class UserManager(BaseUserManager):

    use_in_migrations = True

    def _random_username(self):
        return "autogen:%s" % str(uuid.uuid4())

    def create_user(self, email, password, auto_confirm_email=False, **extra_fields):
        if not email:
            raise ValueError(_("The email must be set"))
        if "username" not in extra_fields:
            extra_fields["username"] = self._random_username()
        user = self.model(**extra_fields)
        if password is None:
            user.set_unusable_password()
        else:
            user.set_password(password)
        user.save()

        email = self.normalize_email(email)
        EmailAddress.objects.create(
            user=user, address=email, primary=True, confirmed=auto_confirm_email, deleted=False)

        return user


class APIManagerUser(AbstractUser):
    """
    Represents a user of the management system which will allow them to
    inspect or create resoures able to use.
    """

    objects = UserManager()

    uuid = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False)

    username = models.CharField(max_length=64, unique=True)

    is_gatekeeper = models.BooleanField(default=False)
    """ This defines whether or not this user is allowed to review and update forms
        submitted by other users to create live keys (see gatekeeper app) """

    USERNAME_FIELD = "username"

    REQUIRED_FIELDS = ["email"]

    @property
    def primary_email(self):
        return self.emailaddress_set.filter(primary=True).first()

    @property
    def two_factor_enabled(self):
        return False

    def __str__(self):
        return self.username


class EmailAddressManager(models.Manager):
    def create(self, *args, **kwargs):
        email = super().create(*args, **kwargs)
        # create a new confirmation token by default
        ConfirmationToken.create_for_email(email)
        return email


class EmailAddress(models.Model):

    objects = EmailAddressManager()

    user = models.ForeignKey(APIManagerUser, on_delete=models.CASCADE)
    """ Which user this email belongs to """

    address = models.EmailField()
    """ The actual email address """

    confirmed = models.BooleanField(default=False)
    """ Whether this email address has been confirmed by a user clicking on a link from an email """

    primary = models.BooleanField(default=False)
    """ If this email represents the user's main email address that they use to log in """

    created = models.DateTimeField(auto_now_add=True)
    """ When this email address object was created """

    deleted = models.BooleanField(default=False)
    """ Whether or not this email address has been deleted by the user. Emails are kept
        around but not displayed or used for login if a user deletes them. """

    def send_confirmation_email(self):
        token = self.confirmation_token
        if token is None:
            raise ValueError(
                "No valid confirmation token for this email address")
        activate_url = urljoin(settings.FRONTEND_URL,
                               "/activate?token=%s" % token.token)
        # sending.send_email(self.address, "registration/activation_email",
        #                    ctx_dict={"action_url": activate_url})

    def confirm(self):
        # deactivate all other emails
        self.user.emailaddress_set.all().update(primary=False, deleted=True)

        # set this email as the user's primary
        self.confirmed = True
        self.primary = True
        self.save()

    @property
    def confirmation_token(self):
        token_timeout = timezone.now() - timedelta(seconds=settings.EMAIL_TOKEN_TTL)
        return self.confirmationtoken_set.filter(created__gte=token_timeout).first()


class ConfirmationToken(models.Model):

    email = models.ForeignKey(EmailAddress, on_delete=models.CASCADE)
    """ Which email address this token will confirm """

    token = models.CharField(max_length=64)
    """ A hashed random string """

    created = models.DateTimeField(auto_now_add=True)
    """ When this token was created, to use in expiry calculations """

    @staticmethod
    def create_for_email(email):
        random_string = get_random_string(
            length=32, allowed_chars=string.printable)
        token = hashlib.sha256(random_string.encode("utf-8")).hexdigest()
        return ConfirmationToken.objects.create(email=email, token=token)

    @property
    def expired(self):
        return (self.created + timedelta(seconds=settings.EMAIL_TOKEN_TTL)) < timezone.now()
