from functools import wraps
from django.http import HttpResponseForbidden


def forbidden_without_login(view_func):
    """
    Decorator for views which simply return an HTTP403 response
    if a user attempts to access the wrapped view without being
    logged in.

    This is to use in place of the standard Django login_required
    which returns a 302 to the login page, however this is an API-only
    application.
    """

    @wraps(view_func)
    def ensure_logged_in(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return HttpResponseForbidden()
        return view_func(request, *args, **kwargs)

    return ensure_logged_in
