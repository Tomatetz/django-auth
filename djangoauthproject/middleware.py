from django.utils.deprecation import MiddlewareMixin


class DisableCSRF(MiddlewareMixin):
    """ CSRF is not implemented in the frontend yet """

    def process_request(self, request):
        setattr(request, "_dont_enforce_csrf_checks", True)
