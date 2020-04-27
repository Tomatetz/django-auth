from collections import defaultdict
from django.http import JsonResponse


class ErrorResponse(JsonResponse):
    def __init__(self, response_code, errors=None):
        errors = errors or {}
        super().__init__(status=response_code, data=errors)

    @staticmethod
    def from_form(status_code, form):
        errors = defaultdict(list)
        for form_error in form.errors:
            errors[form_error] += form.errors[form_error]
        return ErrorResponse(status_code, errors)
