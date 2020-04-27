import json
from json.decoder import JSONDecodeError


class JsonFormMixin:
    """
    Mixin for FormViews to handle POST data that is either sent as
    application/json object or as application/x-www-form-urlencoded
    """

    def get_form_kwargs(self):
        # this can be either form-encoded or a request with a json body
        body = self.request.body
        try:
            data = json.loads(body)
        except JSONDecodeError:
            # this is probably form-encoded then
            data = None
        kwargs = super().get_form_kwargs()
        if data is not None:
            kwargs["data"] = data
        return kwargs
