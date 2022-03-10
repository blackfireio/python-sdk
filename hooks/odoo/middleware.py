from blackfire.utils import get_logger
from blackfire.hooks.wsgi import BlackfireWSGIMiddleware

log = get_logger(__name__)


class OdooMiddleware(BlackfireWSGIMiddleware):

    FRAMEWORK = 'odoo'

    def get_response_class(self):
        from werkzeug.wrappers import Response
        return Response

    def get_view_name(self, method, url):
        # TODO: Maybe a way to retrieve this information?
        return None
