from blackfire.utils import get_logger
from blackfire.hooks.wsgi import BlackfireWSGIMiddleware

log = get_logger(__name__)


class OdooMiddleware(BlackfireWSGIMiddleware):

    FRAMEWORK = 'odoo'

    def build_blackfire_yml_response(
        self, blackfireyml_content, agent_response, environ, start_response
    ):
        from werkzeug.wrappers import Response
        # send response if signature is validated
        if agent_response:
            return Response(
                response=blackfireyml_content or '', headers=[agent_response]
            )(environ, start_response)

        return Response()(environ, start_response)

    def build_ping_response(self, environ, start_response):
        from werkzeug.wrappers import Response

        response = Response()
        response.headers['X-Blackfire-Response'] = 'pong'
        return response(environ, start_response)

    def get_view_name(self, environ):
        return None

    def __getattr__(self, name):
        return getattr(self.app, name)
