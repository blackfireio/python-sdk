from blackfire.utils import get_logger
from blackfire.hooks.wsgi import BlackfireWSGIMiddleware
from blackfire.hooks.utils import add_probe_response_header

log = get_logger(__name__)


class BlackfirePyramidMiddleware(BlackfireWSGIMiddleware):

    FRAMEWORK = 'pyramid'

    def get_view_name(self, environ):
        try:
            from pyramid.request import Request
            from pyramid.scripts.pviews import PViewsCommand

            # convert environ to Request
            request = Request(environ)
            request.registry = self.app.registry

            pvcomm = PViewsCommand([])
            view = pvcomm._find_view(request)
            if view:
                return view.__name__
        except Exception as e:
            log.exception(e)

    def build_blackfire_yml_response(
        self, blackfireyml_content, agent_response, environ, start_response,
        *args
    ):
        from pyramid.response import Response

        response = Response()
        if agent_response:  # send response if signature is validated
            response.text = blackfireyml_content or ''
            add_probe_response_header(response.headers, agent_response)

        return response(environ, start_response)
