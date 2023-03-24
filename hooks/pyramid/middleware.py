from blackfire.utils import get_logger
from blackfire.hooks.wsgi import BlackfireWSGIMiddleware
from blackfire.hooks.utils import add_probe_response_header

log = get_logger(__name__)


class BlackfirePyramidMiddleware(BlackfireWSGIMiddleware):

    FRAMEWORK = 'pyramid'

    def get_view_name(self, request):
        try:
            from pyramid.scripts.pviews import PViewsCommand

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
            response.body = blackfireyml_content or ''
            add_probe_response_header(response.headers, agent_response)

        return response(environ, start_response)
