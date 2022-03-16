from blackfire.utils import get_logger
from blackfire.hooks.wsgi import BlackfireWSGIMiddleware
from blackfire.hooks.utils import add_probe_response_header

log = get_logger(__name__)


class BlackfireFlaskMiddleware(BlackfireWSGIMiddleware):

    FRAMEWORK = 'flask'

    def __init__(self, flask_app):
        self.app = flask_app.wsgi_app
        self.flask_app = flask_app

    def build_blackfire_yml_response(
        self, blackfireyml_content, agent_response, environ, start_response,
        *args
    ):
        from flask import Response

        response = Response()
        if agent_response:  # send response if signature is validated
            response.data = blackfireyml_content or ''
            add_probe_response_header(response.headers, agent_response)

        return response(environ, start_response)

    def get_view_name(self, environ):
        """This is a best effort to get the viewname at the start of Wsgi.__call__
        
        In fact, while running in Flask context, it is easy to get this value 
        from the Request object via `request.endpoint` but wsgi.__call__ is not 
        running in request context.
        
        The only place we run in request context in a standard WSGI middleware is
        the `start_response` callback. But if we check endpoint there and start 
        the profiler there, then we might end up losing some code paths: especially
        the middlewares that ran before ours. As a general rule of thumb: we would 
        like to start the profiler as early as possible and end as late as possible.
        """

        def _get_view_name(method, url):
            from werkzeug.routing import RequestRedirect, MethodNotAllowed, NotFound

            adapter = self.flask_app.url_map.bind('dummy')
            try:
                match = adapter.match(url, method=method)
            except RequestRedirect as e:
                # recursively match redirects
                return _get_view_name(e.new_url, method)
            except (MethodNotAllowed, NotFound):
                return None

            try:
                r = self.flask_app.view_functions[match[0]]
                return r.__name__
            except KeyError:
                # no view is associated with the endpoint
                return None

        try:
            return _get_view_name(
                environ['REQUEST_METHOD'], environ.get('PATH_INFO', '')
            )
        except Exception as e:
            log.exception(e)
