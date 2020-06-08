from blackfire.utils import get_logger
from blackfire.hooks.utils import try_enable_probe, try_end_probe, reset_probe, add_probe_response_header

log = get_logger(__name__)


def get_current_request():
    # From Flask docs:
    # When the Flask application handles a request, it creates a Request
    # object based on the environment it received from the WSGI server.
    # Because a worker (thread, process, or coroutine depending on the server)
    # handles only one request at a time, the request data can be considered
    # global to that worker during that request. Flask uses the term context
    # local for this.
    import flask
    return flask.request


class BlackfireFlaskMiddleware(object):

    def __init__(self, app):
        self.app = app
        self.wsgi_app = app.wsgi_app

        # TODO: Comment
        self._probe_err = None

        # we use before/after request hooks instead of __call__ directly because
        # these functions are called in registered order: meaning that the first function
        # registered will be called last. This means, assuming blackfire.patch_all()
        # is called very early, we will have chance to catch all other middleware
        # profiling data.
        self.app.before_request(self._before_request)
        self.app.after_request(self._after_request)
        self.app.teardown_request(self._teardown_request)

    def __call__(self, environ, start_response):
        # this stays here for Backward compat.
        # TODO: Remove after deprecation period
        return self.wsgi_app(environ, start_response)

    def _before_request(self):
        log.debug("FlaskMiddleware._before_request called.")

        request = get_current_request()

        # When signal is registered we might received other events from other
        # requests. Look at the request object of the current response to determine
        # for finishing the profile session
        if 'HTTP_X_BLACKFIRE_QUERY' not in request.environ:
            return

        self._probe_err = try_enable_probe(
            request.environ['HTTP_X_BLACKFIRE_QUERY']
        )

    def _after_request(self, response):
        log.debug("FlaskMiddleware._after_request called.")

        request = get_current_request()

        try:
            if self._probe_err:
                add_probe_response_header(response.headers, self._probe_err)
                return

            probe_resp = try_end_probe(
                response_status_code=response.status_code,
                response_len=response.headers['Content-Length'],
                http_method=request.method,
                http_uri=request.path,
                https='1' if request.is_secure else '',
                http_server_addr=request.environ.get('SERVER_NAME'),
                http_server_software=request.environ.get('SERVER_SOFTWARE'),
                http_server_port=request.environ.get('SERVER_PORT'),
                http_header_host=request.environ.get('HTTP_HOST'),
                http_header_user_agent=request.environ.get('HTTP_USER_AGENT'),
                http_header_x_forwarded_host=request.environ
                .get('HTTP_X_FORWARDED_HOST'),
                http_header_x_forwarded_proto=request.environ
                .get('HTTP_X_FORWARDED_PROTO'),
                http_header_x_forwarded_port=request.environ
                .get('HTTP_X_FORWARDED_PORT'),
                http_header_forwarded=request.environ.get('HTTP_FORWARDED'),
            )

            add_probe_response_header(response.headers, probe_resp)
        except Exception as e:
            # signals run in the context of app. Do not fail app code on any error
            log.exception(e)

        return response

    def _teardown_request(self, exception):
        log.debug("FlaskMiddleware._teardown_request called.")

        self._probe_err = None

        reset_probe()
