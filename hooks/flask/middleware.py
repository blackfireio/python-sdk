from blackfire import apm, generate_config
from blackfire.utils import get_logger, read_blackfireyml_content, get_time
from blackfire.hooks.utils import try_enable_probe, try_end_probe, add_probe_response_header, \
    try_validate_send_blackfireyml, try_apm_start_transaction, try_apm_stop_and_queue_transaction

log = get_logger(__name__)


def get_current_request():
    # From Flask docs:
    # When the Flask application handles a request, it creates a Request
    # object based on the environment it received from the WSGI server.
    # Because a worker (thread, process, or coroutine depending on the server)
    # handles only one request at a time, the request data can be considered
    # global to that worker during that request. Flask uses the term context
    # local for this.
    # TODO: Remove this lazy imports after explicit middleware usage is deprecated
    # then this file can only be imported through patch_all() which will be safe
    import flask
    return flask.request


def get_request_context():
    # TODO: Remove this lazy imports after explicit middleware usage is deprecated
    # then this file can only be imported through patch_all() which will be safe
    from flask import g
    return g


def end_profile(response):
    req_context = get_request_context()
    request = get_current_request()
    if req_context.probe_err:
        add_probe_response_header(response.headers, req_context.probe_err)
        return response

    probe_resp = try_end_probe(
        req_context.probe,
        response_status_code=response.status_code,
        response_len=response.headers.get('Content-Length', 0),
        controller_name=request.endpoint,
        framework="flask",
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

    return response


class BlackfireFlaskMiddleware(object):

    def __init__(self, app):
        self.app = app
        self.wsgi_app = app.wsgi_app

        # we use before/after request hooks instead of __call__ directly because
        # these functions are called in registered order: meaning that the first function
        # registered will be called last. This means, assuming blackfire.patch_all()
        # is called very early, we will have chance to catch all other middleware
        # profiling data.
        self.app.before_request(self._before_request)
        self.app.after_request(self._after_request)
        self.app.teardown_request(self._teardown_request)

    def __call__(self, environ, start_response):
        return self.wsgi_app(environ, start_response)

    def _before_request(self):
        req_context = get_request_context()

        req_context.apm = False
        req_context.apm_extended = False
        req_context.profile = False
        req_context.probe_err = None
        req_context.probe = None
        req_context.transaction = None

        log.debug("FlaskMiddleware._before_request called.")

        request = get_current_request()

        # bf yaml asked?
        if request.method == 'POST':
            if 'HTTP_X_BLACKFIRE_QUERY' in request.environ:
                config = generate_config(
                    query=request.environ['HTTP_X_BLACKFIRE_QUERY']
                )
                if config.is_blackfireyml_asked():
                    log.debug(
                        'Flask autobuild triggered. Sending `.blackfire.yml` file.'
                    )
                    blackfireyml_content = read_blackfireyml_content()
                    agent_response = try_validate_send_blackfireyml(
                        config, blackfireyml_content
                    )

                    from flask import Response

                    response = Response()
                    if agent_response:  # send response if signature is validated
                        response.data = blackfireyml_content or ''
                        add_probe_response_header(
                            response.headers, agent_response
                        )

                    return response

        # When signal is registered we might received other events from other
        # requests. Look at the request object of the current response to determine
        # for finishing the profile session
        if 'HTTP_X_BLACKFIRE_QUERY' in request.environ:
            req_context.probe_err, req_context.probe = try_enable_probe(
                request.environ['HTTP_X_BLACKFIRE_QUERY']
            )
            req_context.profile = True
            return

        # auto-profile triggered?
        trigger_auto_profile, key_page = apm.trigger_auto_profile(
            request.method, request.path, request.endpoint
        )
        if trigger_auto_profile:
            log.debug("FlaskMiddleware autoprofile triggered.")
            query = apm.get_autoprofile_query(
                request.method, request.path, key_page
            )
            if query:
                req_context.probe_err, req_context.probe = try_enable_probe(
                    query
                )
                req_context.profile = True
                return

        if apm.trigger_trace():
            req_context.apm = True
            req_context.apm_extended = apm.trigger_extended_trace()
            req_context.transaction = try_apm_start_transaction(
                extended=req_context.apm_extended
            )

    def _after_request(self, response):
        req_context = get_request_context()
        request = get_current_request()

        log.debug("FlaskMiddleware._after_request called.")

        try:
            if req_context.profile:
                return end_profile(response)

            if req_context.apm:
                if req_context.transaction:
                    try_apm_stop_and_queue_transaction(
                        controller_name=req_context.transaction.name
                        or request.endpoint,
                        uri=request.path,
                        framework="flask",
                        http_host=request.environ.get('HTTP_HOST'),
                        method=request.method,
                        response_code=response.status_code,
                        stdout=response.headers.get('Content-Length', 0)
                    )
        except Exception as e:
            # signals run in the context of app. Do not fail app code on any error
            log.exception(e)

        return response

    def _teardown_request(self, exception):
        log.debug("FlaskMiddleware._teardown_request called.")
        req_context = get_request_context()

        if req_context.probe:
            req_context.probe.disable()
            req_context.probe.clear_traces()
