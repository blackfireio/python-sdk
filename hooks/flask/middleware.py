import time
import platform
from blackfire import apm, VERSION, generate_config
from blackfire.utils import get_logger, get_probed_runtime, read_blackfireyml_content
from blackfire.hooks.utils import try_enable_probe, try_end_probe, add_probe_response_header, \
    try_validate_send_blackfireyml

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
        # this stays here for Backward compat.
        # TODO: Remove after deprecation period for patch_all
        return self.wsgi_app(environ, start_response)

    def _before_request(self):
        req_context = get_request_context()

        req_context.apm = False
        req_context.apm_extended = False
        req_context.profile = False
        req_context.req_start = time.time()
        req_context.probe_err = None
        req_context.probe = None

        log.debug("FlaskMiddleware._before_request called.")

        request = get_current_request()

        # bf yaml asked?
        if request.method == 'POST':
            if 'HTTP_X_BLACKFIRE_QUERY' in request.environ:
                config = generate_config(
                    query=request.environ['HTTP_X_BLACKFIRE_QUERY']
                )
                if config.is_blackfireyml_asked():
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
            req_context.probe_err, req_context.probe = try_enable_probe(query)
            req_context.profile = True
            return

        if apm.trigger_trace():
            req_context.apm = True
            req_context.apm_extended = apm.trigger_extended_trace()
            apm.enable(extended=req_context.apm_extended)

    def _after_request(self, response):
        req_context = get_request_context()
        request = get_current_request()

        log.debug("FlaskMiddleware._after_request called.")

        try:
            if req_context.profile:
                if req_context.probe_err:
                    add_probe_response_header(
                        response.headers, req_context.probe_err
                    )
                    return response

                probe_resp = try_end_probe(
                    req_context.probe,
                    response_status_code=response.status_code,
                    response_len=response.headers['Content-Length'],
                    controller_name=request.endpoint,
                    framework="flask",
                    http_method=request.method,
                    http_uri=request.path,
                    https='1' if request.is_secure else '',
                    http_server_addr=request.environ.get('SERVER_NAME'),
                    http_server_software=request.environ.get('SERVER_SOFTWARE'),
                    http_server_port=request.environ.get('SERVER_PORT'),
                    http_header_host=request.environ.get('HTTP_HOST'),
                    http_header_user_agent=request.environ
                    .get('HTTP_USER_AGENT'),
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

            if req_context.apm:
                mu, pmu = apm.get_traced_memory()
                apm.disable()
                now = time.time()
                elapsed_wt_usec = int((now - req_context.req_start) * 1000000)
                apm.send_trace(
                    request,
                    req_context.apm_extended,
                    controller_name=request.endpoint,
                    wt=elapsed_wt_usec,
                    mu=mu,
                    pmu=pmu,
                    timestamp=now,
                    uri=request.path,
                    framework="flask",
                    capabilities="trace",
                    host=request.environ.get('HTTP_HOST'),
                    method=request.method,
                    os=platform.system(),
                    language="python",
                    runtime=get_probed_runtime(),
                    response_code=response.status_code,
                    stdout=response.headers['Content-Length'],
                    http_method=request.method,
                    version=VERSION,
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
