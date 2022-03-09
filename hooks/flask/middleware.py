from blackfire.exceptions import *
from blackfire import apm, generate_config
from blackfire.utils import get_logger, read_blackfireyml_content
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


# TODO: Maybe add __class__.__name__ to logs?


def _extract_response_headers(headers):
    return dict((k, v) for (k, v) in headers)


def _catch_response_headers(environ, start_response):

    def _wrapper(status, headers):
        try:
            environ['blackfire.status_code'] = int(status[:3])
            headers_dict = _extract_response_headers(headers)
            environ['blackfire.content_length'] = headers_dict.get(
                'Content-Length', 0
            )
        except Exception as e:
            log.exception(e)
        return start_response(status, headers)

    return _wrapper


class BlackfireWSGIMiddleware(object):

    # Custom WSGI middlewares should override this value
    FRAMEWORK = ''

    def __init__(self, app):
        self.app = app

    def get_response_class(self):
        '''This function retrieves the Response class per framework. There are
        situations where the Middleware needs to return a custom Response object.
        (e.g: sending .blackfire.yml in builds)

        We make this a function rather than a class attribute since we need this 
        to be lazily imported in runtime

        Custom WSGI middlewares need to override this function and return a 
        proper Response class
        '''
        from werkzeug.wrappers import Response
        return Response

    def _blackfired_request(self, environ, start_response, query):
        log.debug("_blackfired_request called. [query=%s]", query)

        # bf yaml asked?
        if environ['REQUEST_METHOD'] == 'POST':
            config = generate_config(query=query)
            if config.is_blackfireyml_asked():
                log.debug('autobuild triggered. Sending `.blackfire.yml` file.')
                blackfireyml_content = read_blackfireyml_content()
                agent_response = try_validate_send_blackfireyml(
                    config, blackfireyml_content
                )

                response_klass = self.get_response_class()
                # send response if signature is validated
                if agent_response:
                    return response_klass(
                        response=blackfireyml_content or '',
                        headers=[agent_response]
                    )(environ, start_response)

                return response_klass()(environ, start_response)

        probe_err, probe = try_enable_probe(query)

        def _start_response(status, headers):
            try:
                if probe:
                    if probe_err:
                        if probe_err is not BlackfireInvalidSignatureError:
                            headers.append((probe_err[0], probe_err[1]))
                    else:
                        headers.append(
                            (
                                'X-Blackfire-Response',
                                probe.get_agent_prolog_response().status_val
                            )
                        )
            except Exception as e:
                log.exception(e)

            return start_response(status, headers)

        try:
            return self.app(
                environ, _catch_response_headers(environ, _start_response)
            )
        finally:
            log.debug("_blackfired_request ended.")

            if probe:
                _ = try_end_probe(
                    probe,
                    response_status_code=environ.get('blackfire.status_code'),
                    response_len=environ.get('blackfire.content_length', 0),
                    controller_name=environ.get('blackfire.endpoint'),
                    framework=self.FRAMEWORK,
                    http_method=environ.get('REQUEST_METHOD'),
                    http_uri=environ.get('REQUEST_URI'),
                    https='1'
                    if environ.get('wsgi.url_scheme') == 'https' else '',
                    http_server_addr=environ.get('SERVER_NAME'),
                    http_server_software=environ.get('SERVER_SOFTWARE'),
                    http_server_port=environ.get('SERVER_PORT'),
                    http_header_host=environ.get('HTTP_HOST'),
                    http_header_user_agent=environ.get('HTTP_USER_AGENT'),
                    http_header_x_forwarded_host=environ
                    .get('HTTP_X_FORWARDED_HOST'),
                    http_header_x_forwarded_proto=environ
                    .get('HTTP_X_FORWARDED_PROTO'),
                    http_header_x_forwarded_port=environ
                    .get('HTTP_X_FORWARDED_PORT'),
                    http_header_forwarded=environ.get('HTTP_FORWARDED'),
                )

    def __call__(self, environ, start_response):
        # method/path_info are mandatory in WSGI spec.
        method = environ['REQUEST_METHOD']
        path_info = environ['PATH_INFO']
        view_name = environ['blackfire.endpoint'] = self.get_view_name(
            method, path_info
        )

        # profile
        query = environ.get('HTTP_X_BLACKFIRE_QUERY')
        if query:
            self._blackfired_request(environ, start_response, query)

        # auto-profile
        trigger_auto_profile, key_page = apm.trigger_auto_profile(
            method, path_info, view_name
        )
        if trigger_auto_profile:
            log.debug("autoprofile triggered.")
            query = apm.get_autoprofile_query(method, path_info, key_page)
            if query:
                return self._blackfired_request(environ, start_response, query)

        # todo: implement _apm_trace
        if apm.trigger_trace():
            return self._apm_trace(
                environ, start_response, extended=apm.trigger_extended_trace()
            )

        return self.app(environ, start_response)


class BlackfireFlaskMiddleware(BlackfireWSGIMiddleware):

    def __init__(self, flask_app):
        self.app = flask_app.wsgi_app
        self.flask_app = flask_app

    def get_view_name(self, method, url):
        """This is a best effort to get the viewname in wsgi.__call__ method. 
        
        In fact, while running in Flask context, it is easy to get this value 
        from the Request object via `request.endpoint` but wsgi.__call__ is not 
        running in request context.
        
        The only place we run in request context in a standard WSGI middleware is
        the `start_response` callback. But if we check endpoint there and start 
        the profiler there, then we might end up losing some code paths: especially
        the middlewares that ran before ours. As a general rule of thumb: we would 
        like to start the profiler as early as possible and end as late as possible.
        """
        from werkzeug.routing import RequestRedirect, MethodNotAllowed, NotFound

        adapter = self.flask_app.url_map.bind('dummy')
        try:
            match = adapter.match(url, method=method)
        except RequestRedirect as e:
            # recursively match redirects
            return self.get_view_name(e.new_url, method)
        except (MethodNotAllowed, NotFound):
            return None

        try:
            r = self.flask_app.view_functions[match[0]]
            return r.__name__
        except KeyError:
            # no view is associated with the endpoint
            return None


class BlackfireFlaskMiddleware2(object):

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
