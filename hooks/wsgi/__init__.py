from blackfire.exceptions import *
from blackfire import apm, generate_config
from blackfire.utils import get_logger, read_blackfireyml_content
from blackfire.hooks.utils import try_enable_probe, try_end_probe, add_probe_response_header, \
    try_validate_send_blackfireyml, try_apm_start_transaction, try_apm_stop_and_queue_transaction

log = get_logger(__name__)

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
        raise NotImplemented('')

    def _profile(self, environ, start_response, query):
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

    def _trace(self, environ, start_response, extended=False):
        transaction = try_apm_start_transaction(extended=extended)
        try:
            return self.app(
                environ, _catch_response_headers(environ, start_response)
            )
        finally:
            if transaction:
                try_apm_stop_and_queue_transaction(
                    controller_name=transaction.name
                    or environ.get('blackfire.endpoint'),
                    uri=environ.get('REQUEST_URI'),
                    framework=self.FRAMEWORK,
                    http_host=environ.get('HTTP_HOST'),
                    method=environ.get('REQUEST_METHOD'),
                    response_code=environ.get('blackfire.status_code'),
                    stdout=environ.get('blackfire.content_length', 0),
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
            return self._profile(environ, start_response, query)

        # auto-profile
        trigger_auto_profile, key_page = apm.trigger_auto_profile(
            method, path_info, view_name
        )
        if trigger_auto_profile:
            log.debug("autoprofile triggered.")
            query = apm.get_autoprofile_query(method, path_info, key_page)
            if query:
                return self._profile(environ, start_response, query)

        # monitoring
        if apm.trigger_trace():
            return self._trace(
                environ, start_response, extended=apm.trigger_extended_trace()
            )

        return self.app(environ, start_response)
