from blackfire.exceptions import *
from blackfire import apm, generate_config
from blackfire.utils import get_logger, read_blackfireyml_content
from blackfire.hooks.utils import try_enable_probe, try_end_probe, \
    try_validate_send_blackfireyml, try_apm_start_transaction, try_apm_stop_and_queue_transaction

log = get_logger(__name__)


def _headers_to_dict(headers):
    return dict((k, v) for (k, v) in headers)


def _catch_response_headers(environ, start_response):

    def _wrapper(status, headers):
        try:
            environ['blackfire.status_code'] = int(status[:3])
            headers_dict = _headers_to_dict(headers)
            environ['blackfire.content_length'] = headers_dict.get(
                'Content-Length', 0
            )
        except Exception as e:
            log.exception(e)
        return start_response(status, headers)

    return _wrapper


class BlackfireWSGIMiddleware(object):

    # Custom WSGI middlewares should override this value
    FRAMEWORK = 'Generic-WSGI'

    def __init__(self, app):
        self.app = app

    def build_blackfire_yml_response(self, *args):
        '''This function is called to handle Blackfire builds. When a special build
        POST request received, this function gets called to build framework specific
        response that contains the blackfire.yaml file contents.
        '''
        raise NotImplemented('')

    def get_view_name(self, environ):
        '''This function is called at the start of wsgi.__call__ to retrieve the
        actual view function name. Usually, the view function is not retrieved by 
        here but we need this information to match controller-name field in APM
        key-pages.
        '''
        raise NotImplemented('')

    def get_app_response(self, *args, **kwargs):
        return self.app(*args, **kwargs)

    def enable_probe(self, query):
        return try_enable_probe(query)

    def end_probe(self, response, probe, probe_err, environ):
        if probe:
            return try_end_probe(
                probe,
                response_status_code=environ.get('blackfire.status_code'),
                response_len=environ.get('blackfire.content_length', 0),
                controller_name=environ.get('blackfire.endpoint'),
                framework=self.FRAMEWORK,
                http_method=environ.get('REQUEST_METHOD'),
                http_uri=environ.get('REQUEST_URI'),
                https='1' if environ.get('wsgi.url_scheme') == 'https' else '',
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

    def _profile(self, query, environ, start_response):
        log.debug(
            "%s profile called. [query=%s]", self.__class__.__name__, query
        )

        # bf yaml asked?
        if environ['REQUEST_METHOD'] == 'POST':
            config = generate_config(query=query)
            if config.is_blackfireyml_asked():
                log.debug(
                    '%s autobuild triggered. Sending `.blackfire.yml` file.',
                    self.__class__.__name__,
                )
                blackfireyml_content = read_blackfireyml_content()
                agent_response = try_validate_send_blackfireyml(
                    config, blackfireyml_content
                )

                return self.build_blackfire_yml_response(
                    blackfireyml_content, agent_response, environ,
                    start_response
                )

        probe_err, probe = self.enable_probe(query)

        def _start_response(status, headers):
            try:
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
            response = self.get_app_response(
                environ,
                _catch_response_headers(
                    environ, _start_response if probe else start_response
                )
            )
            return response
        finally:
            log.debug(
                "%s profile ended.",
                self.__class__.__name__,
            )

            self.end_probe(response, probe, probe_err, environ)

    def _trace(self, environ, start_response, extended=False):
        transaction = try_apm_start_transaction(extended=extended)
        try:
            response = self.get_app_response(
                environ, _catch_response_headers(environ, start_response)
            )
            return response
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
        path_info = environ.get('PATH_INFO', '')  # defensive
        view_name = environ['blackfire.endpoint'] = self.get_view_name(environ)

        # profile
        query = environ.get('HTTP_X_BLACKFIRE_QUERY')
        if query:
            return self._profile(query, environ, start_response)

        # auto-profile
        # path_info is used for matching the key-page controller-name. The key is
        # always present as per WSGI spec and gives more consistent values while
        # switching between staging/prod servers.
        # See https://docs.djangoproject.com/en/4.0/ref/request-response/#django.http.HttpRequest.path_info
        # for more information
        # Also see: https://wsgi.readthedocs.io/en/latest/definitions.html#envvar-PATH_INFO
        trigger_auto_profile, key_page = apm.trigger_auto_profile(
            method, path_info, view_name
        )
        if trigger_auto_profile:
            log.debug("%s autoprofile triggered.", self.__class__.__name__)
            query = apm.get_autoprofile_query(method, path_info, key_page)
            if query:
                return self._profile(query, environ, start_response)

        # monitoring
        if apm.trigger_trace():
            return self._trace(
                environ, start_response, extended=apm.trigger_extended_trace()
            )

        return self.get_app_response(environ, start_response)
