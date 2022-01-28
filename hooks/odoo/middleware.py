from blackfire.exceptions import *
from blackfire.hooks.utils import try_enable_probe, try_end_probe
from blackfire.utils import get_logger

logger = get_logger(__name__)


def _extract_headers(headers):
    return dict((k, v) for (k, v) in headers)


class OdooMiddleware(object):

    def __init__(self, application):
        self.application = application

    def __call__(self, environ, start_response):
        # TODO: bfyaml, APM

        # profile?
        if 'HTTP_X_BLACKFIRE_QUERY' in environ:
            return self._blackfired_request(environ, start_response)

        return self.application(environ, start_response)

    def _blackfired_request(self, environ, start_response):
        query = environ['HTTP_X_BLACKFIRE_QUERY']
        logger.debug(
            "OdooMiddleware._blackfired_request called. [query=%s]", query
        )

        content_length = status_code = None
        probe_err, probe = try_enable_probe(query)
        try:

            def _start_response(status, headers):
                nonlocal status_code, content_length, probe_err, probe

                try:
                    status_code = int(status[:3])  # e.g. 200 OK
                except Exception as e:
                    logger.exception(e)
                headers_dict = _extract_headers(headers)
                content_length = headers_dict.get('Content-Length')

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

                return start_response(status, headers)

            response = self.application(environ, _start_response)
            return response

        finally:
            logger.debug("OdooMiddleware._profiled_request ended.")

            if probe:
                probe_resp = try_end_probe(
                    probe,
                    response_status_code=status_code,
                    response_len=content_length,
                    controller_name=environ['REQUEST_URI'],
                    framework="odoo",
                    http_method=environ['REQUEST_METHOD'],
                    http_uri=environ['REQUEST_URI'],
                    https='1' if environ['wsgi.url_scheme'] == 'https' else '',
                    http_server_addr=environ['SERVER_NAME'],
                    http_server_software=environ['SERVER_SOFTWARE'],
                    http_server_port=environ['SERVER_PORT'],
                    http_header_host=environ['HTTP_HOST'],
                    http_header_user_agent=environ['HTTP_USER_AGENT'],
                    http_header_x_forwarded_host=environ['HTTP_X_FORWARDED_HOST']
                    if 'HTTP_X_FORWARDED_HOST' in environ else '',
                    http_header_x_forwarded_proto=environ[
                        'HTTP_X_FORWARDED_PROTO']
                    if 'HTTP_X_FORWARDED_PROTO' in environ else '',
                    http_header_x_forwarded_port=environ['HTTP_X_FORWARDED_PORT']
                    if 'HTTP_X_FORWARDED_PORT' in environ else '',
                    http_header_forwarded=environ['HTTP_FORWARDED']
                    if 'HTTP_FORWARDED' in environ else '',
                )
