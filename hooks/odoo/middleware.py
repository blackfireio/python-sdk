from blackfire.hooks.utils import try_enable_probe, try_end_probe
from blackfire.utils import get_logger, read_blackfireyml_content

logger = get_logger(__name__)

class OdooMiddleware(object):
    def __init__(self, application):
        self.application = application

    def __call__(self, environ, start_response):
        if 'HTTP_X_BLACKFIRE_QUERY' not in environ:
            logger.debug('Blackfire: PASSTHROUGH')
            return self.application(environ, start_response)

        # TODO: Get .blackfire.yaml when applicable
        logger.debug('Blackfire: PROFILE')
        return self._blackfired_request(environ, start_response)

    def _get_query_from_environ(self, environ):
        return environ['HTTP_X_BLACKFIRE_QUERY']

    def _blackfired_request(self, environ, start_response):
        query = self._get_query_from_environ(environ)
        logger.debug(
            "OdooMiddleware._blackfired_request called. [query=%s]", query
        )

        new_probe = None
        try:
            bf_status = None
            bf_headers = None

            def _start_response(status, headers):
                nonlocal bf_status, bf_headers
                bf_status = status
                bf_headers = headers
                resp = start_response(status, headers)

                return resp

            probe_err, new_probe = try_enable_probe(query)
            # let exceptions propagate through
            response = self.application(environ, _start_response)

            if probe_err:
                logger.info(probe_err)
                bf_headers.append((probe_err[0], probe_err[1]))
            else:
                response_len = -1
                for h in bf_headers:
                    if h[0] == 'Content-Length':
                        response_len = h[1]
                        break

                probe_resp = try_end_probe(
                    new_probe,
                    response_status_code=bf_status[0:3],  # status contains code+string status, e.g. "200 OK"
                    response_len=response_len,
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
                    http_header_x_forwarded_host=environ['HTTP_X_FORWARDED_HOST'] if 'HTTP_X_FORWARDED_HOST' in environ else '',
                    http_header_x_forwarded_proto=environ['HTTP_X_FORWARDED_PROTO'] if 'HTTP_X_FORWARDED_PROTO' in environ else '',
                    http_header_x_forwarded_port=environ['HTTP_X_FORWARDED_PORT'] if 'HTTP_X_FORWARDED_PORT' in environ else '',
                    http_header_forwarded=environ['HTTP_FORWARDED'] if 'HTTP_FORWARDED' in environ else '',
                )
                bf_headers.append((probe_resp[0], probe_resp[1]))

            return response

        finally:
            logger.debug("OdooMiddleware._profiled_request ended.")

            if new_probe:
                new_probe.disable()
                new_probe.clear_traces()
