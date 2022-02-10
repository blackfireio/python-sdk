from blackfire import apm, generate_config
from blackfire.exceptions import *
from blackfire.utils import get_logger, read_blackfireyml_content
from blackfire.hooks.utils import try_enable_probe, try_end_probe, \
    try_validate_send_blackfireyml, try_apm_start_transaction, try_apm_stop_and_queue_transaction

logger = get_logger(__name__)


def _extract_headers(headers):
    return dict((k, v) for (k, v) in headers)


def extract_response_headers(start_response, extracted_data):

    def _wrapper(status, headers):
        try:
            extracted_data['status_code'] = int(status[:3])  # e.g. 200 OK
        except Exception as e:
            logger.exception(e)
        headers_dict = _extract_headers(headers)
        extracted_data['content_length'] = headers_dict.get('Content-Length')
        return start_response(status, headers)

    return _wrapper


class OdooMiddleware(object):

    def __init__(self, application):
        self.application = application

    def __call__(self, environ, start_response):
        # profile?
        if 'HTTP_X_BLACKFIRE_QUERY' in environ:
            return self._blackfired_request(
                environ, start_response, environ['HTTP_X_BLACKFIRE_QUERY']
            )

        # auto-profile triggered?
        trigger_auto_profile, key_page = apm.trigger_auto_profile(
            environ['REQUEST_METHOD'], environ['REQUEST_URI'],
            environ['REQUEST_URI']
        )
        if trigger_auto_profile:
            logger.debug("Odoo autoprofile triggered.")
            query = apm.get_autoprofile_query(
                environ['REQUEST_METHOD'], environ['REQUEST_URI'], key_page
            )
            if query:
                return self._blackfired_request(environ, start_response, query)

        if apm.trigger_trace():
            return self._apm_trace(
                environ, start_response, extended=apm.trigger_extended_trace()
            )

        return self.application(environ, start_response)

    def _blackfired_request(self, environ, start_response, query):
        logger.debug(
            "OdooMiddleware._blackfired_request called. [query=%s]", query
        )

        # bf yaml asked?
        if environ['REQUEST_METHOD'] == 'POST':
            config = generate_config(query=query)
            if config.is_blackfireyml_asked():
                logger.debug(
                    'Odoo autobuild triggered. Sending `.blackfire.yml` file.'
                )
                blackfireyml_content = read_blackfireyml_content()
                agent_response = try_validate_send_blackfireyml(
                    config, blackfireyml_content
                )

                from werkzeug.wrappers import Response

                # send response if signature is validated
                return Response(
                    response=blackfireyml_content or '',
                    headers=[agent_response]
                )(environ, start_response) \
                    if agent_response else Response()(environ, start_response)

        local_dict = {'content_length': None, 'status_code': None}
        probe_err, probe = try_enable_probe(query)
        try:

            def _start_response(status, headers):
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

            response = self.application(
                environ, extract_response_headers(_start_response, local_dict)
            )
            return response

        finally:
            logger.debug("OdooMiddleware._profiled_request ended.")

            if probe:
                probe_resp = try_end_probe(
                    probe,
                    response_status_code=local_dict['status_code'],
                    response_len=local_dict['content_length'],
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

    def _apm_trace(self, environ, start_response, extended=False):
        transaction = try_apm_start_transaction(extended=extended)
        local_dict = {'content_length': 0, 'status_code': 500}
        try:
            response = self.application(
                environ, extract_response_headers(start_response, local_dict)
            )
        finally:
            if transaction:
                try_apm_stop_and_queue_transaction(
                    controller_name=transaction.name or environ['REQUEST_URI'],
                    uri=environ['REQUEST_URI'],
                    framework="odoo",
                    http_host=environ['HTTP_HOST'],
                    method=environ['REQUEST_METHOD'],
                    response_code=local_dict['status_code'],
                    stdout=local_dict['content_length'],
                )

        return response
