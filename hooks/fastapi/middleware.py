import contextvars

from blackfire.exceptions import *
from blackfire import apm, generate_config
from blackfire.agent import Protocol
from blackfire.utils import get_logger, read_blackfireyml_content
from blackfire.hooks.utils import try_enable_probe, try_end_probe, \
    try_apm_start_transaction, try_apm_stop_and_queue_transaction, \
    try_validate_send_blackfireyml

log = get_logger(__name__)


def _extract_headers(d):
    headers = d.get("headers")
    if headers:
        return dict((k.decode(), v.decode()) for (k, v) in headers)
    return {}


def _add_header(response, k, v):
    response['headers'].append(
        [bytes(str(k), Protocol.ENCODING),
         bytes(str(v), Protocol.ENCODING)]
    )


_FRAMEWORK = 'FastAPI'
_req_id = 0
_cv = contextvars.ContextVar('bf_req_id')


def incr_request_id():
    global _req_id
    _req_id += 1
    return _req_id


class BlackfireFastAPIMiddleware:

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        global _cv, _req_id

        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        method = scope.get("method")
        path = scope.get('path')
        transaction = None
        scheme = scope.get('scheme')
        server = scope.get('server')
        probe_err = probe = None
        request_headers = _extract_headers(scope)
        http_host = request_headers.get('host')
        endpoint = None
        trigger_auto_profile, key_page = apm.trigger_auto_profile(
            method, path, endpoint
        )
        # autobuild triggered?
        if method == 'POST' and 'x-blackfire-query' in request_headers:
            config = generate_config(query=request_headers['x-blackfire-query'])
            if config.is_blackfireyml_asked():
                log.debug(
                    'FastAPI autobuild triggered. Sending `.blackfire.yml` file.'
                )
                blackfireyml_content = read_blackfireyml_content()
                agent_response = try_validate_send_blackfireyml(
                    config, blackfireyml_content
                )
                body = blackfireyml_content or ''
                body = bytes(str(body), Protocol.ENCODING)

                async def wrapped_send_bfyaml(response):
                    nonlocal body, agent_response

                    try:
                        if agent_response:  # send response if signature is validated
                            if response.get("type") == "http.response.start":
                                _add_header(
                                    response, agent_response[0],
                                    agent_response[1]
                                )

                                # We can add headers as many as we want but it was
                                # not possible to mutate an existing header without
                                # using below approach.
                                # override the Content-Length received from the original
                                # Response. Note: MutableHeaders is present in the minimum
                                # Starlette version used in minimum FastAPI version (0.51.0)
                                from starlette.datastructures import MutableHeaders
                                headers = MutableHeaders(
                                    raw=response["headers"]
                                )
                                headers['Content-Length'] = str(len(body))
                            elif response.get("type") == "http.response.body":
                                response["body"] = body

                        await send(response)
                    except Exception as e:
                        log.exception(e)

                return await self.app(scope, receive, wrapped_send_bfyaml)

        if 'x-blackfire-query' in request_headers:
            log.debug(
                "FastAPIMiddleware profile request. [query=%s]",
                request_headers['x-blackfire-query']
            )

            _cv.set(incr_request_id())
            probe_err, probe = try_enable_probe(
                request_headers['x-blackfire-query'], ctx_var=_cv
            )
        elif trigger_auto_profile:
            log.debug("FastAPI autoprofile triggered.")
            query = apm.get_autoprofile_query(method, path, key_page)
            if query:
                _cv.set(incr_request_id())
                probe_err, probe = try_enable_probe(query, ctx_var=_cv)
        elif apm.trigger_trace():
            _cv.set(incr_request_id())
            transaction = try_apm_start_transaction(
                extended=apm.trigger_extended_trace(), ctx_var=_cv
            )

        content_length = status_code = None

        async def wrapped_send(response):
            nonlocal content_length, status_code, endpoint

            if 'endpoint' in scope:
                endpoint = scope['endpoint'].__name__

            try:
                if response.get("type") == "http.response.start":
                    response_headers = {}
                    if "status" in response:
                        status_code = response["status"]
                    if "headers" in response:
                        response_headers = _extract_headers(response)
                    content_length = response_headers.get(
                        'content-length', None
                    )

                    if probe:
                        if probe_err:
                            if probe_err is not BlackfireInvalidSignatureError:
                                _add_header(
                                    response, 'X-Blackfire-Error', probe_err[1]
                                )
                        else:
                            _add_header(
                                response, 'X-Blackfire-Response',
                                probe.get_agent_prolog_response().status_val
                            )
                    elif transaction:
                        assert (transaction == apm._get_current_transaction())

                        try_apm_stop_and_queue_transaction(
                            controller_name=transaction.name or endpoint,
                            uri=path,
                            framework=_FRAMEWORK,
                            http_host=http_host,
                            method=method,
                            response_code=status_code if status_code else 500,
                            stdout=content_length if content_length else 0,
                        )
            except Exception as e:
                log.exception(e)
            finally:
                return await send(response)

        try:
            return await self.app(scope, receive, wrapped_send)
        finally:
            if probe:
                log.debug("FastAPIMiddleware profile request ended.")

                r = try_end_probe(
                    probe,
                    response_status_code=status_code,
                    response_len=content_length,
                    controller_name=endpoint,
                    framework=_FRAMEWORK,
                    http_method=method,
                    http_uri=path,
                    https='1' if scheme == 'https' else '',
                    http_server_addr=server[0] if server else '',
                    http_server_port=server[1] if server else '',
                    http_header_host=http_host,
                    http_header_user_agent=request_headers.get('user-agent'),
                    http_header_x_forwarded_host=request_headers
                    .get('x-forwarded-host'),
                    http_header_x_forwarded_proto=request_headers
                    .get('x-forwarded-proto'),
                    http_header_x_forwarded_port=request_headers
                    .get('x-forwarded-port'),
                )
