from blackfire import apm
from blackfire.hooks.utils import try_enable_probe, try_end_probe


def _extract_headers(d):
    headers = d.get("headers")
    if headers:
        return dict((k.decode(), v.decode()) for (k, v) in headers)
    return {}


def _add_header(response, k, v):
    response['headers'].append([bytes(k, 'ascii'), bytes(v, 'ascii')])


_FRAMEWORK = 'FastAPI'


class BlackfireFastAPIMiddleware:

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        # TODO: Add logs

        method = scope.get("method")
        path = scope.get('path')
        transaction = None
        scheme = scope.get('scheme')
        server = scope.get('server')
        probe_err = probe = None
        request_headers = _extract_headers(scope)
        endpoint = None
        if 'endpoint' in scope:
            endpoint = scope['endpoint'].__name__

        if 'x-blackfire-query' in request_headers:
            probe_err, probe = try_enable_probe(
                request_headers['x-blackfire-query']
            )
        elif apm.trigger_trace():
            # TODO: We don't use _start_transaction() as there are checks to see
            # if there are outstanding transactions in a TLS value
            transaction = apm.ApmTransaction(extended=False)
            #transaction = apm._start_transaction(extended=apm.trigger_extended_trace())

        content_length = status_code = None

        async def wrapped_send(response):
            nonlocal content_length, status_code

            if response.get("type") == "http.response.start":
                response_headers = {}
                if "status" in response:
                    status_code = response["status"]
                if "headers" in response:
                    response_headers = _extract_headers(response)
                content_length = response_headers.get('content-length', None)

                if probe:
                    if probe_err:
                        _add_header(response, 'X-Blackfire-Error', probe_err[1])
                    else:
                        _add_header(
                            response, 'X-Blackfire-Response',
                            probe.get_agent_prolog_response().status_val
                        )
                elif transaction:
                    #apm._stop_and_queue_transaction(
                    transaction.stop()
                    apm._queue_trace(
                        transaction,
                        controller_name=transaction.name or endpoint,
                        uri=path,
                        framework=_FRAMEWORK,
                        http_host='http_host',  # TODO:
                        method=method,
                        response_code=status_code if status_code else 500,
                        stdout=content_length if content_length else 0,
                    )
            return await send(response)

        try:
            return await self.app(scope, receive, wrapped_send)
        finally:
            if probe:
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
                    http_server_software='',  # TODO
                    http_server_port=server[1] if server else '',
                    http_header_host=request_headers.get('host'),
                    http_header_user_agent=request_headers.get('user-agent'),
                    http_header_x_forwarded_host='',  # TODO
                    http_header_x_forwarded_proto='',  # TODO
                    http_header_x_forwarded_port='',  # TODO
                    http_header_forwarded='',  # TODO
                )
