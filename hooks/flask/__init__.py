from blackfire.hooks.utils import try_enable_probe, try_end_probe, add_probe_response_header
from blackfire.utils import get_logger

log = get_logger(__name__)

__all__ = [
    'profile_flask_view',
]


def get_current_request():
    import flask
    return flask.request


def get_request_context():
    from flask import g
    return g


def end_profile(response):
    req_context = get_request_context()
    request = get_current_request()

    if req_context.probe is None:
        return

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


def profile_flask_view(
    func=None,
    client_id=None,
    client_token=None,
    title=None,
):

    def inner_func(func):

        def wrapper(*args, **kwargs):
            import flask
            # already patched?
            if getattr(flask, '_blackfire_patch', False):
                log.error('Flask is already patched. Profiling is disabled.')
                return func(*args, **kwargs)

            req_context = get_request_context()
            if not req_context:
                log.error(
                    'Function is decorated via `profile_flask_view` but no application context found. Profiling is disabled.'
                )
                return func(*args, **kwargs)

            @flask.after_this_request
            def end_profile_after_this_request(response):
                return end_profile(response)

            req_context.probe_err, req_context.probe = try_enable_probe(
                query=None,
                client_id=client_id,
                client_token=client_token,
                title=title
            )
            try:
                result = func(*args, **kwargs)
            finally:
                pass

            return result

        return wrapper

    # return wrapper function if no parantheses and return decorator if arguments provided
    if callable(func):
        return inner_func(func)
    else:
        return inner_func
