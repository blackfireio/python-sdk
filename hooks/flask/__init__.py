from blackfire.hooks.utils import try_enable_probe
from blackfire.hooks.flask.middleware import get_request_context, end_profile
from blackfire.utils import get_logger
from blackfire.exceptions import BlackfireProfilerException

log = get_logger(__name__)

__all__ = [
    'profile_flask_view',
]


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
