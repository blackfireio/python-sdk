from blackfire import profiler
from blackfire.utils import wrapfn, get_logger
from blackfire.hooks.utils import patch_module

log = get_logger(__name__)


def _wrap_send(fn, self, request, **kwargs):
    try:
        bf_http_title = request.headers.get('X-Blackfire-HTTP-Query-Title')

        if bf_http_title is not None:
            with profiler.start_pending_span(
                name=bf_http_title, fn_name='requests.sessions.Session.send'
            ) as span:
                r = fn(self, request, **kwargs)
                return r
    except Exception as e:
        log.exception(e)  # no matter what, call the orig. fn

    return fn(self, request, **kwargs)


def patch():

    def _patch(module):
        module.Session.send = wrapfn(module.Session.send, _wrap_send)

    return patch_module('requests', _patch)
