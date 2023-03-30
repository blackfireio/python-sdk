from blackfire.utils import wrap, get_logger
from blackfire.hooks.utils import patch_module

log = get_logger(__name__)

MIN_SUPPORTED_VERSION = '0.12'


def _wrap_app(instance, *args, **kwargs):
    try:
        from blackfire.hooks.flask.middleware import BlackfireFlaskMiddleware

        instance.wsgi_app = BlackfireFlaskMiddleware(instance)

        log.debug("Flask middleware enabled.")
    except Exception as e:
        log.exception(e)


def patch():

    def _patch(module):
        module.Flask.__init__ = wrap(module.Flask.__init__, post_func=_wrap_app)

    return patch_module('flask', _patch)
