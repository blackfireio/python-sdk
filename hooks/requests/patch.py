from blackfire.utils import wrap2, import_module, get_logger, patch_module

log = get_logger(__name__)


def _wrap_app(instance, *args, **kwargs):
    try:
        from blackfire.hooks.flask.middleware import BlackfireFlaskMiddleware

        instance.wsgi_app = BlackfireFlaskMiddleware(instance)

        log.debug("Flask middleware enabled.")
    except Exception as e:
        log.exception(e)


def patch():

    def _patch(module):
        module.Session.send = wrap(module.Session.send, post_func=_wrap_app)

    return patch_module('requests', _patch)
