from blackfire.utils import wrap, get_logger
from blackfire.hooks.utils import patch_module

log = get_logger(__name__)


def _insert_leading_middleware(*args, **kwargs):
    try:
        from django.conf import settings
        blackfire_middleware_path = 'blackfire.hooks.django.middleware.BlackfireDjangoMiddleware'

        settings_key = None
        if hasattr(settings, 'MIDDLEWARE'):
            settings_key = 'MIDDLEWARE'
        elif hasattr(settings, 'MIDDLEWARE_CLASSES'):
            settings_key = 'MIDDLEWARE_CLASSES'

        if not settings_key:
            raise Exception('No MIDDLEWARE definition found in settings')

        middlewares = getattr(settings, settings_key)

        # middleware is already enabled?
        if blackfire_middleware_path in middlewares:
            return

        if isinstance(middlewares, list):
            middlewares = [blackfire_middleware_path] + middlewares
        elif isinstance(middlewares, tuple):
            middlewares = (blackfire_middleware_path, ) + middlewares

        setattr(settings, settings_key, middlewares)

        log.debug("Django settings.MIDDLEWARE patched.")

    except Exception as e:
        log.exception(e)


def patch():

    def _patch(module):
        module.BaseHandler.load_middleware = wrap(
            module.BaseHandler.load_middleware,
            pre_func=_insert_leading_middleware
        )

    return patch_module('django.core.handlers.base', _patch, package='django')
