import importlib
import traceback
from blackfire.utils import function_wrapper, import_module


def _insert_leading_middleware(*args, **kwargs):
    try:
        from django.conf import settings
        blackfire_middleware_path = 'blackfire.middleware.DjangoMiddleware'

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

        # TODO: log
        print("Django settings.MIDDLEWARE patched.")

    except:
        # TODO: log
        traceback.print_exc()


def patch():
    module = import_module('django.core.handlers.base')
    if not module:
        return False

    # already patched?
    if getattr(module, '_blackfire_patch', False):
        return
    setattr(module, '_blackfire_patch', True)

    try:
        module.BaseHandler.load_middleware = function_wrapper(
            module.BaseHandler.load_middleware,
            pre_func=_insert_leading_middleware
        )
        return True
    except:
        # TODO: log
        traceback.print_exc()

    return False
