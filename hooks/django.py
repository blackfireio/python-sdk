import importlib
import traceback
from blackfire.utils import function_wrapper


def _insert_leading_middleware(*args, **kwargs):
    try:
        from django.conf import settings

        settings_key = None
        if hasattr(settings, 'MIDDLEWARE'):
            settings_key = 'MIDDLEWARE'
        elif hasattr(settings, 'MIDDLEWARE_CLASSES'):
            settings_key = 'MIDDLEWARE_CLASSES'

        if not settings_key:
            raise Exception('No MIDDLEWARE definition found in settings')

        middlewares = getattr(settings, settings_key)
        if isinstance(middlewares, list):
            middlewares = [
                'blackfire.middleware.DjangoMiddleware'
            ] + middlewares
        elif isinstance(middlewares, tuple):
            middlewares = (
                'blackfire.middleware.DjangoMiddleware',
            ) + middlewares

        setattr(settings, settings_key, middlewares)

        # TODO: log
        print("Blackfire Django middleware enabled.")

    except:
        # TODO: log
        traceback.print_exc()


def patch():
    # TODO: if already imported print warning? I did not see anyone has done
    # similar thing?

    try:
        module = importlib.import_module('django.core.handlers.base')
    except ImportError:
        # This is an expected situation where patch_all() is called. User does not
        # have to have all libraries available
        return False

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
