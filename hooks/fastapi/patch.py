from blackfire.utils import import_module, get_logger
from blackfire.hooks.fastapi.middleware import BlackfireFastAPIMiddleware

log = get_logger(__name__)


def _wrap_build_middleware_stack(self, *args, **kwargs):
    result = _wrap_build_middleware_stack._orig(self, *args, **kwargs)
    result = BlackfireFastAPIMiddleware(result)

    log.debug("FastAPI middleware enabled.")

    return result


def patch():
    module = import_module('fastapi')
    if not module:
        return False

    # already patched?
    if getattr(module, '_blackfire_patch', False):
        return

    try:
        fastapi_supported_min_version = '0.51.0'
        fastapi_version = getattr(module, '__version__', '0.0.0')
        if fastapi_version < fastapi_supported_min_version:
            log.warning(
                'Blackfire FastAPI middleware requires FastAPI %s and up. '
                'Current version is %s.' %
                (fastapi_supported_min_version, fastapi_version)
            )
            return False

        _wrap_build_middleware_stack._orig = module.FastAPI.build_middleware_stack
        module.FastAPI.build_middleware_stack = _wrap_build_middleware_stack

        log.debug('FastAPI version %s patched.', (fastapi_version))

        setattr(module, '_blackfire_patch', True)

        return True
    except Exception as e:
        log.exception(e)

    return False
