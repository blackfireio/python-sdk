from blackfire.utils import wrap, import_module, get_logger
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
        # TODO: Print required version. 0.13.0
        _wrap_build_middleware_stack._orig = module.FastAPI.build_middleware_stack
        module.FastAPI.build_middleware_stack = _wrap_build_middleware_stack

        fastapi_version = getattr(module, '__version__', None)
        log.debug('FastAPI version %s patched.', (fastapi_version))

        setattr(module, '_blackfire_patch', True)

        return True
    except Exception as e:
        log.exception(e)

    return False
