from blackfire.utils import import_module, get_logger, wrapfn, unwrap
from blackfire.hooks.fastapi.middleware import BlackfireFastAPIMiddleware
from blackfire.hooks.utils import patch_module, unpatch_module

log = get_logger(__name__)


def _wrap_build_middleware_stack(fn, self, *args, **kwargs):
    result = fn(self, *args, **kwargs)
    result = BlackfireFastAPIMiddleware(result)

    log.debug("FastAPI middleware enabled.")
    return result


def patch():
    module = import_module('fastapi')
    if not module:
        return False

    fastapi_supported_min_version = '0.51.0'
    fastapi_version = getattr(module, '__version__', '0.0.0')
    if fastapi_version < fastapi_supported_min_version:
        log.warning(
            'Blackfire FastAPI middleware requires FastAPI %s and up. '
            'Current version is %s.' %
            (fastapi_supported_min_version, fastapi_version)
        )
        return False

    def _patch(module):
        module.FastAPI.build_middleware_stack = wrapfn(
            module.FastAPI.build_middleware_stack, _wrap_build_middleware_stack
        )

    return patch_module('fastapi', _patch, version=fastapi_version)


def unpatch():

    def _unpatch(_):
        import fastapi
        unwrap(fastapi.FastAPI, "build_middleware_stack")

    unpatch_module('fastapi', _unpatch)
