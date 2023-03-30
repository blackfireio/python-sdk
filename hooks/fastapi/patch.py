from blackfire.utils import import_module, get_logger, wrapfn, unwrap
from blackfire.hooks.fastapi.middleware import BlackfireFastAPIMiddleware
from blackfire.hooks.utils import patch_module, check_supported_version, unpatch_module

log = get_logger(__name__)

MIN_SUPPORTED_VERSION = '0.51.0'


def _wrap_build_middleware_stack(fn, self, *args, **kwargs):
    result = fn(self, *args, **kwargs)
    result = BlackfireFastAPIMiddleware(result)

    log.debug("FastAPI middleware enabled.")
    return result


def patch():
    module = import_module('fastapi')
    if not module:
        return False

    fastapi_version = getattr(module, '__version__', '0.0.0')
    if not check_supported_version('fastapi', fastapi_version):
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
