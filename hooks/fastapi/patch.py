from blackfire.utils import import_module, get_logger, wrapfn, unwrap
from blackfire.hooks.fastapi.middleware import BlackfireFastAPIMiddleware
from blackfire.hooks.utils import patch_module, unpatch_module

log = get_logger(__name__)


def _wrap_build_middleware_stack(fn, self, *args, **kwargs):
    result = fn(self, *args, **kwargs)
    # FastAPI support subapplications where you have multiple independent FastAPI
    # apps. See https://fastapi.tiangolo.com/advanced/sub-applications/
    # These subapps are mounted to the main one and when that happens,
    # build_middleware_stack() adds Blackfire FastAPI middleware more than once.
    # Check that condition via a flag.
    if getattr(fn, "_blackfire_patch", False):
        return result
    result = BlackfireFastAPIMiddleware(result)
    fn._blackfire_patch = True

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
        fastapi.FastAPI.build_middleware_stack._blackfire_patch = False

    unpatch_module('fastapi', _unpatch)
