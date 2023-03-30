from blackfire.utils import get_logger, import_module, wrapfn, unwrap
from blackfire.hooks.utils import patch_module, check_supported_version, unpatch_module
from blackfire.hooks.pyramid.middleware import BlackfirePyramidMiddleware

log = get_logger(__name__)

MIN_SUPPORTED_VERSION = '1.5.0'


def _wrap_make_wsgi_app(fn, self, *args, **kwargs):
    result = fn(self, *args, **kwargs)
    result = BlackfirePyramidMiddleware(result)

    log.debug("Pyramid middleware enabled.")
    return result


def _get_pyramid_version():
    try:
        import pkg_resources
        return pkg_resources.get_distribution("pyramid").version
    except Exception as e:
        log.exception(e)
        return '0.0.0'


def patch():
    module = import_module('pyramid')
    if not module:
        return False

    pyramid_version = _get_pyramid_version()
    if not check_supported_version('pyramid', pyramid_version):
        return False

    def _patch(module):
        module.Configurator.make_wsgi_app = wrapfn(
            module.Configurator.make_wsgi_app, _wrap_make_wsgi_app
        )

    return patch_module(
        'pyramid.config', _patch, package='pyramid', version=pyramid_version
    )


def unpatch():

    def _unpatch(_):
        import pyramid
        unwrap(pyramid.config.Configurator, "make_wsgi_app")

    unpatch_module('pyramid.config', _unpatch, package='pyramid')
