from blackfire.utils import unwrap, get_logger, import_module, wrapfn
from blackfire.hooks.utils import patch_module, unpatch_module
from blackfire.hooks.pyramid.middleware import BlackfirePyramidMiddleware

log = get_logger(__name__)


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
        return '0.0'


def patch():
    module = import_module('pyramid')
    if not module:
        return False

    pyramid_supported_min_version = '1.5.0'
    pyramid_version = _get_pyramid_version()
    if pyramid_version < pyramid_supported_min_version:
        log.warning(
            'Blackfire Pyramid middleware requires Pyramid %s and up. '
            'Current version is %s.' %
            (pyramid_supported_min_version, pyramid_version)
        )
        return False

    def _patch(module):
        module.config.Configurator.make_wsgi_app = wrapfn(
            module.config.Configurator.make_wsgi_app, _wrap_make_wsgi_app
        )

    return patch_module('pyramid', _patch)
