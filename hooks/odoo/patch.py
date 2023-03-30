import sys
from blackfire.utils import import_module, get_logger, get_executable_path
from blackfire.hooks.utils import patch_module

log = get_logger(__name__)

MIN_SUPPORTED_VERSION = '13'


def patch():
    # this defensive check is necessary since sometimes argv is not present
    # during bootstrap and also needs to be done before importing odoo as we modify
    # sys.path
    if hasattr(sys, 'argv'):
        # Since Odoo is not importable by default, try to add
        # its directory in python path.
        # Assumes that odoo-bin is in the same directory than odoo module.
        executable_path = get_executable_path(sys.argv[0])
        if executable_path is not None and executable_path.endswith(
            '/odoo-bin'
        ):
            import os
            odoo_path = os.path.dirname(executable_path)
            log.debug("Detected Odoo path: %s", odoo_path)
            sys.path.append(odoo_path)

    def _patch(module):
        from blackfire.hooks.odoo.middleware import OdooMiddleware

        module.service.wsgi_server.application = OdooMiddleware(
            module.service.wsgi_server.application
        )

    module = import_module('odoo')
    if not module:
        return False

    return patch_module('odoo', _patch, version=module.release.version)
