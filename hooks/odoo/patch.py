from blackfire.utils import wrap, import_module, get_logger

log = get_logger(__name__)


def patch():
    module = import_module('odoo')
    if not module:
        return False

    # already patched?
    if getattr(module, '_blackfire_patch', False):
        return

    try:
        from blackfire.hooks.odoo.middleware import OdooMiddleware

        module.service.wsgi_server.application = OdooMiddleware(
            module.service.wsgi_server.application
        )

        log.debug('Odoo version %s patched.', (module.release.version))

        setattr(module, '_blackfire_patch', True)

        return True
    except Exception as e:
        log.exception(e)

    return False
