import logging

from .middleware import OdooMiddleware

logger = logging.getLogger(__name__)


def _blackfire_post_load():
    logger.debug('Odoo._blackfire_post_load called.')
    import odoo

    if odoo.release.version_info[0] >= 15:
        odoo.http.root = OdooMiddleware(odoo.http.root)
    else:
        odoo.service.wsgi_server.application = OdooMiddleware(
            odoo.service.wsgi_server.application
        )
