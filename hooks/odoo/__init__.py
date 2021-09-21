import logging

import odoo
from .middleware import OdooMiddleware

logger = logging.getLogger(__name__)


def _blackfire_post_load():
    logger.info('Hello Blackfire!')
    odoo.service.wsgi_server.application = OdooMiddleware(odoo.service.wsgi_server.application)
