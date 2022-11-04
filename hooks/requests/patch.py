from blackfire.utils import wrap2, get_logger
from blackfire.hooks.utils import patch_module

log = get_logger(__name__)


def patch():

    def _patch(module):
        pass

    return patch_module('requests', _patch)
