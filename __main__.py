import sys
from blackfire.utils import get_logger

log = get_logger(__name__)

cmd = sys.argv[1]
if cmd == 'install-bootstrap' or cmd == 'uninstall-bootstrap':
    log.warning(
        'DeprecationWarning: Do not use this command, use `blackfire-python` instead.'
    )
