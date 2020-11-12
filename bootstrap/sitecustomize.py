import os
import sys
import imp
import blackfire

from blackfire.utils import get_logger

log = get_logger(__name__)

blackfire.bootstrap()

# Ensure other sitecustomize.py is called if available in sys.path
bootstrap_dir = os.path.dirname(__file__)
path = list(sys.path)

if bootstrap_dir in path:
    path.remove(bootstrap_dir)

try:
    (f, path, description) = imp.find_module("sitecustomize", path)
except ImportError:
    pass
else:
    log.debug("sitecustomize from user found in: %s", path)
    imp.load_module("sitecustomize", f, path, description)
