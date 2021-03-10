import os
import sys
import blackfire

from blackfire.utils import get_logger

log = get_logger("blackfire.sitecustomize")

# Ensure other sitecustomize.py is called if available in sys.path
bootstrap_dir = os.path.dirname(__file__)
if bootstrap_dir in sys.path:
    index = sys.path.index(bootstrap_dir)
    del sys.path[index]

    # hold a reference
    ref_sitecustomize = sys.modules["sitecustomize"]
    del sys.modules["sitecustomize"]
    try:
        import sitecustomize
    except ImportError:
        sys.modules["sitecustomize"] = ref_sitecustomize
    else:
        log.debug("sitecustomize from user found in: %s", sys.path)
    finally:
        # reinsert the bootstrap_dir again
        sys.path.insert(index, bootstrap_dir)

blackfire.bootstrap()
