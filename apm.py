import random
import _blackfire_profiler as _bfext
from blackfire.utils import get_logger

# globals
_config = None
log = get_logger(__name__)


def _init_apm_config():
    # init shared configuration from the C extension
    global _config

    _config = _bfext.get_apm_data()["config"]


_init_apm_config()


def trigger_trace():
    global _config

    return _config["sample_rate"] >= random.random()


def trigger_extended_trace():
    global _config

    return _config["extended_sample_rate"] >= random.random()


def send_trace(request, **kwargs):
    print(kwargs)
    print(">>>>>>>>>>>>>>>")


def send_extended_trace(request, **kwargs):
    pass
