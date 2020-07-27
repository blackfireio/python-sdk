import random
import _blackfire_profiler as _bfext
from blackfire.utils import get_logger
from blackfire import agent


class ApmConfig(object):

    def __init__(self):
        self.sample_rate = 1.0
        self.extended_sample_rate = 0.0
        self.key_pages = ()
        self.timespan_entries = ()
        self.fn_arg_entries = ()

    #def __repr__(self):
    #    return "%s" % (self.sample_rate)


# init shared configuration from the C extension, this data will persist among
# different interpreters in the same process
_config = _bfext.get_or_set_ext_data("apm_config", ApmConfig())

log = get_logger(__name__)


def trigger_trace():
    global _config

    return _config["sample_rate"] >= random.random()


def trigger_extended_trace():
    global _config

    return _config["extended_sample_rate"] >= random.random()


def send_trace(request, **kwargs):
    print(kwargs)
    conn = agent.Connection()


def send_extended_trace(request, **kwargs):
    pass
