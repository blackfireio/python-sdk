import random
import _blackfire_profiler as _bfext
from blackfire.utils import get_logger
from blackfire import agent, generate_config


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
_apm_config = None

# init config for the APM for communicating with the Agent
_apm_probe_config = None

log = get_logger(__name__)


def initialize():
    global _apm_config, _apm_probe_config

    _apm_config = _bfext.get_or_set_ext_data("apm_config", ApmConfig())
    _apm_probe_config = _bfext.get_or_set_ext_data(
        "apm_probe_config", generate_config()
    )


def trigger_trace():
    global _apm_config

    return _apm_config["sample_rate"] >= random.random()


def trigger_extended_trace():
    global _apm_config

    return _apm_config["extended_sample_rate"] >= random.random()


def send_trace(request, **kwargs):

    import time
    for i in range(25):
        agent_conn = agent.Connection(_apm_probe_config)
        agent_conn.connect(prolog=False)

        data = """file-format: BlackfireApm
    sample-rate: 1.0
    uri: /index.php
    timestamp: {}
    response-code: 200
    """.format(time.time())
        data = bytes(data, 'ascii')
        agent_conn.send(data)
        agent_conn.close()
        time.sleep(0.2)
        print(i)


def send_extended_trace(request, **kwargs):
    pass
