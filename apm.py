import random
import os
import _blackfire_profiler as _bfext
from blackfire.utils import get_logger, IS_PY3, json_prettify
from blackfire import agent, DEFAULT_AGENT_SOCKET, DEFAULT_AGENT_TIMEOUT
from multiprocessing.pool import ThreadPool


class ApmConfig(object):

    def __init__(self):
        self.sample_rate = 1.0
        self.extended_sample_rate = 0.0
        self.key_pages = ()
        self.timespan_entries = ()
        self.fn_arg_entries = ()


class ApmProbeConfig(object):

    def __init__(self):
        self.agent_socket = os.environ.get(
            'BLACKFIRE_AGENT_SOCKET', DEFAULT_AGENT_SOCKET
        )
        self.agent_timeout = os.environ.get(
            'BLACKFIRE_AGENT_TIMEOUT', DEFAULT_AGENT_TIMEOUT
        )


# init shared configuration from the C extension, this data will persist among
# different interpreters in the same process
_apm_config = None
# init config for the APM for communicating with the Agent
_apm_probe_config = None
_thread_pool = ThreadPool()

log = get_logger(__name__)


def initialize():
    global _apm_config, _apm_probe_config

    _apm_config = _bfext.get_or_set_ext_data("apm_config", ApmConfig())
    _apm_probe_config = _bfext.get_or_set_ext_data(
        "apm_probe_config", ApmProbeConfig()
    )

    log.debug(
        "APM Configuration initialized. [%s] [%s] [%s]",
        json_prettify(_apm_config.__dict__),
        json_prettify(_apm_probe_config.__dict__),
        os.getpid(),
    )


def trigger_trace():
    global _apm_config

    return _apm_config.sample_rate >= random.random()


def trigger_extended_trace():
    global _apm_config

    return _apm_config.extended_sample_rate >= random.random()


def _send_trace_async(data):
    agent_conn = agent.Connection(
        _apm_probe_config.agent_socket, _apm_probe_config.agent_timeout
    )
    try:
        agent_conn.connect()
        agent_conn.send(data)
    finally:
        agent_conn.close()


def send_trace(request, **kwargs):

    data = """file-format: BlackfireApm
        sample-rate:{}
    """.format(_apm_config.sample_rate)
    for k, v in kwargs.items():
        data += "%s: %s\n" % (k, v)
    data += "\n"

    if IS_PY3:
        data = bytes(data, 'ascii')

    # We should not have a blocking call in APM path. Do agent connection setup
    # socket send in a separate thread.
    _thread_pool.apply_async(_send_trace_async, args=(data, ))


def send_extended_trace(request, **kwargs):
    pass
