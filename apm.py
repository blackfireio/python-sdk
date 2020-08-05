import random
import os
import logging
import time
import _blackfire_profiler as _bfext
from blackfire.utils import get_logger, IS_PY3, json_prettify, run_in_thread_pool, ConfigParser, is_testing
from blackfire import agent, DEFAULT_AGENT_SOCKET, DEFAULT_AGENT_TIMEOUT, DEFAULT_CONFIG_FILE
from blackfire.exceptions import BlackfireAPMException


class RuntimeMetrics(object):

    CACHE_INTERVAL = 1.0

    def __init__(self):
        self._last_collected = 0
        self._cache = {}

    def memory(self):
        if time.time() - self._last_collected <= self.CACHE_INTERVAL:
            return self._cache["memory"]

        import psutil

        usage = peak_usage = 0

        mem_info = psutil.Process().memory_info()
        usage = mem_info.rss  # this is platform independent
        if os.name == 'nt':
            # psutil uses GetProcessMemoryInfo API to get PeakWorkingSet
            # counter. It is in bytes.
            peak_usage = mem_info.peak_wset
        else:
            import resource
            peak_usage = resource.getrusage(
                resource.RUSAGE_SELF
            ).ru_maxrss * 1024

        result = (usage, peak_usage)
        self._cache["memory"] = result
        return result


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

        # read APM_ENABLED config from env.var.
        # TODO: Config file initialization will be done later
        self.apm_enabled = bool(int(os.environ.get('BLACKFIRE_APM_ENABLED', 0)))


# init shared configuration from the C extension, this data will persist among
# different interpreters in the same process
_apm_config = None
# init config for the APM for communicating with the Agent
_apm_probe_config = None
_runtime_metrics = None

log = get_logger(__name__)


def reset():
    global _apm_config, _apm_probe_config, _runtime_metrics

    _bfext.del_ext_data("apm_config")
    _bfext.del_ext_data("apm_probe_config")
    _runtime_metrics = None


def initialize():
    global _apm_config, _apm_probe_config, _runtime_metrics

    _apm_config = _bfext.get_or_set_ext_data("apm_config", ApmConfig())
    _apm_probe_config = _bfext.get_or_set_ext_data(
        "apm_probe_config", ApmProbeConfig()
    )

    if not _runtime_metrics:
        _runtime_metrics = RuntimeMetrics()

    # do not even evaluate the params if DEBUG is not set in APM path
    if log.isEnabledFor(logging.DEBUG):
        log.debug(
            "APM Configuration initialized. [%s] [%s] [%s]",
            json_prettify(_apm_config.__dict__),
            json_prettify(_apm_probe_config.__dict__),
            os.getpid(),
        )


def trigger_trace():
    global _apm_config, _apm_probe_config

    return _apm_probe_config.apm_enabled and \
        _apm_config.sample_rate >= random.random()


def trigger_extended_trace():
    global _apm_config, _apm_probe_config

    return _apm_probe_config.apm_enabled and \
        _apm_config.extended_sample_rate >= random.random()


def _send_trace_async(data):
    agent_conn = agent.Connection(
        _apm_probe_config.agent_socket, _apm_probe_config.agent_timeout
    )

    try:
        agent_conn.connect()
        agent_conn.send(data)

        # verify agent responds success
        response_raw = agent_conn.recv()
        agent_resp = agent.BlackfireAPMResponse().from_bytes(response_raw)
        if 'false' in agent_resp.status_val_dict['success']:
            raise BlackfireAPMException(agent_resp.status_val_dict['error'])

        # Update config if any configuration update received
        if len(agent_resp.args) or len(agent_resp.key_pages):
            new_apm_config = ApmConfig()
            try:
                new_apm_config.sample_rate = float(
                    agent_resp.args['sample-rate'][0]
                )
            except:
                pass
            try:
                new_apm_config.extended_sample_rate = float(
                    agent_resp.args['extended-sample-rate'][0]
                )
            except:
                pass

            new_apm_config.key_pages = tuple(agent_resp.key_pages)

            # update the process-wise global apm configuration. Once this is set
            # the new HTTP requests making initialize() will get this new config
            _bfext.set_ext_data("apm_config", new_apm_config)

        if log.isEnabledFor(logging.DEBUG):
            log.debug(
                "APM trace sent. [%s]",
                json_prettify(data),
            )

    except Exception as e:
        if is_testing():
            raise e
        log.error("APM message could not be sent. [reason:%s]" % (e))
    finally:
        agent_conn.close()


def send_trace(request, **kwargs):
    global _runtime_metrics

    data = """file-format: BlackfireApm
        sample-rate: {}
    """.format(_apm_config.sample_rate)

    # add extra headers
    mu, pmu = _runtime_metrics.memory()
    kwargs["mu"] = mu
    kwargs["pmu"] = pmu

    for k, v in kwargs.items():
        if v:
            # convert `_` to `-` in keys. e.g: controller_name -> controller-name
            k = k.replace('_', '-')
            data += "%s: %s\n" % (k, v)

    # add final marker
    data += "\n"

    print(data)

    if IS_PY3:
        data = bytes(data, 'ascii')

    # We should not have a blocking call in APM path. Do agent connection setup
    # socket send in a separate thread.
    run_in_thread_pool(_send_trace_async, args=(data, ))


def send_extended_trace(request, **kwargs):
    pass
