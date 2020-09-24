import random
import os
import logging
import time
import re
import sys
import platform
import _blackfire_profiler as _bfext
from blackfire.utils import get_logger, IS_PY3, json_prettify, ConfigParser, is_testing, ThreadPool
from blackfire import agent, DEFAULT_AGENT_SOCKET, DEFAULT_AGENT_TIMEOUT, DEFAULT_CONFIG_FILE
from contextlib import contextmanager

_thread_pool = ThreadPool()

log = get_logger(__name__)


class _RuntimeMetrics(object):

    CACHE_INTERVAL = 1.0
    _last_collected = 0
    _cache = {}

    @classmethod
    def reset(cls):
        cls._last_collected = 0
        cls._cache = {}

    @classmethod
    def memory(cls):
        if time.time() - cls._last_collected <= cls.CACHE_INTERVAL:
            return cls._cache["memory"]

        import psutil

        usage = peak_usage = 0

        mem_info = psutil.Process().memory_info()
        usage = mem_info.rss  # this is platform independent
        plat_sys = platform.system()
        if plat_sys == 'Windows':
            # psutil uses GetProcessMemoryInfo API to get PeakWorkingSet
            # counter. It is in bytes.
            peak_usage = mem_info.peak_wset
        else:
            import resource
            peak_usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            if plat_sys == "Linux":
                peak_usage = peak_usage * 1024

        result = (usage, peak_usage)
        cls._cache["memory"] = result
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


_apm_config = ApmConfig()
_apm_probe_config = ApmProbeConfig()

# do not even evaluate the params if DEBUG is not set in APM path

log.debug(
    "APM Configuration initialized. [%s] [%s] [%s]",
    json_prettify(_apm_config.__dict__),
    json_prettify(_apm_probe_config.__dict__),
    os.getpid(),
)

_MEMALLOCATOR_API_AVAILABLE = sys.version_info[
    0] == 3 and sys.version_info[1] >= 5


def start_memory_profiler():
    if _MEMALLOCATOR_API_AVAILABLE:
        log.debug("APM memory profiler activated.")
        _bfext.start_memory_profiler()


def stop_memory_profiler():
    _bfext.stop_memory_profiler()
    _RuntimeMetrics.reset()

    log.debug("APM memory profiler deactivated.")


def get_traced_memory():
    if _MEMALLOCATOR_API_AVAILABLE:
        return _bfext.get_traced_memory()
    else:
        return _RuntimeMetrics.memory()


def reset():
    global _apm_config, _apm_probe_config, _runtime_metrics

    _apm_config = ApmConfig()
    # init config for the APM for communicating with the Agent
    _apm_probe_config = ApmProbeConfig()
    _RuntimeMetrics.reset()


def trigger_trace():
    global _apm_config, _apm_probe_config

    return _apm_probe_config.apm_enabled and \
        _apm_config.sample_rate >= random.random()


def trigger_extended_trace():
    global _apm_config, _apm_probe_config

    return _apm_probe_config.apm_enabled and \
        _apm_config.extended_sample_rate >= random.random()


def trigger_auto_profile(method, uri, controller_name):
    global _apm_config

    for key_page in _apm_config.key_pages:

        # skip key-page if mandatory fields are missing
        if "matcher-pattern" not in key_page or "id" not in key_page:
            log.warning(
                "KeyPage skipped as mandatory fields are missing. [%s]",
                key_page
            )
            continue

        # auto-profile defined? profile is optional
        profile = key_page.get("profile", "false")
        if profile == "false":
            continue

        # matcher-type is optional
        matcher_type = key_page.get("matcher-type", "uri")
        if matcher_type not in ["uri", "controller"]:
            continue

        # method matches? http_method is optional
        http_method = key_page.get("http-method", "*")
        if http_method != "*" and method != http_method:
            continue

        # first char is '=' for equal matcher and '#' or '/' for regex matcher
        matcher_pattern = key_page["matcher-pattern"]
        matcher_value = uri
        if matcher_type == 'controller':
            matcher_value = controller_name
        if matcher_pattern[0] == '=':
            if matcher_pattern[1:] == matcher_value:
                return True, key_page
        elif matcher_pattern[0] == '/' or matcher_pattern[0] == '#':
            # first and last chars are regex chars
            if re.match(matcher_pattern[1:-1], matcher_value):
                log.debug(
                    "matcher_value:%s matched against matcher-pattern:%s." %
                    (matcher_value, key_page["matcher-pattern"])
                )
                return True, key_page

    return False, None


@contextmanager
def get_agent_connection():
    global _apm_probe_config

    agent_conn = agent.Connection(
        _apm_probe_config.agent_socket, _apm_probe_config.agent_timeout
    )
    try:
        agent_conn.connect()
        yield agent_conn
    finally:
        agent_conn.close()


def _update_apm_config(response):
    global _apm_config

    agent_resp = agent.BlackfireAPMResponse().from_bytes(response)

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
        _apm_config = new_apm_config

        if log.isEnabledFor(logging.DEBUG):
            log.debug(
                "APM Configuration updated. [%s] [%s]",
                json_prettify(_apm_config.__dict__),
                os.getpid(),
            )


def _send_trace(data):
    try:
        with get_agent_connection() as agent_conn:
            agent_conn.send(data)

            response_raw = agent_conn.recv()
            _update_apm_config(response_raw)

            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    "APM trace sent. [%s]",
                    json_prettify(data),
                )

    except Exception as e:
        if is_testing():
            raise e
        log.error("APM message could not be sent. [reason:%s]" % (e))


def get_autoprofile_query(method, uri, key_page):
    # TODO: blackfire-auth header?
    data = """file-format: BlackfireApmRequestProfileQuery
        uri: {}
        method: {}
        key-page-id: {}\n""".format(method, uri, key_page["id"])
    if IS_PY3:
        data = bytes(data, 'ascii')
    data += agent.Protocol.HEADER_MARKER

    with get_agent_connection() as agent_conn:
        agent_conn.send(data)

        response_raw = agent_conn.recv()
        agent_resp = agent.BlackfireAPMResponse().from_bytes(response_raw)

        return agent_resp.args['blackfire-query'][0]


def send_trace(request, **kwargs):
    global _apm_config

    data = """file-format: BlackfireApm
        sample-rate: {}
    """.format(_apm_config.sample_rate)
    for k, v in kwargs.items():
        if v:
            # convert `_` to `-` in keys. e.g: controller_name -> controller-name
            k = k.replace('_', '-')
            data += "%s: %s\n" % (k, v)
    if IS_PY3:
        data = bytes(data, 'ascii')
    data += agent.Protocol.HEADER_MARKER

    # We should not have a blocking call in APM path. Do agent connection setup
    # socket send in a separate thread.
    _thread_pool.apply(_send_trace, args=(data, ))


def send_extended_trace(request, **kwargs):
    pass
