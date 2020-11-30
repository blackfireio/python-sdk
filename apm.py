import random
import os
import logging
import time
import re
import sys
import _blackfire_profiler as _bfext
from blackfire.utils import get_logger, IS_PY3, json_prettify, ConfigParser, is_testing, ThreadPool, get_load_avg, \
    get_cpu_count, get_memory_usage
from blackfire import agent, DEFAULT_AGENT_SOCKET, DEFAULT_AGENT_TIMEOUT, DEFAULT_CONFIG_FILE, profiler
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

        result = get_memory_usage()
        cls._cache["memory"] = result
        return result


class ApmConfig(object):

    def __init__(self):
        self.sample_rate = 1.0
        self.extended_sample_rate = 0.0
        self.key_pages = ()
        self.timespan_selectors = {}
        self.instrumented_funcs = {}


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


def enable(extended=False):
    global _apm_config

    if extended:
        profiler.start(
            builtins=True,
            profile_cpu=True,
            profile_memory=False,
            profile_timespan=True,
            instrumented_funcs=_apm_config.instrumented_funcs,
            timespan_selectors=_apm_config.timespan_selectors,
            apm_extended_trace=True,
        )

    if _MEMALLOCATOR_API_AVAILABLE:
        # starts memory profiling for the current thread and get_traced_memory()
        # will return per-thread used/peak memory
        _bfext.start_memory_profiler()

    log.debug("APM profiler enabled. (extended=%s)" % (extended))


def disable():
    if _MEMALLOCATOR_API_AVAILABLE:
        _bfext.stop_memory_profiler()
    _RuntimeMetrics.reset()

    profiler.stop()

    log.debug("APM profiler disabled.")


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
        new_apm_config.instrumented_funcs = agent_resp.get_instrumented_funcs()
        new_apm_config.timespan_selectors = agent_resp.get_timespan_selectors()

        # update the process-wise global apm configuration. Once this is set
        # the new HTTP requests making initialize() will get this new config
        _apm_config = new_apm_config

        if log.isEnabledFor(logging.DEBUG):
            log.debug(
                "APM Configuration updated. [%s] [%s]",
                json_prettify(_apm_config.__dict__),
                os.getpid(),
            )


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


def _send_trace(req):
    try:
        with get_agent_connection() as agent_conn:
            agent_conn.send(req.to_bytes())

            response_raw = agent_conn.recv()
            _update_apm_config(response_raw)

            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    "APM trace sent. [%s]",
                    req,
                )
    except Exception as e:
        if is_testing():
            raise e
        log.error("APM message could not be sent. [reason:%s]" % (e))


def send_trace(request, extended, **kwargs):
    global _apm_config

    kwargs['file-format'] = 'BlackfireApm'
    kwargs['sample-rate'] = _apm_config.sample_rate

    if extended:
        kwargs['load'] = get_load_avg()
        kwargs['nproc'] = get_cpu_count()
        kwargs['cost-dimensions'] = 'wt cpu mu pmu'
        kwargs['extended-sample-rate'] = _apm_config.extended_sample_rate

    headers = {}
    for k, v in kwargs.items():
        if v is not None:
            # convert `_` to `-` in keys. e.g: controller_name -> controller-name
            k = k.replace('_', '-')
            headers[k] = v

    extended_traces = profiler.get_traces(extended=True) if extended else None
    profiler.clear_traces()  # we can clear the traces

    apm_trace_req = agent.BlackfireAPMRequest(
        headers=headers, data=str(extended_traces).strip()
    )

    # We should not have a blocking call in APM path. Do agent connection setup
    # socket send in a separate thread.
    _thread_pool.apply(_send_trace, args=(apm_trace_req, ))
