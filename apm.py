import random
import os
import logging
import platform
import re
import sys
import _blackfire_profiler as _bfext
from threading import Thread
from blackfire.utils import get_logger, IS_PY3, json_prettify, ConfigParser, \
    is_testing, get_load_avg, get_cpu_count, get_os_memory_usage, Queue, \
        get_probed_runtime
from blackfire import agent, DEFAULT_AGENT_SOCKET, DEFAULT_AGENT_TIMEOUT, \
    DEFAULT_CONFIG_FILE, profiler, VERSION
from contextlib import contextmanager

log = get_logger(__name__)

DEFAULT_TIMESPAN_THRESHOLD_PER_RULE = 100
DEFAULT_TIMESPAN_THRESHOLD_GLOBAL = 200


class _ApmWorker(Thread):

    def __init__(self):
        Thread.__init__(self)
        # infinite Queue, put() should not block
        self._tasks = Queue(0)
        self.daemon = True
        self.start()

    def add_task(self, fn, args=(), kwargs={}):
        if is_testing():
            fn(*args, **kwargs)
        else:
            self._tasks.put((fn, args, kwargs))

    def run(self):
        while True:
            func, args, kwargs = self._tasks.get()
            try:
                if func is None:
                    break
                func(*args, **kwargs)
            except Exception as e:
                print(e)
            finally:
                self._tasks.task_done()

    def close(self):
        self._tasks.put((None, None, None))


class ApmConfig(object):

    def __init__(self):
        self.sample_rate = 1.0
        self.extended_sample_rate = 0.0
        self.disable_config_update = 0
        self.key_pages = ()
        self.timespan_selectors = {}
        self.instrumented_funcs = {}
        self.config_version = None
        self.timespan_time_threshold = 0  #ms
        self.timespan_threshold_per_rule = 100
        self.timespan_threshold_global = 200

        # some env. vars used in testing
        self.sample_rate = float(
            os.environ.get('BLACKFIRE_APM_SAMPLE_RATE_TEST', self.sample_rate)
        )
        self.extended_sample_rate = float(
            os.environ.get(
                'BLACKFIRE_APM_EXTENDED_SAMPLE_RATE_TEST',
                self.extended_sample_rate
            )
        )
        self.disable_config_update = bool(int(os.environ.get(
                'BLACKFIRE_APM_DISABLE_CONFIG_UPDATE_TEST',
                self.disable_config_update)))

        self.timespan_time_threshold = int(
            os.environ.get('BLACKFIRE_APM_TIMESPAN_TIME_THRESHOLD_TEST', self.timespan_time_threshold)
        )


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
_apm_worker = _ApmWorker()

# do not even evaluate the params if DEBUG is not set in APM path

log.debug(
    "APM Configuration initialized. [%s] [%s] [%s]",
    json_prettify(_apm_config.__dict__),
    json_prettify(_apm_probe_config.__dict__),
    os.getpid(),
)


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
            timespan_threshold=_apm_config.timespan_time_threshold,
            apm_timespan_threshold_per_rule=_apm_config.\
                timespan_threshold_per_rule,
            apm_timespan_threshold_global=_apm_config.timespan_threshold_global,
        )

    log.debug("APM profiler enabled. (extended=%s)" % (extended))


def disable():
    profiler.stop()

    log.debug("APM profiler disabled.")


def get_traced_memory():
    return profiler.runtime_metrics.memory()


def reset():
    global _apm_config, _apm_probe_config

    _apm_config = ApmConfig()
    # init config for the APM for communicating with the Agent
    _apm_probe_config = ApmProbeConfig()
    profiler.runtime_metrics.reset()


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

    if _apm_config.disable_config_update:
        return

    new_apm_config = ApmConfig()
    try:
        new_apm_config.sample_rate = float(response.args['sample-rate'][0])
    except:
        pass
    try:
        new_apm_config.extended_sample_rate = float(
            response.args['extended-sample-rate'][0]
        )
    except:
        pass
    try:
        new_apm_config.timespan_time_threshold = float(
            response.args['timespan_time_threshold'][0]
        )
    except:
        pass
    try:
        new_apm_config.config_version = response.args['config-version'][0]
    except:
        pass

    new_apm_config.key_pages = tuple(response.key_pages)
    new_apm_config.instrumented_funcs = response.get_instrumented_funcs()
    new_apm_config.timespan_selectors = response.get_timespan_selectors()

    # update the process-wise global apm configuration. Once this is set
    # the new HTTP requests making initialize() will get this new config
    # No need to make this thread-safe
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

    try:
        with get_agent_connection() as agent_conn:
            agent_conn.send(data)

            response_raw = agent_conn.recv()
            agent_resp = agent.BlackfireAPMResponse().from_bytes(response_raw)

            return agent_resp.args['blackfire-query'][0]
    except BlackfireAPMStatusFalseException:
        # Agent returns status=False when the endpoint is profiled and then when
        # a new APM message is sent/received config is updated.
        log.exception(e)
    except Exception as e:
        log.exception(e)


def _send_trace(req):
    try:
        with get_agent_connection() as agent_conn:
            agent_conn.send(req.to_bytes())

            response_raw = agent_conn.recv()
            agent_resp = agent.BlackfireAPMResponse().from_bytes(response_raw)

            if log.isEnabledFor(logging.DEBUG):
                log.debug(
                    "Agent APM response received. [%s]",
                    agent_resp,
                )

            if agent_resp.update_config:
                _update_apm_config(agent_resp)

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
    global _apm_config, _apm_worker

    kwargs['file-format'] = 'BlackfireApm'
    kwargs['sample-rate'] = _apm_config.sample_rate
    if _apm_config.config_version:
        kwargs['config-version'] = _apm_config.config_version
    kwargs['capabilities'] = "trace, profile"
    kwargs['os'] = platform.system()
    kwargs['host'] = platform.node()  # faster than socket.gethostbyname (Linux)
    kwargs['language'] = "python"
    kwargs['runtime'] = get_probed_runtime()
    kwargs['version'] = VERSION

    if extended:
        kwargs['load'] = get_load_avg()
        kwargs['nproc'] = get_cpu_count()
        kwargs['cost-dimensions'] = 'wt cpu mu pmu'
        kwargs['extended-sample-rate'] = _apm_config.extended_sample_rate
        kwargs['timespan_dropped'] = profiler.get_apm_timespan_dropped()
        kwargs['timespan_threshold_per_rule'
               ] = _apm_config.timespan_threshold_per_rule
        kwargs['timespan_threshold_global'
               ] = _apm_config.timespan_threshold_global

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
    _apm_worker.add_task(_send_trace, args=(apm_trace_req, ))
