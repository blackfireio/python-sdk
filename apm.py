import random
import os
import time
import logging
import platform
import re
import atexit

import _blackfire_profiler as _bfext
from threading import Thread
from blackfire.exceptions import *
from blackfire.utils import get_logger, IS_PY3, json_prettify, is_testing, \
    get_load_avg, get_cpu_count, Queue, get_probed_runtime, get_time, \
    urlencode, get_caller_frame, ContextDict, QueueFull
from blackfire import agent, DEFAULT_AGENT_SOCKET, DEFAULT_AGENT_TIMEOUT, \
 profiler, VERSION, COST_DIMENSIONS
from contextlib import contextmanager

log = get_logger(__name__)

_DEFAULT_TIMESPAN_LIMIT_PER_RULE = 100
_DEFAULT_TIMESPAN_LIMIT_GLOBAL = 200
_DEFAULT_APM_QUEUE_SIZE = 100000
_PAUSE_DURATION = 300  # secs
_paused = False
_paused_until = 0

__all__ = [
    'set_transaction_name', 'set_tag', 'ignore_transaction',
    'start_transaction', 'stop_transaction'
]


class _ApmWorker(Thread):

    def __init__(self, queue_size=_DEFAULT_APM_QUEUE_SIZE):
        Thread.__init__(self)
        self._tasks = Queue(queue_size)
        self._closed = False

        self.daemon = True
        self.started = False
        self.queue_size = queue_size

    def _ensure_worker_started(self):
        # We lazily start the thread because if we do it in import time as before,
        # a forked Process that calls add_task() can see the Thread is started
        # but it might not be started in that process at all, so we make sure
        # we start the thread in the same context from where we send the trace.
        if not self.started:
            self.start()
            self.started = True

    def _add_task_safe(self, task_tuple):
        try:
            self._tasks.put_nowait(task_tuple)
        except QueueFull:
            log.exception("add_task is ignored as Queue is full.")

    def add_task(self, fn, args=(), kwargs={}):
        if self._closed:
            return

        self._ensure_worker_started()

        if is_testing():
            fn(*args, **kwargs)
        else:
            self._add_task_safe((fn, args, kwargs))

    def run(self):
        self.started = True  # defensive
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
        self._add_task_safe((None, None, None))
        self._closed = True

    def join(self):
        # The reason of this defensive check here:
        # We start ApmWorker thread lazily in _ensure_worker_started.
        # There is a possibilty where there is Connection issue with the Agent
        # and probe pauses APM and then a join() is called. This is only an
        # example, there might be many more scenarios leading up here without a
        # started Thread.
        if not self.started:
            return
        super(_ApmWorker, self).join()


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
        self.timespan_limit_per_rule = _DEFAULT_TIMESPAN_LIMIT_PER_RULE
        self.timespan_limit_global = _DEFAULT_TIMESPAN_LIMIT_GLOBAL

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
        self.disable_config_update = bool(
            int(
                os.environ.get(
                    'BLACKFIRE_APM_DISABLE_CONFIG_UPDATE_TEST',
                    self.disable_config_update
                )
            )
        )

        self.timespan_time_threshold = int(
            os.environ.get(
                'BLACKFIRE_APM_TIMESPAN_TIME_THRESHOLD_TEST',
                self.timespan_time_threshold
            )
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

# _state is a per-context resource. An example use: it holds current executing APM transaction
_state = ContextDict('bf_apm_state')

# do not even evaluate the params if DEBUG is not set in APM path

if _apm_probe_config.apm_enabled:
    log.debug(
        "APM Configuration initialized. [%s] [%s] [%s]",
        json_prettify(_apm_config.__dict__),
        json_prettify(_apm_probe_config.__dict__),
        os.getpid(),
    )


class ApmTransaction(object):
    '''
    ApmTransaction objects can also be used as a Context Manager:

    E.g:
        with apm.start_transaction() as t:
            foo()
            t.set_name('xxx')
    '''

    def __init__(self, extended):
        self.ignored = False
        self.name = None
        self.t0 = get_time()
        self.extended = extended
        self.tags = {}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        _stop_and_queue_transaction(
            file=get_caller_frame().f_code.co_filename,
        )

    def set_tag(self, k, v):
        self.tags[k] = v

    def ignore(self):
        self.ignored = True

    def set_name(self, name):
        self.name = name

    def stop(self):
        profiler.stop()


def _set_current_transaction(transaction):
    _state.set('transaction', transaction)


def _get_current_transaction():
    return _state.get('transaction')


def pause(reason):
    global _paused, _paused_until

    _paused = True
    _paused_until = time.time() + _PAUSE_DURATION

    log.warning(
        "APM is paused for %s seconds. [reason:%s]", _PAUSE_DURATION, reason
    )


def unpause():
    global _paused, _paused_until

    _paused = False
    _paused_until = 0
    log.debug("APM unpaused.")


def is_paused():
    global _paused, _paused_until

    if _paused:
        if time.time() <= _paused_until:
            return True
        unpause()

    return False


def set_transaction_name(name):
    curr_transaction = _get_current_transaction()
    if curr_transaction:
        curr_transaction.name = name


def set_tag(key, val):
    '''
    Updates/Inserts key:val pair to the transaction.tags dict.
    '''
    curr_transaction = _get_current_transaction()
    if curr_transaction:
        curr_transaction.set_tag(key, val)


def ignore_transaction():
    curr_transaction = _get_current_transaction()
    if curr_transaction:
        curr_transaction.ignore()


def _start_transaction(extended=False, ctx_var=None):
    curr_transaction = _get_current_transaction()

    # do nothing if there is an ongoing APM transaction or a profiling session
    if curr_transaction:
        log.debug(
            "APM transaction cannot be started as another transaction is in progress."
        )
        return

    if profiler.is_session_active():
        log.debug(
            "APM transaction cannot be started as a profile is in progress."
        )
        return

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
            apm_timespan_limit_per_rule=_apm_config.timespan_limit_per_rule,
            apm_timespan_limit_global=_apm_config.timespan_limit_global,
            ctx_var=ctx_var,
        )

    new_transaction = ApmTransaction(extended)
    _set_current_transaction(new_transaction)

    log.debug("APM transaction started. (extended=%s)" % (extended))

    return new_transaction


def start_transaction():
    result = _start_transaction()

    def _wait_pending_transactions():
        _apm_worker.close()
        _apm_worker.join()

    atexit.register(_wait_pending_transactions)
    return result


def _stop_and_queue_transaction(**kwargs):
    curr_transaction = _stop_transaction()
    if curr_transaction:
        _queue_trace(curr_transaction, **kwargs)


def _stop_transaction():
    curr_transaction = _get_current_transaction()

    if curr_transaction:
        curr_transaction.stop()
        _set_current_transaction(None)

        log.debug("APM transaction stopped.")

        return curr_transaction


def stop_transaction():
    _stop_and_queue_transaction(file=get_caller_frame().f_code.co_filename)


def _get_traced_memory():
    return profiler.runtime_metrics.memory()


def reset():
    global _apm_config, _apm_probe_config

    _apm_config = ApmConfig()
    # init config for the APM for communicating with the Agent
    _apm_probe_config = ApmProbeConfig()
    profiler.runtime_metrics.reset()
    _set_current_transaction(None)


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
def _get_agent_connection():
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
        new_apm_config.timespan_time_threshold = int(
            response.args['timespan-time-threshold'][0]
        )
    except:
        pass
    try:
        new_apm_config.timespan_limit_per_rule = int(
            response.args['timespan-limit-per-rule'][0]
        )
    except:
        pass
    try:
        new_apm_config.timespan_limit_global = int(
            response.args['timespan-limit-global'][0]
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
        with _get_agent_connection() as agent_conn:
            agent_conn.send(data)

            response_raw = agent_conn.recv()
            agent_resp = agent.BlackfireAPMResponse().from_bytes(response_raw)

            return agent_resp.args['blackfire-query'][0]
    except BlackfireAPMStatusFalseException:
        # Agent returns status=False when the endpoint is profiled and then when
        # a new APM message is sent/received config is updated.
        pass
    except Exception as e:
        log.exception(e)


def _send_trace(req):
    try:
        with _get_agent_connection() as agent_conn:
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


def _queue_trace(transaction, **kwargs):
    global _apm_config, _apm_worker

    if is_paused():
        log.debug("Transaction ignored since APM is paused.")
        return

    if transaction.ignored:
        return

    now = get_time()
    mu, pmu = _get_traced_memory()

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
    kwargs['wt'] = now - transaction.t0  # usec
    kwargs['mu'] = mu
    kwargs['pmu'] = pmu
    kwargs['timestamp'] = now / 1000000  # sec
    if len(transaction.tags):
        kwargs['tags'] = urlencode(transaction.tags)

    if transaction.extended:
        kwargs['load'] = get_load_avg()
        kwargs['nproc'] = get_cpu_count()
        kwargs['cost-dimensions'] = COST_DIMENSIONS
        kwargs['extended-sample-rate'] = _apm_config.extended_sample_rate
        kwargs['timespan_dropped'] = profiler.get_apm_timespan_dropped()
        kwargs['timespan_limit_per_rule'] = _apm_config.timespan_limit_per_rule
        kwargs['timespan_limit_global'] = _apm_config.timespan_limit_global

    # if no controller-name provided use transaction.name
    if 'controller_name' not in kwargs:
        kwargs['controller-name'] = transaction.name

    headers = {}
    for k, v in kwargs.items():
        if v is not None:
            # convert `_` to `-` in keys. e.g: controller_name -> controller-name
            k = k.replace('_', '-')
            headers[k] = v

    extended_traces = profiler.get_traces(
        extended=True
    ) if transaction.extended else None
    profiler.clear_traces()  # we can clear the traces

    apm_trace_req = agent.BlackfireAPMRequest(
        headers=headers, data=str(extended_traces).strip()
    )

    # We should not have a blocking call in APM path. Do agent connection setup
    # socket send in a separate thread.
    _apm_worker.add_task(_send_trace, args=(apm_trace_req, ))
