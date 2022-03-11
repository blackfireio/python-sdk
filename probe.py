import sys
import time
import atexit
import platform
import traceback
import logging
import base64
import random
from contextlib import contextmanager
from blackfire import profiler, VERSION, agent, generate_config, DEFAULT_CONFIG_FILE, \
    COST_DIMENSIONS
from blackfire.utils import IS_PY3, urlencode, get_load_avg, get_logger, json_prettify, \
    get_probed_runtime
from blackfire.exceptions import BlackfireApiException
from blackfire.constants import BlackfireConstants

log = get_logger(__name__)

# globals
_config = None
_probe = None

_DEFAULT_OMIT_SYS_PATH = True
_DEFAULT_PROFILE_TITLE = 'unnamed profile'

__all__ = [
    'get_traces', 'clear_traces', 'is_enabled', 'enable', 'end', 'reset',
    'disable', 'run', 'initialize', 'set_transaction_name'
]


class _ProbeProxy(object):
    '''
    This class implements a proxy interface for the current probe object.
    If probe does not exist, all calls are noops
    '''

    def __init__(self, probe):
        self._probe = probe

    def _docall(self, method_name, *args, **kwargs):
        if not self._probe:
            return

        fn = getattr(self._probe, method_name)
        return fn(*args, **kwargs)

    def enable(self):
        self._docall("enable")

    def disable(self):
        self._docall("disable")

    def clear_traces(self):
        self._docall("clear_traces")

    def is_enabled(self):
        r = self._docall("is_enabled")
        return r is not None

    def get_traces(self, *args, **kwargs):
        r = self._docall("get_traces", *args, **kwargs)
        if r is None:
            return ""
        return r

    def end(self, *args, **kwargs):
        return self._docall("end", *args, **kwargs)


class Probe(object):

    def __init__(self, config):
        self._config = config
        self._agent_conn = None
        self._enabled = False

        self.transaction_name = None

        log.debug('Probe version %s initialized.' % (VERSION))

    def is_enabled(self):
        return self._enabled

    def get_agent_prolog_response(self):
        '''Returns the first response of the Agent in prolog dialogue'''
        assert self._agent_conn is not None

        return self._agent_conn.agent_response

    def enable(self):
        if self._enabled:
            return

        self._enabled = True

        # connect agent
        if not self._agent_conn:
            try:
                self._agent_conn = agent.Connection(
                    self._config.agent_socket, self._config.agent_timeout
                )
                self._agent_conn.connect(config=self._config)
            except Exception as e:
                self._enabled = False
                self._agent_conn = None
                raise e

        self._req_start = time.time()

        # pass start options from _config.args, set defaults as necessary
        builtins = not bool(int(self._config.args.get('flag_no_builtins', '0')))
        profile_cpu = bool(int(self._config.args.get('flag_cpu', '0')))
        profile_memory = bool(int(self._config.args.get('flag_memory', '0')))
        fn_args_enabled = bool(int(self._config.args.get('flag_fn_args', '0')))
        profile_nw = bool(int(self._config.args.get('flag_nw', '0')))

        # only enable timespan if this is the last profile of multiple sample profiles.
        # we look at 'continue': 'false' from the agent response
        profile_timespan = False
        timespan_threshold = profiler.MAX_TIMESPAN_THRESHOLD  # not probable number
        if self._agent_conn.agent_response.status_val_dict.get(
            'first_sample'
        ) == 'true':
            profile_timespan = bool(
                int(self._config.args.get('flag_timespan', '0'))
            )
            timespan_threshold = int(
                self._config.args.get('timespan_threshold', 10)
            )

        # timespan_selectors is a dict of set of prefix/equal regex selectors.
        timespan_selectors = self._agent_conn.agent_response.get_timespan_selectors() \
                if profile_timespan else {}

        # instrumented_funcs is a dict of {func_name:[list of argument IDs]}
        instrumented_funcs = self._agent_conn.agent_response.get_instrumented_funcs() \
                if fn_args_enabled else {}

        log.debug(
            "profiler started. [instrumented_funcs:%s, timespan_selectors:%s, "
            "timespan_threshold=%d, config.args=%s]",
            json_prettify(instrumented_funcs),
            json_prettify(timespan_selectors),
            timespan_threshold,
            self._config.args,
        )

        # enable just before profiling starts to exclude Blackfire related `nw` activity
        # e.g: prologue with Agent
        from blackfire.hooks import nw
        nw.enable()

        profiler.start(
            builtins=builtins,
            profile_cpu=profile_cpu,
            profile_memory=profile_memory,
            profile_nw=profile_nw,
            profile_timespan=profile_timespan,
            instrumented_funcs=instrumented_funcs,
            timespan_selectors=timespan_selectors,
            timespan_threshold=timespan_threshold,
            probe=self,
            ctx_var=self._config.ctx_var
        )

        # TODO: 'Blackfire-Error: 103 Samples quota is out'

    def disable(self):
        if not self._enabled:
            return

        # there might be multiple start/stop. Again: we want to have `nw` hooks
        # enabled just before profiler starts
        from blackfire.hooks import nw
        nw.disable()

        self._enabled = False
        profiler.stop()

    def clear_traces(self):
        profiler.clear_traces()

    def end(self, headers={}, omit_sys_path_dirs=_DEFAULT_OMIT_SYS_PATH):
        if not self._agent_conn:
            return

        self.disable()
        traces = self.get_traces(omit_sys_path_dirs=omit_sys_path_dirs)
        self.clear_traces()

        log.debug("probe.end() called.")

        # write main prolog
        profile_title = self._config.args.get(
            'profile_title', _DEFAULT_PROFILE_TITLE
        )
        end_headers = {
            'file-format': 'BlackfireProbe',
            'Probed-Runtime': get_probed_runtime(),
            'Probed-Language': 'python',
            'Probed-Os': platform.platform(),
            'Probe-version': VERSION,
            'Probed-Features': self._config.args_raw,
            'Request-Start': self._req_start,
            'Request-End': time.time(),
            'Profile-Title': profile_title,
            'cost-dimensions': COST_DIMENSIONS,
        }
        load_avg = get_load_avg()
        if load_avg:
            end_headers['Request-Sys-Load-Avg'] = load_avg

        end_headers.update(headers)

        context_dict = {'script': sys.executable, 'argv[]': sys.argv}
        # middlewares populate the Context dict?
        if 'Context' in end_headers:
            context_dict.update(end_headers['Context'])
        end_headers['Context'] = urlencode(context_dict, doseq=True)

        # add Constants header if provisioned
        constants_dict = {}
        constants = self._agent_conn.agent_response.get_constants()
        for constant in constants:
            val = BlackfireConstants.get(constant)
            if val is not None:
                constants_dict[constant] = val

        if len(constants_dict) > 0:
            end_headers['Constants'] = urlencode(constants_dict, doseq=True)

        profile_data_req = agent.BlackfireRequest(
            headers=end_headers, data=traces
        )
        self._agent_conn.send(profile_data_req.to_bytes())
        self._agent_conn.close()
        self._agent_conn = None

        return traces

    def get_traces(self, omit_sys_path_dirs=_DEFAULT_OMIT_SYS_PATH):
        return profiler.get_traces(omit_sys_path_dirs=omit_sys_path_dirs)


def get_traces(omit_sys_path_dirs=_DEFAULT_OMIT_SYS_PATH):
    return get_current().get_traces(omit_sys_path_dirs=omit_sys_path_dirs)


def clear_traces():
    get_current().clear_traces()


# used from testing to set Probe state to a consistent state
def reset():
    global _config, _probe

    _config = None
    _probe = None
    agent._blackfire_keys = None


def add_marker(label=''):
    pass


def generate_subprofile_query():
    global _config

    if not _config:
        raise BlackfireApiException(
            'Unable to create a subprofile query as profiling is not enabled.'
        )

    args_copy = _config.args.copy()

    parent_sid = ''
    if 'sub_profile' in args_copy:
        parent_sid = args_copy['sub_profile'].split(':')[1]
    args_copy.pop('aggreg_samples')

    s = ''.join(chr(random.randint(0, 255)) for _ in range(7))
    if IS_PY3:
        s = bytes(s, agent.Protocol.ENCODING)
    sid = base64.b64encode(s)
    sid = sid.decode("ascii")
    sid = sid.rstrip('=')
    sid = sid.replace('+', 'A')
    sid = sid.replace('/', 'B')
    sid = sid[:9]
    args_copy['sub_profile'] = '%s:%s' % (parent_sid, sid)

    result = "%s&signature=%s&%s" % (
        _config.challenge_raw,
        _config.signature,
        urlencode(args_copy),
    )
    return result


def initialize(
    query=None,
    client_id=None,
    client_token=None,
    agent_socket=None,
    agent_timeout=None,
    endpoint=None,
    config_file=DEFAULT_CONFIG_FILE,
    method="manual",
    title=None,
    ctx_var=None,
):
    global _config, log, _probe

    log.debug("probe.initialize called. [method:'%s']", method)

    _config = generate_config(
        query,
        client_id,
        client_token,
        agent_socket,
        agent_timeout,
        endpoint,
        config_file,
        title,
        ctx_var,
    )

    log.debug(
        "Probe Configuration initialized. [%s]",
        json_prettify(_config.__dict__)
    )

    _probe = Probe(_config)


def is_enabled():
    return get_current().is_enabled()


def enable(end_at_exit=False):
    global _config, _probe

    if not _config:
        raise BlackfireApiException(
            'No configuration set. initialize should be called first.'
        )

    if profiler.is_session_active():
        raise BlackfireApiException('Another probe is already profiling')

    log.debug("probe.enable() called.")

    if end_at_exit:  # used for profiling CLI scripts

        # patch sys module to get the exit code/stdout/stderr output lengths
        from blackfire.hooks.sys.patch import patch
        from blackfire.hooks.sys import SysHooks

        patch()

        def _deinitialize():

            headers = {}
            headers['Response-Code'] = SysHooks.exit_code
            headers['Response-Bytes'
                    ] = SysHooks.stdout_len + SysHooks.stderr_len
            try:
                end(headers=headers)
            except:
                # we do not need to return if any error happens inside end()
                # but it would be nice to see the traceback
                log.warn(traceback.format_exc())

            logging.shutdown()

        # Note: The functions registered via this module are not called when the
        # program is killed by a signal not handled by Python, when a Python fatal
        # internal error is detected, or when os._exit() is called.
        atexit.register(_deinitialize)

    _probe.enable()


def disable():
    get_current().disable()

    log.debug("probe.disable() called.")


def end(headers={}, omit_sys_path_dirs=_DEFAULT_OMIT_SYS_PATH):
    '''
    headers: additional headers to send along with the final profile data.
    '''
    r = get_current().end()

    log.debug("probe.end() called.")

    return r


@contextmanager
def run(call_end=True):
    enable()
    try:
        yield
    finally:
        disable()
        if call_end:
            end()


def set_transaction_name(name):
    '''
    Retrieves the current probe for the current session and sets transaction_name
    property. transaction_name is the generic name for the name of the handler 
    function. E.g: In Django terms it is the view_name.
    '''
    curr_probe = profiler.get_current_probe()
    if curr_probe:
        curr_probe.transaction_name = name


def get_current():
    '''
    Retrieves the current probe for the current session (including the CLI probe)
    '''
    curr_probe = profiler.get_current_probe()
    return _ProbeProxy(curr_probe)
