import re
import os
import sys
import time
import atexit
import platform
import traceback
import logging
import base64
import random
from contextlib import contextmanager
from blackfire import profiler, VERSION, agent, generate_config, DEFAULT_CONFIG_FILE
from blackfire.utils import IS_PY3, get_home_dir, ConfigParser, \
    urlparse, urljoin, urlencode, get_load_avg, get_logger, quote, \
    parse_qsl, Request, urlopen, json_prettify, get_probed_runtime
from blackfire.exceptions import BlackfireApiException
from blackfire import BlackfireConfiguration

log = get_logger(__name__)

# globals
_config = None
_probe = None

_DEFAULT_OMIT_SYS_PATH = True
_DEFAULT_PROFILE_TITLE = 'unnamed profile'

__all__ = [
    'get_traces', 'clear_traces', 'is_enabled', 'enable', 'end', 'reset',
    'disable', 'run', 'initialize'
]


class Probe(object):

    def __init__(self, config):
        self._config = config
        self._agent_conn = None
        self._enabled = False

    def is_enabled(self):
        return self._enabled

    def get_agent_prolog_response(self):
        '''Returns the first response of the Agent in prolog dialogue'''
        assert self._agent_conn is not None

        return self._agent_conn.agent_response

    def enable(self):
        if self._enabled:
            raise BlackfireApiException('Another probe is already profiling')
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
        timespan_selectors = {'^': set(), '=': set()}
        if profile_timespan:
            ts_selectors = self._agent_conn.agent_response.args.get(
                'Blackfire-Timespan', []
            )

            for ts_sel in ts_selectors:
                if ts_sel[0] not in ['^', '=']:
                    log.warning(
                        "Ignoring invalid timespan selector '%s'.", ts_sel
                    )
                    continue

                timespan_selectors[ts_sel[0]].add(ts_sel[1:])

        # instrumented_funcs is a dict of {func_name:[list of argument IDs]}
        instrumented_funcs = {}
        if fn_args_enabled:
            # convert the fn-args string to dict for faster lookups on C side
            fn_args = self._agent_conn.agent_response.args.get(
                'Blackfire-Fn-Args', []
            )
            for fn_arg in fn_args:
                fn_name, arg_ids_s = fn_arg.split()
                fn_name = fn_name.strip()

                if fn_name in instrumented_funcs:
                    log.warning(
                        "Function '%s' is already instrumented. Ignoring fn-args directive %s.",
                        fn_name, fn_arg
                    )
                    continue

                arg_ids = []
                for arg_id in arg_ids_s.strip().split(','):
                    if arg_id.isdigit():
                        arg_ids.append(int(arg_id))
                    else:
                        arg_ids.append(arg_id)

                instrumented_funcs[fn_name] = arg_ids

        profiler.start(
            builtins=builtins,
            profile_cpu=profile_cpu,
            profile_memory=profile_memory,
            profile_timespan=profile_timespan,
            instrumented_funcs=instrumented_funcs,
            timespan_selectors=timespan_selectors,
            timespan_threshold=timespan_threshold,
        )

        # TODO: 'Blackfire-Error: 103 Samples quota is out'

        log.debug(
            "profiler started. [instrumented_funcs:%s, timespan_selectors:%s]",
            json_prettify(instrumented_funcs),
            json_prettify(timespan_selectors),
        )

    def disable(self):
        self._enabled = False
        profiler.stop()

    def clear_traces(self):
        profiler.clear_traces()

    def end(self, headers={}, omit_sys_path_dirs=_DEFAULT_OMIT_SYS_PATH):
        if not self._agent_conn:
            return

        log.debug("probe.end() called.")

        self.disable()
        traces = get_traces(omit_sys_path_dirs=omit_sys_path_dirs)
        self.clear_traces()

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
    return profiler.get_traces(omit_sys_path_dirs=omit_sys_path_dirs)


def clear_traces():
    profiler.clear_traces()


# used from testing to set Probe state to a consistent state
def reset():
    global _config, _probe

    _config = None
    _probe = None


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
        _config.challenge,
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
    log_file=None,
    log_level=None,
    config_file=DEFAULT_CONFIG_FILE,
    method="manual",
):
    global _config, log, _probe

    if log_file or log_level:
        log = get_logger(__name__, log_file=log_file, log_level=log_level)
        log.warning(
            "DeprecationWarning: 'LOG_FILE' and 'LOG_LEVEL' params are no longer used from 'probe.initialize' API. "
            "Please use 'BLACKFIRE_LOG_FILE'/'BLACKFIRE_LOG_LEVEL' environment variables."
            "These settings will be removed in the next version."
        )

    log.debug("probe.initialize called. [method:'%s']", method)

    _config = generate_config(
        query,
        client_id,
        client_token,
        agent_socket,
        agent_timeout,
        endpoint,
        log_file,
        log_level,
        config_file,
    )

    log.debug(
        "Probe Configuration initialized. [%s]",
        json_prettify(_config.__dict__)
    )

    _probe = Probe(_config)


def is_enabled():
    global _probe

    if not _probe:
        return False

    return _probe.is_enabled()


def enable(end_at_exit=False):
    global _config, _probe

    if not _config:
        raise BlackfireApiException(
            'No configuration set. initialize should be called first.'
        )

    log.debug("probe.enable() called.")
    _probe.enable()

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


def disable():
    global _probe

    if not _probe:
        return

    _probe.disable()

    log.debug("probe.disable() called.")


def end(headers={}, omit_sys_path_dirs=_DEFAULT_OMIT_SYS_PATH):
    '''
    headers: additional headers to send along with the final profile data.
    '''
    global _probe

    if not _probe:
        return

    log.debug("probe.end() called.")

    return _probe.end()


@contextmanager
def run(call_end=True):
    enable()
    try:
        yield
    finally:
        disable()
        if call_end:
            end()
