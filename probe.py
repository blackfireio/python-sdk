import re
import os
import sys
import time
import atexit
import platform
import traceback
import base64
import logging
import json
import random
from contextlib import contextmanager
from blackfire import profiler, VERSION, agent
from blackfire.utils import SysHooks, IS_PY3, get_home_dir, ConfigParser, \
    urlparse, urljoin, urlencode, get_load_avg, get_logger, quote, \
    parse_qsl, Request, urlopen, json_prettify, get_probed_runtime
from blackfire.exceptions import *
from blackfire import BlackfireConfiguration

log = get_logger(__name__)


def _get_default_agent_socket():
    plat = platform.system()
    if plat == 'Windows':
        return 'tcp://127.0.0.1:8307'
    elif plat == 'Darwin':
        return 'unix:///usr/local/var/run/blackfire-agent.sock'
    else:
        return 'unix:///var/run/blackfire/agent.sock'


# globals
_config = None
_enabled = False
_agent_conn = None
_req_start = None

_DEFAULT_OMIT_SYS_PATH = True
_DEFAULT_ENDPOINT = 'https://blackfire.io/'
_DEFAULT_CONFIG_FILE = os.path.join(get_home_dir(), '.blackfire.ini')
_API_TIMEOUT = 5.0
_DEFAULT_PROFILE_TITLE = 'unnamed profile'
_DEFAULT_AGENT_TIMEOUT = 0.25
_DEFAULT_AGENT_SOCKET = _get_default_agent_socket()

__all__ = [
    'get_traces', 'clear_traces', 'is_enabled', 'enable', 'end', 'reset',
    'disable', 'run', 'initialize'
]


def _get_signing_response(
    signing_endpoint, client_id, client_token, urlopen=urlopen
):
    request = Request(signing_endpoint)
    auth_hdr = '%s:%s' % (client_id, client_token)
    if IS_PY3:
        auth_hdr = bytes(auth_hdr, 'ascii')
    base64string = base64.b64encode(auth_hdr)
    if IS_PY3:
        base64string = base64string.decode("ascii")
    request.add_header("Authorization", "Basic %s" % base64string)
    result = urlopen(request, timeout=_API_TIMEOUT)
    if not (200 <= result.code < 400):
        raise BlackfireApiException(
            'Signing request failed for manual profiling. [%s]' % (result.code)
        )
    result = result.read()
    # python 3.5 does not accept bytes for json loads so always convert
    # response to string
    if isinstance(result, bytes):
        result = result.decode("ascii")
    return json.loads(result)


def get_traces(omit_sys_path_dirs=_DEFAULT_OMIT_SYS_PATH):
    return profiler.get_traces(omit_sys_path_dirs=omit_sys_path_dirs)


def clear_traces():
    profiler.clear_traces()


def reset():
    global _config, _enabled, _agent_conn, _req_start

    _config = None
    _enabled = False
    _agent_conn = None
    _req_start = None


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
    config_file=_DEFAULT_CONFIG_FILE,
    _method="manual",
):
    global _config, log

    if log_file or log_level:
        log = get_logger(__name__, log_file=log_file, log_level=log_level)
        log.warning(
            "DeprecationWarning: 'LOG_FILE' and 'LOG_LEVEL' params are no longer used from 'probe.initialize' API. "
            "Please use 'BLACKFIRE_LOG_FILE'/'BLACKFIRE_LOG_LEVEL' environment variables."
            "These settings will be removed in the next version."
        )

    agent_socket = agent_socket or os.environ.get(
        'BLACKFIRE_AGENT_SOCKET', _DEFAULT_AGENT_SOCKET
    )
    agent_timeout = agent_timeout or os.environ.get(
        'BLACKFIRE_AGENT_TIMEOUT', _DEFAULT_AGENT_TIMEOUT
    )
    endpoint = endpoint or os.environ.get(
        'BLACKFIRE_ENDPOINT', _DEFAULT_ENDPOINT
    )
    agent_timeout = float(agent_timeout)

    log.debug("probe.initialize called. [method:'%s']", _method)

    # manual profiling?
    if query is None:

        c_client_id = c_client_token = None

        # read config params from config file
        if os.path.exists(config_file):
            config = ConfigParser()
            config.read(config_file)
            if 'blackfire' in config.sections():
                bf_section = dict(config.items('blackfire'))

                c_client_id = bf_section.get('client-id', '').strip()
                c_client_token = bf_section.get('client-token', '').strip()

        # read config params from Env. vars, these have precedence
        c_client_id = os.environ.get('BLACKFIRE_CLIENT_ID', c_client_id)
        c_client_token = os.environ.get(
            'BLACKFIRE_CLIENT_TOKEN', c_client_token
        )

        # now read from the params, these have more precedence, if everything fails
        # use default ones wherever appropriate
        client_id = client_id or c_client_id
        client_token = client_token or c_client_token

        # if we still not have client_id or token by here
        if (not client_id or not client_token):
            raise BlackfireApiException(
                'No client id/token pair or query is provided '
                'to initialize the probe.'
            )

        signing_endpoint = urljoin(endpoint, 'api/v1/signing')

        # make a /signing request to server
        resp_dict = _get_signing_response(
            signing_endpoint, client_id, client_token
        )

        # tweak some options for manual profiling
        resp_dict['options']['aggreg_samples'] = 1

        # generate the query string from the signing req.
        query = resp_dict['query_string'] + '&' + urlencode(
            resp_dict['options']
        )

    _config = BlackfireConfiguration(
        query,
        agent_socket=agent_socket,
        agent_timeout=agent_timeout,
        client_id=client_id,
        client_token=client_token,
        endpoint=endpoint,
        log_file=log_file,
        log_level=log_level,
    )

    log.debug(
        "Configuration initialized. [%s]", json_prettify(_config.__dict__)
    )


def is_enabled():
    return profiler.is_running()


def enable(end_at_exit=False):
    global _agent_conn, _req_start, _config

    if not _config:
        raise BlackfireApiException(
            'no configuration set. initialize should be called first.'
        )

    if is_enabled():
        raise BlackfireApiException('Another probe is already profiling')

    log.debug("probe.enable() called.")

    _req_start = time.time()

    if end_at_exit:  # used for profiling CLI scripts
        # install a exitcode hook to get the exit code by hooking into sys.exit
        # and sys.excepthook, this is not called if application killed by a signal
        sys_hooks = SysHooks()
        sys_hooks.register()

        def _deinitialize():

            sys_hooks.unregister()

            headers = {}
            headers['Response-Code'] = sys_hooks.exit_code
            headers['Response-Bytes'
                    ] = sys_hooks.stdout_len + sys_hooks.stderr_len
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

    if not _agent_conn:
        try:
            _agent_conn = agent.Connection(_config)
            _agent_conn.connect()
        except Exception as e:
            _agent_conn = None
            raise e  # re-raise

    # pass start options from _config.args, set defaults as necessary
    builtins = not bool(int(_config.args.get('flag_no_builtins', '0')))
    profile_cpu = bool(int(_config.args.get('flag_cpu', '0')))
    profile_memory = bool(int(_config.args.get('flag_memory', '0')))
    fn_args_enabled = bool(int(_config.args.get('flag_fn_args', '0')))

    # only enable timespan if this is the last profile of multiple sample profiles.
    # we look at 'continue': 'false' from the agent response
    profile_timespan = False
    timespan_threshold = profiler.MAX_TIMESPAN_THRESHOLD  # not probable number
    if _agent_conn.agent_response.status_val_dict.get('first_sample') == 'true':
        profile_timespan = bool(int(_config.args.get('flag_timespan', '0')))
        timespan_threshold = int(_config.args.get('timespan_threshold', 10))

    # timespan_selectors is a dict of set of prefix/equal regex selectors.
    timespan_selectors = {'^': set(), '=': set()}
    if profile_timespan:
        ts_selectors = _agent_conn.agent_response.args.get(
            'Blackfire-Timespan', []
        )

        for ts_sel in ts_selectors:
            if ts_sel[0] not in ['^', '=']:
                log.warning("Ignoring invalid timespan selector '%s'.", ts_sel)
                continue

            timespan_selectors[ts_sel[0]].add(ts_sel[1:])

    # instrumented_funcs is a dict of {func_name:[list of argument IDs]}
    instrumented_funcs = {}
    if fn_args_enabled:
        # convert the fn-args string to dict for faster lookups on C side
        fn_args = _agent_conn.agent_response.args.get('Blackfire-Fn-Args', [])
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

    _enabled = True

    log.debug(
        "profiler started. [instrumented_funcs:%s, timespan_selectors:%s]",
        json_prettify(instrumented_funcs),
        json_prettify(timespan_selectors),
    )


def disable():
    global _enabled
    profiler.stop()

    _enabled = False

    log.debug("probe.disable() called.")


def end(headers={}, omit_sys_path_dirs=_DEFAULT_OMIT_SYS_PATH):
    '''
    headers: additional headers to send along with the final profile data.
    '''
    global _config, _req_start, _agent_conn

    if not _agent_conn:
        return

    log.debug("probe.end() called.")

    disable()
    traces = get_traces(omit_sys_path_dirs=omit_sys_path_dirs)
    clear_traces()

    # write main prolog
    profile_title = _config.args.get('profile_title', _DEFAULT_PROFILE_TITLE)
    end_headers = {
        'file-format': 'BlackfireProbe',
        'Probed-Runtime': get_probed_runtime(),
        'Probed-Language': 'python',
        'Probed-Os': platform.platform(),
        'Probe-version': VERSION,
        'Probed-Features': _config.args_raw,
        'Request-Start': _req_start,
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

    profile_data_req = agent.BlackfireRequest(headers=end_headers, data=traces)
    _agent_conn.send(profile_data_req.to_bytes())

    _agent_conn.close()
    _agent_conn = None

    return traces


@contextmanager
def run(call_end=True):
    enable()
    try:
        yield
    finally:
        disable()
        if call_end:
            end()
