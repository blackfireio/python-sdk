import re
import os
import sys
import time
import atexit
import socket
import platform
import traceback
import base64
import logging
import json
from contextlib import contextmanager
from collections import defaultdict
from blackfire import profiler, VERSION
from blackfire.utils import SysHooks, IS_PY3, get_home_dir, ConfigParser, \
    urlparse, urljoin, urlencode, get_load_avg, get_logger, init_logger, quote, \
    parse_qsl
from blackfire.exceptions import *
from blackfire import BlackfireConfiguration


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

_AGENT_PROTOCOL_MAX_RECV_SIZE = 4096
_AGENT_PROTOCOL_MAX_SEND_SIZE = 4096
_DEFAULT_OMIT_SYS_PATH = True
_AGENT_PROTOCOL_ENCODING = 'utf-8'
_DEFAULT_ENDPOINT = 'https://blackfire.io/'
_DEFAULT_CONFIG_FILE = os.path.join(get_home_dir(), '.blackfire.ini')
_API_TIMEOUT = 5.0
_DEFAULT_PROFILE_TITLE = 'unnamed profile'
_DEFAULT_LOG_LEVEL = 1
_DEFAULT_LOG_FILE = 'python-probe.log'
_DEFAULT_AGENT_TIMEOUT = 0.25
_DEFAULT_AGENT_SOCKET = _get_default_agent_socket()

_AGENT_PROTOCOL_MARKER = '\n\n'
if IS_PY3:
    _AGENT_PROTOCOL_MARKER = bytes(
        _AGENT_PROTOCOL_MARKER, _AGENT_PROTOCOL_ENCODING
    )

__all__ = [
    'BlackfireRequest', 'BlackfireResponse', 'get_traces', 'clear_traces',
    'is_enabled', 'enable', 'end', 'reset', 'disable', 'run', 'initialize'
]


def _get_probed_runtime():
    return "%s %s+%s" % (
        platform.python_implementation(), platform.python_version(),
        platform.platform()
    )


def _get_signing_response(signing_endpoint, client_id, client_token):
    if IS_PY3:
        import urllib.request as urllib
    else:
        import urllib2 as urllib

    request = urllib.Request(signing_endpoint)
    auth_hdr = '%s:%s' % (client_id, client_token)
    if IS_PY3:
        auth_hdr = bytes(auth_hdr, 'ascii')
    base64string = base64.b64encode(auth_hdr)
    if IS_PY3:
        base64string = base64string.decode("ascii")
    request.add_header("Authorization", "Basic %s" % base64string)
    result = urllib.urlopen(request, timeout=_API_TIMEOUT)
    if not (200 <= result.code < 400):
        raise BlackfireApiException(
            'Signing request failed for manual profiling. [%s]' % (result.code)
        )

    return json.loads(result.read())


class _AgentConnection(object):

    def __init__(self, config):

        self.config = config
        self._closed = False
        self.agent_response = None

        # parse & init sock params
        sock_parsed = urlparse(self.config.agent_socket)
        if sock_parsed.scheme == "unix":
            family = socket.AF_UNIX
            self._sock_addr = sock_parsed.path
        elif sock_parsed.scheme == "tcp":
            # TODO: Old probe used AF_UNSPEC here to support IPv6?
            family = socket.AF_INET
            host, port = sock_parsed.netloc.split(':')
            self._sock_addr = (
                host,
                int(port),
            )
        else:
            raise BlackfireApiException(
                "Unsupported socket type. [%s]" % (sock_parsed.scheme)
            )

        # init the real socket
        self._socket = socket.socket(family, socket.SOCK_STREAM)
        self._socket.settimeout(self.config.agent_timeout)

        # it is advised to disable NAGLE algorithm
        try:
            self._socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception as e:
            get_logger().warning(
                "Error happened while disabling NODELAY option. [%s]" % (e)
            )

    def __del__(self):
        try:
            self.close()
        except:
            pass

    def connect(self):
        get_logger().debug("Connecting to agent at %s." % str(self._sock_addr))
        try:
            self._socket.connect(self._sock_addr)
        except Exception as e:
            raise BlackfireApiException(
                'Agent connection failed.[%s][%s]' %
                (e, self.config.agent_socket)
            )

        self._write_prolog()

    def close(self):
        if self._closed:
            return

        self._socket.close()
        self._closed = True

        get_logger().debug("Agent connection closed.")

    def send(self, data):
        # Agent expects data is written in chunks
        try:
            while (data):
                self._socket.sendall(data[:_AGENT_PROTOCOL_MAX_SEND_SIZE])
                data = data[_AGENT_PROTOCOL_MAX_SEND_SIZE:]
        except Exception as e:
            raise BlackfireApiException(
                'Agent send data failed.[%s][%s]' % (e, data)
            )

    def recv(self):
        global _AGENT_PROTOCOL_MARKER

        result = ''
        if IS_PY3:
            result = bytes(result, _AGENT_PROTOCOL_ENCODING)

        try:
            while (True):
                result += self._socket.recv(_AGENT_PROTOCOL_MAX_RECV_SIZE)
                if not len(result):
                    # other side indicated no more data will be sent
                    raise Exception('Agent closed the connection.')

                if result.endswith(_AGENT_PROTOCOL_MARKER):
                    break

        except Exception as e:
            raise BlackfireApiException('Agent recv data failed.[%s]' % (e))

        return result

    def _write_prolog(self):
        headers = {
            #'Blackfire-Auth':
            #'%s:%s' % (self.config.env_id, self.config.env_token),
            'Blackfire-Query':
            '%s&signature=%s&aggreg_samples=%s' % (
                self.config.challenge,
                self.config.signature,
                self.config.args['aggreg_samples'],
            ),
            'Blackfire-Probe':
            'python-%s' % (sys.hexversion),
        }

        hello_req = BlackfireRequest(headers=headers)
        self.send(hello_req.to_bytes())

        response_raw = self.recv()
        self.agent_response = BlackfireResponse().from_bytes(response_raw)
        if self.agent_response.status_code != BlackfireResponse.StatusCode.OK:
            raise BlackfireApiException(
                'Invalid response received from Agent. [%s]' %
                (self.agent_response)
            )

        get_logger().debug(
            "Response received from Agent. (response='%s')" %
            (self.agent_response)
        )

        # TODO: response.args holds some features that might need to be implemented
        # blackfire-yaml, composer-lock(probably not needed), firstsample


class BlackfireMessage(object):

    def to_bytes(self):
        pass

    def save(self, path):
        with open(path, "wb") as f:
            f.write(self.to_bytes())


class BlackfireRequest(BlackfireMessage):

    __slots__ = 'headers', 'data'

    def __init__(self, headers={}, data=None):
        self.headers = headers
        self.data = data

    def to_bytes(self):
        result = ''
        for k, v in self.headers.items():
            result += '%s: %s\n' % (k, v)
        if len(self.headers):
            result += '\n'  # add header marker
        if self.data:
            result += str(self.data)

        if IS_PY3:
            result = bytes(result, _AGENT_PROTOCOL_ENCODING)
        return result

    def from_bytes(self, data):
        data = data.decode(_AGENT_PROTOCOL_ENCODING)
        dsp = data.split(
            _AGENT_PROTOCOL_MARKER.decode(_AGENT_PROTOCOL_ENCODING)
        )
        header_lines = []
        if len(dsp) == 3:
            header_lines = dsp[0]
            self.data = dsp[1] + '\n' + dsp[2]  # timespan + trace?
        elif len(dsp) == 2:
            header_lines, self.data = dsp
        elif len(dsp) == 1:
            header_lines = dsp[0]
        else:
            raise BlackfireApiException(
                'Invalid BlackfireRequest message. [%s]' % (data)
            )

        header_lines = header_lines.split('\n')
        for line in header_lines:
            spos = line.find(':')
            if spos > -1:
                self.headers[line[:spos].strip()] = line[spos + 1:].strip()
        return self

    def pretty_print(self):
        import json
        container_dict = {"headers": self.headers, "data": self.data}
        print(json.dumps(container_dict, indent=4))


class BlackfireResponse(BlackfireMessage):

    # TODO: Do this later
    #__slots__ = 'status_code', 'raw_data', 'err_reason', 'args', 'args_raw'

    class StatusCode:
        OK = 0
        ERR = 1

    def __init__(self):
        self.status_code = BlackfireResponse.StatusCode.OK
        self.status_val = None
        self.raw_data = None
        self.args = defaultdict(list)

    def from_bytes(self, data):
        if IS_PY3:
            data = data.decode(_AGENT_PROTOCOL_ENCODING)
        self.status_code = BlackfireResponse.StatusCode.OK
        self.raw_data = data.strip()

        lines = self.raw_data.split('\n')

        # first line is the status line
        resp_type, resp_val = lines[0].split(':')
        resp_type = resp_type.strip()
        self.status_val = resp_val.strip()
        self.status_val_dict = dict(parse_qsl(self.status_val))
        if resp_type == 'Blackfire-Error':
            self.status_code = BlackfireResponse.StatusCode.ERR

        for line in lines[1:]:
            resp_key, resp_val = line.split(':')
            resp_key = resp_key.strip()
            resp_val = resp_val.strip()

            # there are arguments which occur multiple times with different
            # values (e.g: fn-args)
            self.args[resp_key].append(resp_val)

        return self

    def to_bytes(self):
        result = ''

        # add the status line
        if self.status_code == BlackfireResponse.StatusCode.ERR:
            result += 'Blackfire-Error: '
        elif self.status_code == BlackfireResponse.StatusCode.OK:
            result += 'Blackfire-Response: '
        result += self.status_val

        # add .args
        if len(self.args) > 0:
            result += '\n'
        for arg_key, arg_values in self.args.items():
            for arg_val in arg_values:
                result += '%s: %s\n' % (arg_key, arg_val)

        if IS_PY3:
            result = bytes(result, _AGENT_PROTOCOL_ENCODING)
        return result

    def __repr__(self):
        return "status_code=%s, args=%s, status_val=%s" % (
            self.status_code, self.args, self.status_val
        )


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
):
    global _config

    agent_socket = agent_socket or os.environ.get(
        'BLACKFIRE_AGENT_SOCKET', _DEFAULT_AGENT_SOCKET
    )
    agent_timeout = agent_timeout or os.environ.get(
        'BLACKFIRE_AGENT_TIMEOUT', _DEFAULT_AGENT_TIMEOUT
    )
    endpoint = endpoint or os.environ.get(
        'BLACKFIRE_ENDPOINT', _DEFAULT_ENDPOINT
    )
    log_file = log_file or os.environ.get(
        'BLACKFIRE_LOG_FILE', _DEFAULT_LOG_FILE
    )
    log_level = log_level or os.environ.get(
        'BLACKFIRE_LOG_LEVEL', _DEFAULT_LOG_LEVEL
    )
    log_level = int(log_level)  # make sure it is int

    init_logger(log_file=log_file, log_level=log_level)

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

    get_logger().debug("Configuration initialized. [%s]" % (_config))


def is_enabled():
    return profiler.is_running()


def enable(end_at_exit=False):
    global _agent_conn, _req_start, _config

    if not _config:
        raise BlackfireApiException(
            'no configuration set. initialize should be called first.'
        )

    if is_enabled():
        raise BlackfireApiException('An other probe is already profiling')

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
                get_logger().warn(traceback.format_exc())

        # Note: The functions registered via this module are not called when the
        # program is killed by a signal not handled by Python, when a Python fatal
        # internal error is detected, or when os._exit() is called.
        atexit.register(_deinitialize)

    if not _agent_conn:
        try:
            _agent_conn = _AgentConnection(_config)
            _agent_conn.connect()
        except Exception as e:
            _agent_conn = None
            raise e  # re-raise

    # pass start options from _config.args, set defaults as necessary
    builtins = not bool(int(_config.args.get('flag_no_builtins', '0')))
    profile_cpu = bool(int(_config.args.get('flag_cpu', '1')))
    profile_memory = bool(int(_config.args.get('flag_memory', '1')))
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
                get_logger().warning(
                    "Ignoring invalid timespan selector '%s'." % (ts_sel),
                    RuntimeWarning
                )
                continue

            timespan_selectors[ts_sel[0]].add(ts_sel[1:])

    # instrumented_funcs is a dict of {func_name:[list of argument IDs]}
    instrumented_funcs = {}
    if fn_args_enabled:
        # convert the fn-args string to dict for faster lookups on C side
        fn_args = _agent_conn.agent_response.args.get('Blackfire-Fn-Args', [])
        for fn_arg in fn_args:
            fn_name, arg_ids = fn_arg.split()
            fn_name = fn_name.strip()
            arg_ids = [int(arg_id) for arg_id in arg_ids.strip().split(',')]

            if fn_name in instrumented_funcs:
                get_logger().warning(
                    "Function '%s' is already instrumented. Ignoring fn-args directive %s."
                    % (fn_name, fn_arg), RuntimeWarning
                )
                continue

            instrumented_funcs[fn_name] = arg_ids

    # no memory profiling in first release
    profile_memory = False

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


def disable():
    global _enabled
    profiler.stop()

    _enabled = False


def end(headers={}, omit_sys_path_dirs=_DEFAULT_OMIT_SYS_PATH):
    '''
    headers: additional headers to send along with the final profile data.
    '''
    global _config, _req_start, _agent_conn

    if not _agent_conn:
        return

    get_logger().debug("Profile session ended.")

    disable()
    traces = get_traces(omit_sys_path_dirs=omit_sys_path_dirs)
    clear_traces()

    # write main prolog
    profile_title = _config.args.get('profile_title', _DEFAULT_PROFILE_TITLE)
    end_headers = {
        'file-format': 'BlackfireProbe',
        'Probed-Runtime': _get_probed_runtime(),
        'Probed-Language': 'python',
        'Probed-Os': platform.platform(),
        'Probe-version': VERSION,
        'Request-Sys-Load-Avg': get_load_avg(),
        'Probed-Features': _config.args_raw,
        'Request-Start': _req_start,
        'Request-End': time.time(),
        'Profile-Title': profile_title,
    }
    end_headers.update(headers)

    context_dict = {'script': sys.executable, 'argv[]': sys.argv}
    # middlewares populate the Context dict?
    if 'Context' in end_headers:
        context_dict.update(end_headers['Context'])
    end_headers['Context'] = urlencode(context_dict, doseq=True)

    profile_data_req = BlackfireRequest(headers=end_headers, data=traces)
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
