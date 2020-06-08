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
import random
from contextlib import contextmanager
from collections import defaultdict
from blackfire import profiler, VERSION
from blackfire.utils import SysHooks, IS_PY3, get_home_dir, ConfigParser, \
    urlparse, urljoin, urlencode, get_load_avg, get_logger, quote, \
    parse_qsl, Request, urlopen
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

_AGENT_PROTOCOL_MAX_RECV_SIZE = 4096
_AGENT_PROTOCOL_MAX_SEND_SIZE = 4096
_DEFAULT_OMIT_SYS_PATH = True
_AGENT_PROTOCOL_ENCODING = 'utf-8'
_DEFAULT_ENDPOINT = 'https://blackfire.io/'
_DEFAULT_CONFIG_FILE = os.path.join(get_home_dir(), '.blackfire.ini')
_API_TIMEOUT = 5.0
_DEFAULT_PROFILE_TITLE = 'unnamed profile'
_DEFAULT_AGENT_TIMEOUT = 0.25
_DEFAULT_AGENT_SOCKET = _get_default_agent_socket()

_AGENT_HEADER_MARKER = '\n'
_AGENT_PROTOCOL_MARKER = '\n\n'
if IS_PY3:
    _AGENT_PROTOCOL_MARKER = bytes(
        _AGENT_PROTOCOL_MARKER, _AGENT_PROTOCOL_ENCODING
    )
    _AGENT_HEADER_MARKER = bytes(_AGENT_HEADER_MARKER, _AGENT_PROTOCOL_ENCODING)

__all__ = [
    'BlackfireRequest', 'BlackfireResponse', 'get_traces', 'clear_traces',
    'is_enabled', 'enable', 'end', 'reset', 'disable', 'run', 'initialize'
]


def _get_probed_runtime():
    return "%s %s+%s" % (
        platform.python_implementation(), platform.python_version(),
        platform.platform()
    )


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
            log.warning(
                "Error happened while disabling NODELAY option. [%s]", e
            )

    def __del__(self):
        try:
            self.close()
        except:
            pass

    def connect(self):
        log.debug("Connecting to agent at %s." % str(self._sock_addr))
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

        log.debug("Agent connection closed.")

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

    def recv(self, header_only=False):
        global _AGENT_PROTOCOL_MARKER

        result = ''
        if IS_PY3:
            result = bytes(result, _AGENT_PROTOCOL_ENCODING)

        try:
            while (True):
                data = self._socket.recv(_AGENT_PROTOCOL_MAX_RECV_SIZE)
                if not len(data):
                    # other side indicated no more data will be sent
                    raise Exception('Agent closed the connection.')
                result += data

                if header_only and result.endswith(_AGENT_HEADER_MARKER):
                    break

                if result.endswith(_AGENT_PROTOCOL_MARKER):
                    break

        except Exception as e:
            raise BlackfireApiException('Agent recv data failed.[%s]' % (e))

        return result

    def _write_prolog(self):
        blackfire_yml = bool(int(_config.args.get('flag_yml', '1')))
        blackfire_yml_contents = None
        if blackfire_yml:
            bf_yaml_files = [".blackfire.yaml", ".blackfire.yml"]
            for fpath in bf_yaml_files:
                if os.path.exists(fpath):
                    with open(fpath, "r") as f:
                        blackfire_yml_contents = f.read()
                        break

        bf_probe_header = 'python-%s' % (sys.hexversion)

        # recv timespan entries if timespan enabled
        recv_timespan = bool(int(_config.args.get('flag_timespan', '0')))
        if recv_timespan:
            bf_probe_header += ', timespan'

        # it is an expected situation to not have the bf_yaml file in place
        # even it is defined as a flag
        if blackfire_yml_contents:
            bf_probe_header += ', blackfire_yml'

        headers = {
            'Blackfire-Query':
            '%s&signature=%s&%s' % (
                self.config.challenge,
                self.config.signature,
                self.config.args_raw,
            ),
            'Blackfire-Probe':
            bf_probe_header,
        }

        # add Blackfire-Auth header if server_id/server_token are defined as
        # env. vars
        bf_server_id = os.environ.get('BLACKFIRE_SERVER_ID')
        bf_server_token = os.environ.get('BLACKFIRE_SERVER_TOKEN')
        if bf_server_id and bf_server_token:
            headers['Blackfire-Auth'
                    ] = '%s:%s' % (bf_server_id, bf_server_token)

        hello_req = BlackfireRequest(headers=headers)
        self.send(hello_req.to_bytes())

        log.debug("SEND hello_req ('%s')", hello_req.to_bytes())

        response_raw = self.recv(header_only=bool(blackfire_yml_contents))
        self.agent_response = BlackfireResponse().from_bytes(response_raw)
        if self.agent_response.status_code != BlackfireResponse.StatusCode.OK:
            raise BlackfireApiException(
                'Invalid response received from Agent. [%s]' %
                (self.agent_response)
            )

        log.debug("RECV hello_req response. ('%s')", self.agent_response)

        if self.agent_response.status_val_dict.get('blackfire_yml') == 'true':
            blackfire_yml_req = BlackfireRequest(
                headers={'Blackfire-Yaml-Size': len(blackfire_yml_contents)},
                data=blackfire_yml_contents,
            )
            self.send(blackfire_yml_req.to_bytes())

            log.debug(
                "SEND blackfire_yml_req ('%s')", blackfire_yml_req.to_bytes()
            )

            # as we send blackfire_yml back, the first agent_response should include
            # some extra params that might be changed with blackfire_yml file.
            # e.x: fn-args, timespan entries, metric defs.
            response_raw = self.recv()
            blackfire_yml_response = BlackfireResponse(
            ).from_bytes(response_raw)
            if blackfire_yml_response.status_code != BlackfireResponse.StatusCode.OK:
                raise BlackfireApiException(
                    'Invalid response received from Agent to blackfire_yml request. [%s]'
                    % (blackfire_yml_response)
                )

            # TODO: Can there be more data to merge other than args?
            self.agent_response.args.update(blackfire_yml_response.args)

            log.debug(
                "RECV blackfire_yml_req response. ('%s')",
                blackfire_yml_response.to_bytes()
            )


class BlackfireMessage(object):

    def to_bytes(self):
        pass

    def save(self, path):
        with open(path, "wb") as f:
            f.write(self.to_bytes())


class BlackfireRequest(BlackfireMessage):

    __slots__ = 'headers', 'data'

    def __init__(self, headers=None, data=None):
        if not headers:
            headers = {}
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
        s = bytes(s, _AGENT_PROTOCOL_ENCODING)
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


def log_me(msg):
    log.debug(msg)


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

    log.debug("Configuration initialized. [%s]", _config)


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
            _agent_conn = _AgentConnection(_config)
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
        instrumented_funcs, timespan_selectors
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
        'Probed-Runtime': _get_probed_runtime(),
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
