import socket
import os
import sys
import json
from blackfire.exceptions import *
import _blackfire_profiler as _bfext
from collections import defaultdict
from blackfire.utils import urlparse, get_logger, IS_PY3, parse_qsl, read_blackfireyml_content, \
    replace_bad_chars, get_time, unquote, UC, unicode_or_bytes

log = get_logger(__name__)
_blackfire_keys = None


def pause_apm(reason):
    from blackfire import apm
    apm.pause(reason=reason)


class Protocol(object):
    MAX_RECV_SIZE = 4096
    MAX_SEND_SIZE = 4096
    ENCODING = 'utf-8'

    HEADER_MARKER = '\n'
    MARKER = '\n\n'

    if IS_PY3:
        HEADER_MARKER = bytes(HEADER_MARKER, ENCODING)
        MARKER = bytes(MARKER, ENCODING)


class Connection(object):

    def __init__(self, agent_socket, agent_timeout):
        self.agent_socket = agent_socket
        self.agent_timeout = agent_timeout
        self._closed = False
        self.agent_response = None

        # parse & init sock params
        sock_parsed = urlparse(self.agent_socket)
        if sock_parsed.scheme == "unix":
            family = socket.AF_UNIX
            self._sock_addr = sock_parsed.path
        elif sock_parsed.scheme == "tcp":
            family = socket.AF_INET
            # there are some URLs like: tcp://[::]:10666 which might contain
            # `:` in the host section. That is why we use rsplit(...) below
            host, port = sock_parsed.netloc.rsplit(':', 1)

            # is this a IPv6 address?
            if host.startswith('['):
                host = host[1:-1]
                family = socket.AF_INET6

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
        self._socket.settimeout(self.agent_timeout)

        # it is advised to disable NAGLE algorithm
        try:
            self._socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except:
            pass

    def __del__(self):
        try:
            self.close()
        except:
            pass

    def _contains_blackfireyaml_header(self, recv_wnd):
        BFYAML_HDR = 'blackfire_yml=true'
        if IS_PY3:
            BFYAML_HDR = bytes(BFYAML_HDR, Protocol.ENCODING)
        return BFYAML_HDR in recv_wnd

    def connect(self, config=None):
        # check if signature is valid even before connecting to the Agent
        if config and _blackfire_keys and not _blackfire_keys.is_expired():
            sig = replace_bad_chars(unquote(config.signature))
            msg = config.challenge_raw
            signature_verified = False
            for key in _blackfire_keys:
                signature_verified = _bfext._verify_signature(key, sig, msg)
                log.debug("_verify_signature(key=%s, sig=%s, msg=%s) returned %s." % \
                    (key, sig, msg, signature_verified))
                if signature_verified:
                    break
            if not signature_verified:
                raise BlackfireInvalidSignatureError(
                    'Invalid signature received. (%s)' % (sig)
                )
            log.debug('Signature verified.')

        log.debug("Connecting to agent at %s." % str(self._sock_addr))
        try:
            self._socket.connect(self._sock_addr)
        except Exception as e:
            pause_apm(reason=e)
            raise BlackfireApiException(
                'Agent connection failed.[%s][%s]' % (e, self.agent_socket)
            )

        # if no config provided, it is APM case
        if config:
            self._write_prolog(config)

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
                self._socket.sendall(data[:Protocol.MAX_SEND_SIZE])
                data = data[Protocol.MAX_SEND_SIZE:]
        except Exception as e:
            pause_apm(reason=e)
            raise BlackfireApiException(
                'Agent send data failed.[%s][%s]' % (e, data)
            )

    def recv(self):
        result = ''
        if IS_PY3:
            result = bytes(result, Protocol.ENCODING)

        try:
            while (True):
                data = self._socket.recv(Protocol.MAX_RECV_SIZE)
                if not len(data):
                    # other side indicated no more data will be sent
                    raise Exception('Agent closed the connection.')
                result += data

                # when blackfire_yaml header is present in the recv_window
                # do not try to read until Protocol.MARKER found. This will
                # be a header only msg
                if self._contains_blackfireyaml_header(result) and \
                    result.endswith(Protocol.HEADER_MARKER):
                    break

                if result.endswith(Protocol.MARKER):
                    break

        except Exception as e:
            pause_apm(reason=e)
            raise BlackfireApiException('Agent recv data failed.[%s]' % (e))

        return result

    def _write_prolog(self, config):
        global _blackfire_keys

        blackfire_yml = bool(int(config.args.get('flag_yml', '1')))
        blackfire_yml_content = None
        if blackfire_yml:
            blackfire_yml_content = read_blackfireyml_content()
            log.debug('Sending .blackfire.yml along with profile data.')
        bf_probe_header = 'python-%s, config' % (sys.hexversion)

        # recv timespan entries if timespan enabled
        recv_timespan = bool(int(config.args.get('flag_timespan', '0')))
        if recv_timespan:
            bf_probe_header += ', timespan'

        # it is an expected situation to not have the bf_yaml file in place
        # even it is defined as a flag
        if blackfire_yml_content:
            bf_probe_header += ', blackfire_yml'

        # blackfire.yaml asked from build&scenarios? Agent will not wait
        # for anymore data when noop is seen
        if config.is_blackfireyml_asked():
            bf_probe_header += ', noop'

        if bool(int(config.args.get('no_pruning', '0'))):
            bf_probe_header += ', no_pruning'

        if bool(int(config.args.get('no_anon', '0'))):
            bf_probe_header += ', no_anon'

        headers = {
            'Blackfire-Query':
            '%s&signature=%s&%s' % (
                config.challenge_raw,
                config.signature,
                config.args_raw,
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

        response_raw = self.recv()
        self.agent_response = BlackfireResponse().from_bytes(response_raw)
        _blackfire_keys = self.agent_response.get_blackfire_keys()

        if self.agent_response.status_code != BlackfireResponse.StatusCode.OK:
            raise BlackfireApiException(
                'Invalid response received from Agent. [%s]' %
                (self.agent_response)
            )

        log.debug("RECV hello_req response. ('%s')", self.agent_response)

        if self.agent_response.status_val_dict.get('blackfire_yml') == 'true':
            blackfire_yml_req = BlackfireRequest(
                headers={'Blackfire-Yaml-Size': len(blackfire_yml_content)},
                data=blackfire_yml_content,
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

            # There can be Blackfire-Fn-Args + Blackfire-Const, Blackfire-Keys all
            # update the .args dict
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


class BlackfireKeys(object):

    def __init__(self, keys):
        '''Parses the received Blackfire-Keys line and presents necessary fields
        as attributes.

        keys: a string that contains Blackfire-Keys entries.
        e.g: max_age (secs);Key1, Key2, Key3
        '''
        self._keys_raw = keys
        keys = keys.split(',')

        max_age, key1 = keys[0].split(';')
        keys = [key1] + keys[1:]
        keys = list(map(replace_bad_chars, keys))
        self._keys = keys
        self._expiration_time = get_time() + int(max_age)

    def is_expired(self):
        return self._expiration_time <= get_time()

    def __iter__(self):
        return iter(self._keys)

    def __repr__(self):
        return "keys=%s, expiration_time=%s" % (
            self._keys, self._expiration_time
        )


class BlackfireResponseBase(BlackfireMessage):
    TIMESPAN_KEY = 'Blackfire-Timespan'
    FN_ARGS_KEY = 'Blackfire-Fn-Args'
    CONSTANTS_KEY = 'Blackfire-Const'
    BLACKFIRE_KEYS_KEY = 'Blackfire-Keys'

    def get_blackfire_keys(self):
        keys = self.args.get(self.BLACKFIRE_KEYS_KEY, [])
        if len(keys) == 1:  # defensive
            # Blackfire-Keys is not repeated like other headers. Keys are sent
            # in a single line as comma separated values
            return BlackfireKeys(keys[0])

    def get_timespan_selectors(self):
        result = {'^': set(), '=': set()}

        ts_selectors = self.args.get(self.TIMESPAN_KEY, [])

        for ts_sel in ts_selectors:
            if ts_sel[0] not in ['^', '=']:
                log.warning("Ignoring invalid timespan selector '%s'.", ts_sel)
                continue

            result[ts_sel[0]].add(ts_sel[1:])

        return result

    def get_constants(self):
        return self.args.get(self.CONSTANTS_KEY, [])

    def get_instrumented_funcs(self):
        result = {}
        # convert the fn-args string to dict for faster lookups on C side
        fn_args = self.args.get(self.FN_ARGS_KEY, [])
        for fn_arg in fn_args:
            fn_name, arg_ids_s = fn_arg.rsplit(" ", 1)
            fn_name = fn_name.strip()

            if fn_name in result:
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

            result[fn_name] = arg_ids

        return result


class BlackfireRequest(BlackfireMessage):

    __slots__ = 'headers', 'data'

    def __init__(self, headers=None, data=None):
        if not headers:
            headers = {}
        self.headers = {}
        for k, v in headers.items():
            # these headers are not expected to be lower-case
            if k not in [
                'Blackfire-Query', 'Blackfire-Probe', 'Blackfire-Yaml-Size'
            ]:
                self.headers[k.lower()] = v
                continue
            self.headers[k] = v
        self.data = data

    def to_bytes(self):
        result = ''

        # There are multiple BlackfireRequest messages between Agent->Probe. If this
        # message contains file-format or Blackfire-Query header, we make sure it is the first line
        # in the protocol. While this is not mandatory, this is to comply with other
        # probes.
        if 'file-format' in self.headers:
            result += 'file-format: %s\n' % (self.headers['file-format'])
        if 'Blackfire-Query' in self.headers:
            result += 'Blackfire-Query: %s\n' % (
                self.headers['Blackfire-Query']
            )
        for k, v in self.headers.items():
            if k in ['Blackfire-Query', 'file-format']:
                continue
            result += '%s: %s\n' % (UC(k), UC(v))
        if len(self.headers):
            result += '\n'
        if self.data:
            result += str(self.data)

        # Py2 note:
        # Py2 treats the string as ASCII encoded unless you explicitly do it.
        # As we have used UC() on most of the headers passed to this function,
        # we are safe to encode to Protocol.ENCODING directly here
        return unicode_or_bytes(result)

    def from_bytes(self, data):
        data = data.decode(Protocol.ENCODING)
        dsp = data.split(Protocol.MARKER.decode(Protocol.ENCODING))
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

    def __repr__(self):
        container_dict = {"headers": self.headers, "data": self.data}
        return json.dumps(container_dict, indent=4)


class BlackfireAPMRequest(BlackfireRequest):

    def to_bytes(self):
        result = ''

        # APM protocol requires the first header to be FileFormat
        result += 'file-format: %s\n' % (self.headers['file-format'])
        for k, v in self.headers.items():
            if k == 'file-format':
                continue
            result += '%s: %s\n' % (k, v)

        if self.data is not None:
            result += str(self.data)
        result += '\n\n'

        if IS_PY3:
            result = bytes(result, Protocol.ENCODING)
        return result


class BlackfireAPMResponse(BlackfireResponseBase):
    TIMESPAN_KEY = 'timespan'
    FN_ARGS_KEY = 'fn-args'

    def __init__(self):
        self.args = defaultdict(list)
        self.key_pages = []
        self.raw_data = ''
        self.update_config = False

    def __repr__(self):
        return self.raw_data

    def from_bytes(self, data):
        if IS_PY3:
            data = data.decode(Protocol.ENCODING)
        self.raw_data = data.strip()

        lines = self.raw_data.split('\n')

        # first line is the status line
        resp = lines[0].split(':')
        resp_type = resp[0]
        resp_val = resp[1]

        if resp_type == 'Blackfire-Error':
            raise BlackfireAPMException(
                'Agent could not send APM trace. reason=%s' % (resp_val)
            )

        resp_type = resp_type.strip()
        self.status_val = resp_val.strip()
        self.status_val_dict = dict(parse_qsl(self.status_val))

        if 'false' in self.status_val_dict['success']:
            raise BlackfireAPMStatusFalseException(
                self.status_val_dict.get(
                    'error', "status=False and no error received from Agent."
                )
            )

        self.update_config = False if self.status_val_dict.get(
            'update_config', 'false'
        ) == 'false' else True

        key_page = None
        for line in lines[1:]:
            line = line.strip()
            # every key-page entry starts with `key-page(` and endswith `)`
            if line.startswith('key-page('):
                key_page = {}
                continue
            elif line.startswith(')'):
                self.key_pages.append(key_page)
                key_page = None
                continue

            # split only first occurrence
            resp_key, resp_val = line.split(':', 1)
            resp_key = resp_key.strip()
            resp_val = resp_val.strip()

            # are we parsing a key-page entry?
            if key_page is not None:
                key_page[resp_key] = resp_val
            else:
                # there are arguments which occur multiple times with different
                # values (e.g: fn-args)
                # e.g:
                # timespan: =mysql_connect
                # timespan: =mysql_query
                # timespan: ^PDO::
                # fn-args: file_get_contents 1,2
                # fn-args: PDO::query 1
                self.args[resp_key].append(resp_val)

        return self


class BlackfireResponse(BlackfireResponseBase):

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
            data = data.decode(Protocol.ENCODING)
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
            resp_key, resp_val = line.split(':', 1)
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
            result = bytes(result, Protocol.ENCODING)
        return result

    def __repr__(self):
        return "status_code=%s, args=%s, status_val=%s" % (
            self.status_code, self.args, self.status_val
        )
