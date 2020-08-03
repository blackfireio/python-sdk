import socket
import os
import sys
import json
from blackfire.exceptions import BlackfireApiException
from collections import defaultdict
from blackfire.utils import urlparse, get_logger, IS_PY3, parse_qsl

log = get_logger(__name__)


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
        self._socket.settimeout(self.agent_timeout)

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

    def connect(self, config=None):
        log.debug("Connecting to agent at %s." % str(self._sock_addr))
        try:
            self._socket.connect(self._sock_addr)
        except Exception as e:
            raise BlackfireApiException(
                'Agent connection failed.[%s][%s]' % (e, self.agent_socket)
            )

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
            raise BlackfireApiException(
                'Agent send data failed.[%s][%s]' % (e, data)
            )

    def recv(self, header_only=False):
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

                if header_only and result.endswith(Protocol.HEADER_MARKER):
                    break

                if result.endswith(Protocol.MARKER):
                    break

        except Exception as e:
            raise BlackfireApiException('Agent recv data failed.[%s]' % (e))

        return result

    def _write_prolog(self, config):
        blackfire_yml = bool(int(config.args.get('flag_yml', '1')))
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
        recv_timespan = bool(int(config.args.get('flag_timespan', '0')))
        if recv_timespan:
            bf_probe_header += ', timespan'

        # it is an expected situation to not have the bf_yaml file in place
        # even it is defined as a flag
        if blackfire_yml_contents:
            bf_probe_header += ', blackfire_yml'

        headers = {
            'Blackfire-Query':
            '%s&signature=%s&%s' % (
                config.challenge,
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
            result = bytes(result, Protocol.ENCODING)
        return result

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

    def pretty_print(self):
        container_dict = {"headers": self.headers, "data": self.data}
        print(json.dumps(container_dict, indent=4))


class BlackfireAPMResponse(BlackfireMessage):

    def __init__(self):
        self.args = defaultdict(list)
        self.key_pages = []

    def from_bytes(self, data):
        if IS_PY3:
            data = data.decode(Protocol.ENCODING)
        self.raw_data = data.strip()

        lines = self.raw_data.split('\n')

        # first line is the status line
        resp_type, resp_val = lines[0].split(':')
        resp_type = resp_type.strip()
        self.status_val = resp_val.strip()
        self.status_val_dict = dict(parse_qsl(self.status_val))

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
            result = bytes(result, Protocol.ENCODING)
        return result

    def __repr__(self):
        return "status_code=%s, args=%s, status_val=%s" % (
            self.status_code, self.args, self.status_val
        )
