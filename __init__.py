import re
import io
import os
import sys
import traceback
import logging
import atexit
import json
import base64
import importlib
import platform

from blackfire.utils import *
from blackfire import profiler
from blackfire.exceptions import BlackfireApiException

__all__ = [
    'BlackfireConfiguration',
    'VERSION',
    'bootstrap_python',
    'patch_all',
    'profile',
    'generate_config',
]

ext_dir = os.path.dirname(os.path.abspath(__file__))
with io.open(os.path.join(ext_dir, 'VERSION')) as f:
    VERSION = f.read().strip()

COST_DIMENSIONS = 'wt cpu mu pmu nw_in nw_out'


def _get_default_agent_socket():
    plat = platform.system()
    if plat == 'Windows':
        return 'tcp://127.0.0.1:8307'
    elif plat == 'Darwin':
        if platform.processor() == 'arm':
            return 'unix:///opt/homebrew/var/run/blackfire-agent.sock'
        else:
            return 'unix:///usr/local/var/run/blackfire-agent.sock'
    else:
        return 'unix:///var/run/blackfire/agent.sock'


# conform with optional pep: PEP396
__version__ = VERSION
DEFAULT_AGENT_TIMEOUT = 0.25
DEFAULT_AGENT_SOCKET = _get_default_agent_socket()
_DEFAULT_ENDPOINT = 'https://blackfire.io/'
DEFAULT_CONFIG_FILE = os.path.join(get_home_dir(), '.blackfire.ini')
BLACKFIRE_CLI_EXEC = 'blackfire'

log = get_logger("blackfire.init")


class BlackfireConfiguration(object):

    def __init__(self, query, **kwargs):
        """
        query: is the BLACKFIRE_QUERY url encoded string that contains the signed params
        signature ...etc.
        """
        self.query_raw = query

        for k, v in kwargs.items():
            setattr(self, k, v)

        matches = re.split('(?:^|&)signature=(.+?)(?:&|$)', query, 2)

        self.challenge_raw = matches[0]
        self.signature = matches[1]
        self.args_raw = matches[2]

        self.args = dict(parse_qsl(self.args_raw))
        self.challenge = dict(parse_qsl(self.challenge_raw))

    def is_blackfireyml_asked(self):
        return 'request-id-blackfire-yml' in self.challenge['agentIds']

    def __getattribute__(self, name):
        value = None
        try:
            value = object.__getattribute__(self, name)
        except AttributeError:
            raise AttributeError(
                'BlackfireConfiguration object has no attribute=%s.' % (name)
            )

        return value

    def __repr__(self):
        return json_prettify(self.__dict__)


def _get_signing_response(
    signing_endpoint,
    client_id,
    client_token,
    http_proxy,
    https_proxy,
    urlopen=urlopen
):
    _SIGNING_API_TIMEOUT = 5.0

    request = Request(signing_endpoint)
    auth_hdr = '%s:%s' % (client_id, client_token)
    if IS_PY3:
        auth_hdr = bytes(auth_hdr, 'ascii')
    base64string = base64.b64encode(auth_hdr)
    if IS_PY3:
        base64string = base64string.decode("ascii")

    if http_proxy or https_proxy:
        install_proxy_handler(http_proxy, https_proxy)

    request.add_header("Authorization", "Basic %s" % base64string)
    result = urlopen(request, timeout=_SIGNING_API_TIMEOUT)
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


def _stop_at_exit():
    profiler.stop()
    logging.shutdown()


# Note: The functions registered via this module are not called when the
# program is killed by a signal not handled by Python, when a Python fatal
# internal error is detected, or when os._exit() is called.
atexit.register(_stop_at_exit)


def _add_bootstrap_to_pythonpath(bootstrap_dir):
    """
    Add our bootstrap directory to the head of $PYTHONPATH to ensure
    it is loaded before program code
    """
    python_path = os.environ.get('PYTHONPATH', '')

    if python_path:
        new_path = '%s%s%s' % (
            bootstrap_dir, os.path.pathsep, os.environ['PYTHONPATH']
        )
        os.environ['PYTHONPATH'] = new_path
    else:
        os.environ['PYTHONPATH'] = bootstrap_dir


def _print_help():
    help_string = '''Usage: blackfire-python <program>
       blackfire-python [options] run [options] <program>
       blackfire-python help <command>

blackfire-python will make the Python program <program> instrumentable by Blackfire without any code modification.

Commands:

  run		Enable code instrumentation and start profiling immediately with "blackfire run".
  help		Provide help

For more information on blackfire-python, please visit https://blackfire.io/docs.
    '''
    if get_executable_path(BLACKFIRE_CLI_EXEC) is None:
        help_string += '\nWarning: The "blackfire" CLI is not installed. It is needed for the "run"' \
            'command to work properly.\nPlease visit https://blackfire.io/docs/up-and-running/installation ' \
            'to install it.\n'
    print(help_string)


def _print_help_run():
    help_string = '''Usage: blackfire-python <program>
       blackfire-python [options] run [options] <program>
       blackfire-python help <command>

Help for the "run" command:

Enable code instrumentation, run a python program, and starts profiling
immediately.

blackfire-python [options] run [options] <program>

The "blackfire-python run" command is a proxy for "blackfire run".
Any options accepted by "blackfire run" are available in this command.
To learn more, please run "blackfire help run".

For more information on blackfire-python, please visit https://blackfire.io/docs.
'''

    if get_executable_path(BLACKFIRE_CLI_EXEC) is None:
        help_string += '\nWarning: The "blackfire" CLI is not installed. It is needed for the "run" ' \
            'command to work properly.\nPlease visit https://blackfire.io/docs/up-and-running/installation ' \
            'to install it.\n'

    print(help_string)


def bootstrap_python():
    global ext_dir

    bootstrap_dir = os.path.join(ext_dir, 'bootstrap')

    _add_bootstrap_to_pythonpath(bootstrap_dir)

    log.debug('PYTHONPATH: %s' % os.environ['PYTHONPATH'])

    if len(sys.argv) < 2:
        _print_help()
        sys.exit(1)

    # `blackfire-python` cmd has a run command that propagates the call to `blackfire run`.
    # `blackfire run` arguments can either be passed as prefixes and/or suffixes.
    # There are also commands like `blackfire-python python3 myapp.py run` which should
    # not be propagated to `blackfire run`. To differentiate having a run command and not having
    # it is: looking at the prefix of run and checking if the arguments are valid for
    # `blackfire run`. Specifically: if they start with `-` or `--`. One more exception to
    # this is: `blackfire-python help run`. `help` is also a valid prefix, too.
    cmd = sys.argv[1:]

    if len(cmd) == 1 and cmd[0] == 'help':
        _print_help()
        sys.exit(1)
    elif len(cmd) == 2 and cmd[0] == 'help' and cmd[1] == 'run':
        _print_help_run()
        sys.exit(1)

    run_index = cmd.index('run') if 'run' in cmd else None
    executable = None
    if run_index is not None:
        executable = BLACKFIRE_CLI_EXEC
        for i in range(run_index):
            if not cmd[i][0] in ['-', '--']:  # is not a run option?
                executable = None

    if executable is None:
        executable = sys.argv[1]
        args = sys.argv[2:]
    else:
        args = sys.argv[1:]

    log.debug(
        'Executing command = %s (executable=%s, args=%s)', cmd, executable, args
    )

    executable_path = get_executable_path(executable)
    if executable_path is None:
        if executable == BLACKFIRE_CLI_EXEC:
            print(
                'Error: The "blackfire" CLI is not installed. It is needed for the "run" '
                'command to work properly.\nPlease visit https://blackfire.io/docs/up-and-running/installation '
                'to install it.'
            )
            sys.exit(1)

        raise Exception('`%s` is not a valid executable.' % (executable))

    # execl(...) propagates current env. vars
    os.execl(executable_path, executable_path, *args)


def bootstrap():
    try:
        patch_all()
    except:
        traceback.print_exc()

    try:
        query = os.environ.get('BLACKFIRE_QUERY')
        if query:
            del os.environ['BLACKFIRE_QUERY']

            from blackfire import probe

            probe.initialize(query=query, method="bootstrap")
            probe.enable(end_at_exit=True)
    except:
        traceback.print_exc()


# This code should be the first to run before any import is made.
# It monkey patches the modules given if installed.
def patch_all():
    PATCH_MODULES = ['nw', 'django', 'flask', 'odoo']

    # we check for sys.version because patch will import FastAPI middleware code
    # that might raise SyntaxError on older versions
    if sys.version_info >= (3, 7):
        PATCH_MODULES.append('fastapi')

    patched_modules = []
    for mod_name in PATCH_MODULES:
        module = importlib.import_module(
            'blackfire.hooks.%s.patch' % (mod_name)
        )
        r = module.patch()
        if r:
            patched_modules.append(mod_name)

    log.debug("Patched modules=%s", patched_modules)


def profile(
    func=None,
    client_id=None,
    client_token=None,
    title=None,
):
    from blackfire.probe import enable, end, initialize

    def inner_func(func):

        def wrapper(*args, **kwargs):
            initialize(
                client_id=client_id,
                client_token=client_token,
                method="decorator",
                title=title,
            )
            enable()
            try:
                result = func(*args, **kwargs)
            finally:
                end()

            return result

        return wrapper

    # return wrapper function if no parantheses and return decorator if arguments
    # provided
    if callable(func):
        return inner_func(func)
    else:
        return inner_func


def generate_config(
    query=None,
    client_id=None,
    client_token=None,
    agent_socket=None,
    agent_timeout=None,
    endpoint=None,
    config_file=DEFAULT_CONFIG_FILE,
    title=None,
    ctx_var=None,
):
    agent_socket = agent_socket or os.environ.get(
        'BLACKFIRE_AGENT_SOCKET', DEFAULT_AGENT_SOCKET
    )
    agent_timeout = agent_timeout or os.environ.get(
        'BLACKFIRE_AGENT_TIMEOUT', DEFAULT_AGENT_TIMEOUT
    )
    endpoint = endpoint or os.environ.get(
        'BLACKFIRE_ENDPOINT', _DEFAULT_ENDPOINT
    )
    agent_timeout = float(agent_timeout)

    log.debug(
        "generate_config(query=%s, endpoint=%s, title=%s, ctx_var=%s) called." %
        (query, endpoint, title, ctx_var)
    )

    # manual profiling?
    if query is None:

        c_client_id = c_client_token = None
        http_proxy = https_proxy = None

        # read config params from config file
        if os.path.exists(config_file):
            config = ConfigParser()
            config.read(config_file)
            if 'blackfire' in config.sections():
                bf_section = dict(config.items('blackfire'))

                c_client_id = bf_section.get('client-id', '').strip()
                c_client_token = bf_section.get('client-token', '').strip()

                http_proxy = bf_section.get('http-proxy', '').strip()
                https_proxy = bf_section.get('https-proxy', '').strip()

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
            signing_endpoint, client_id, client_token, http_proxy, https_proxy
        )

        # tweak some options for manual profiling
        resp_dict['options']['aggreg_samples'] = 1
        if title is not None:
            resp_dict['options']['profile_title'] = title

        # generate the query string from the signing req.
        query = resp_dict['query_string'] + '&' + urlencode(
            resp_dict['options']
        )

    return BlackfireConfiguration(
        query,
        agent_socket=agent_socket,
        agent_timeout=agent_timeout,
        client_id=client_id,
        client_token=client_token,
        endpoint=endpoint,
        ctx_var=ctx_var,
    )
