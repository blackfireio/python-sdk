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
from distutils.sysconfig import get_python_lib

__all__ = [
    'BlackfireConfiguration',
    'VERSION',
    'process_bootstrap',
    'patch_all',
    'profile',
    'generate_config',
]

ext_dir = os.path.dirname(os.path.abspath(__file__))
with io.open(os.path.join(ext_dir, 'VERSION')) as f:
    VERSION = f.read().strip()


def _get_default_agent_socket():
    plat = platform.system()
    if plat == 'Windows':
        return 'tcp://127.0.0.1:8307'
    elif plat == 'Darwin':
        return 'unix:///usr/local/var/run/blackfire-agent.sock'
    else:
        return 'unix:///var/run/blackfire/agent.sock'


# conform with optional pep: PEP396
__version__ = VERSION
DEFAULT_AGENT_TIMEOUT = 0.25
DEFAULT_AGENT_SOCKET = _get_default_agent_socket()
_DEFAULT_ENDPOINT = 'https://blackfire.io/'
DEFAULT_CONFIG_FILE = os.path.join(get_home_dir(), '.blackfire.ini')

log = get_logger("blackfire.init")


class BlackfireConfiguration(object):

    def __init__(self, query, **kwargs):
        """
        query: is the BLACKFIRE_QUERY url encoded string that contains the signed params
        signature ...etc.
        """

        for k, v in kwargs.items():
            setattr(self, k, v)

        matches = re.split('(?:^|&)signature=(.+?)(?:&|$)', query, 2)

        self.challenge = matches[0]
        self.signature = matches[1]
        self.args_raw = matches[2]

        self.args = dict(parse_qsl(self.args_raw))

    def __getattribute__(self, name):
        value = None
        try:
            value = object.__getattribute__(self, name)
        except AttributeError:
            raise AttributeError(
                'BlackfireConfiguration object has no attribute=%s.' % (name)
            )

        return value


def _get_signing_response(
    signing_endpoint, client_id, client_token, urlopen=urlopen
):
    _SIGNING_API_TIMEOUT = 5.0

    request = Request(signing_endpoint)
    auth_hdr = '%s:%s' % (client_id, client_token)
    if IS_PY3:
        auth_hdr = bytes(auth_hdr, 'ascii')
    base64string = base64.b64encode(auth_hdr)
    if IS_PY3:
        base64string = base64string.decode("ascii")
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


def _uninstall_bootstrap():
    site_packages_dir = get_python_lib()
    bootstrap_pth_file = os.path.join(
        site_packages_dir, 'zzz_blackfire_bootstrap.pth'
    )
    bootstrap_file = os.path.join(site_packages_dir, '_blackfire_bootstrap.py')

    if os.path.exists(bootstrap_pth_file):
        os.remove(bootstrap_pth_file)
    if os.path.exists(bootstrap_file):
        os.remove(bootstrap_file)

    print("The pre-interpreter hook files has been uninstalled.")


def _install_bootstrap():
    # add zzz_bootstrap.pth to site-packages dir for the init code. This is to
    # run code at pre-interpreter startup. This is especially needed for 'blackfire run'
    # cmd as we will enable profiler if BLACKFIRE_QUERY is in env. vars. There seems to be
    # only 2 ways to do this, which are also hecky. Python has no documented way of
    # doing these:
    #   1/ Add sitecustomize.py or modify if there is an existing one,
    #   2/ Add a custom .pth file to site-packages dir
    # We selected option 2 as it is nearly impossible to revert the changes we made
    # to the orig. sitecustomize on uninstall. So, the second way is cleaner
    # at least for uninstall operations. There are also other libs choosing this
    # approach. See: https://nedbatchelder.com/blog/201001/running_code_at_python_startup.html
    site_packages_dir = None
    try:
        site_packages_dir = get_python_lib()
        # generate the .pth file to be loaded at startup
        bootstrap_pth_file = os.path.join(
            site_packages_dir, 'zzz_blackfire_bootstrap.pth'
        )
        with open(bootstrap_pth_file, "w") as f:
            f.write("import _blackfire_bootstrap\n")
        # generate the .py file that will be imported *safely* from the .pth file.
        # This is to ensure even blackfire is uninstalled from the system this import
        # fail will not be affecting the interpreter.
        bootstrap_file = os.path.join(
            site_packages_dir, '_blackfire_bootstrap.py'
        )
        with open(bootstrap_file, "w") as f:
            f.write(
                "try:\n"
                "    import blackfire; blackfire.process_bootstrap();\n"
                "except:\n"
                "    pass\n"
            )

        print(
            "The pre-interpreter hook files has been installed. These files can "
            "be removed by running `python -m uninstall-bootstrap`.\n\nYou can try "
            "blackfire by running `blackfire run %s -m blackfire hello-world`" %
            (os.path.basename(sys.executable).strip())
        )

    except Exception as e:
        print(
            "Exception occurred while installing pre-interpreter hooks files to %s."
            "'blackfire run' command might not work properly.[exc=%s]" %
            (site_packages_dir, e)
        )


def process_bootstrap():
    query = os.environ.get('BLACKFIRE_QUERY')
    if query:
        del os.environ['BLACKFIRE_QUERY']
        try:
            from blackfire.probe import initialize, enable
            initialize(query=query, _method="bootstrap")
            enable(end_at_exit=True)
        except:
            # As this is called in import time, tracebacks cannot be seen
            # this is to ensure traceback is available if exception occurs
            traceback.print_exc()


# This code monkey patches Django and Flask frameworks if installed.
# This code should be the first to run before any import is made.
def patch_all():
    PATCH_MODULES = ['django', 'flask']

    patched_modules = []
    for mod_name in PATCH_MODULES:
        module = importlib.import_module(
            'blackfire.hooks.%s.patch' % (mod_name)
        )
        r = module.patch()
        if r:
            patched_modules.append(mod_name)

    log.info("Patched modules=%s", patched_modules)


def profile(client_id=None, client_token=None):
    from blackfire.probe import enable, end, initialize

    def inner_func(func):

        def wrapper():
            initialize(client_id=client_id, client_token=client_token)
            enable()
            try:
                func()
            finally:
                end()

        return wrapper

    return inner_func


def generate_config(
    query=None,
    client_id=None,
    client_token=None,
    agent_socket=None,
    agent_timeout=None,
    endpoint=None,
    log_file=None,
    log_level=None,
    config_file=DEFAULT_CONFIG_FILE,
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

    log.debug("generate_config() called.")

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

    return BlackfireConfiguration(
        query,
        agent_socket=agent_socket,
        agent_timeout=agent_timeout,
        client_id=client_id,
        client_token=client_token,
        endpoint=endpoint,
        log_file=log_file,
        log_level=log_level,
    )
