import os
import sys
import json
import traceback
import logging
import platform
import importlib
from multiprocessing.pool import ThreadPool

IS_PY3 = sys.version_info > (3, 0)

if IS_PY3:
    from urllib.parse import parse_qsl, quote, urlparse, urlencode, urljoin
    from configparser import ConfigParser
    console_input = input
    from urllib.request import Request, urlopen
else:
    from urlparse import parse_qsl, urlparse, urljoin
    from urllib import quote, urlencode
    from ConfigParser import ConfigParser
    console_input = raw_input
    from urllib2 import Request, urlopen

_DEFAULT_LOG_LEVEL = 2
_DEFAULT_LOG_FILE = 'python-probe.log'
_thread_pool = ThreadPool()


def import_module(mod_name):
    try:
        return importlib.import_module(mod_name)
    except ImportError:
        pass


def function_wrapper(f, pre_func=None, post_func=None):

    def wrapper(*args, **kwargs):
        if pre_func:
            pre_func(*args, **kwargs)
        try:
            return f(*args, **kwargs)
        finally:
            if post_func:
                post_func(*args, **kwargs)

    return wrapper


def get_probed_runtime():
    return "%s %s+%s" % (
        platform.python_implementation(), platform.python_version(),
        platform.platform()
    )


# TODO: Use function_wrapper for SysHooks


class SysHooks(object):

    def __init__(self):
        self.exit_code = 0  # if nothing happens, exit_code should be zero 0
        self.stdout_len = 0
        self.stderr_len = 0

    def _sys_exit(self, code):
        self.exit_code = code
        self._orig_exit(code)

    def _sys_excepthook(self, exc_type, exc_value, exc_traceback):
        self.exit_code = 1
        sys.__excepthook__(exc_type, exc_value, exc_traceback)

    def _sys_stdout_write(self, s):
        self.stdout_len += len(s)
        self._orig_stdout_write(s)

    def _sys_stderr_write(self, s):
        self.stderr_len += len(s)
        self._orig_stderr_write(s)

    def unregister(self):
        sys.stdout.write = self._orig_stdout_write
        sys.stderr.write = self._orig_stderr_write
        sys.exit = self._orig_exit

    def register(self):
        self._orig_exit = sys.exit
        self._orig_stdout_write = sys.stdout.write
        self._orig_stderr_write = sys.stderr.write
        sys.exit = self._sys_exit
        sys.excepthook = self._sys_excepthook

        try:
            sys.stdout.write = self._sys_stdout_write
            sys.stderr.write = self._sys_stderr_write
        except AttributeError:
            # in Py2, stdout.write is a read-only attribute. To overcome this,
            # we need to change stdout to StringIO and then monkey patch.
            from StringIO import StringIO
            sys.stdout = StringIO()
            sys.stdout.write = self._sys_stdout_write
            sys.stderr = StringIO()
            sys.stderr.write = self._sys_stderr_write


def get_load_avg():
    try:
        load_avg = os.getloadavg()
        return " ".join([str(x) for x in load_avg])
    except:
        pass  # os.getloadavg not available in Windows


def get_logger(name, log_file=None, log_level=None, include_line_info=True):
    # Normally basicConfig initialized the root logger but we need to support PY2/PY3
    # in same code base, so we use a flag to determine if logger is initialized or not

    log_file = log_file or os.environ.get(
        'BLACKFIRE_LOG_FILE', _DEFAULT_LOG_FILE
    )
    log_level = log_level or os.environ.get(
        'BLACKFIRE_LOG_LEVEL', _DEFAULT_LOG_LEVEL
    )
    log_level = int(log_level)  # make sure it is int

    _LOG_LEVELS = {
        4: logging.DEBUG,
        3: logging.INFO,
        2: logging.WARNING,
        1: logging.ERROR
    }

    logger = logging.getLogger(name)
    logger.setLevel(_LOG_LEVELS[log_level])

    formatter_info = "%(asctime)s - %(name)s - %(levelname)s - "

    # line info becomes irrelevant when logging is made from the C extension, thus
    # this is configurable.
    if include_line_info:
        formatter_info += "%(filename)s:%(lineno)d - "
    formatter_info += "%(message).8192s"

    formatter = logging.Formatter(formatter_info)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    file_handler = logging.FileHandler(log_file, 'a')
    file_handler.setFormatter(formatter)

    logger.handlers = [
        console_handler,
        file_handler,
    ]

    return logger


def get_home_dir():
    # This function is cross platform way to retrieve HOME dir.
    # See: https://docs.python.org/3/library/os.path.html#os.path.expanduser
    return os.path.expanduser("~")


# used for logging dictionaries in indented json format which can contain sets
class _JsonSetEncoder(json.JSONEncoder):

    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)

        return json.JSONEncoder.default(self, obj)


# this function take an object and run json.dumps on it with indentation enabled.
# It also does this safely, no exceptions will be thrown for this on error as this
# will usually be called from log APIs. Supports objects containing Set() objects
# as well.
def json_prettify(obj):
    try:
        return json.dumps(obj, indent=4, cls=_JsonSetEncoder)
    except:
        return str(obj)


def is_testing():
    return 'BLACKFIRE_TESTING' in os.environ


def run_in_thread_pool(fn, args):
    if is_testing():
        _thread_pool.apply(fn, args=args)
    else:
        _thread_pool.apply_async(fn, args=args)
