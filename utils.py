import os
import sys
import json
import traceback
import logging
import platform
import importlib
from threading import Thread

IS_PY3 = sys.version_info > (3, 0)

if IS_PY3:
    from urllib.parse import parse_qsl, quote, urlparse, urlencode, urljoin
    from configparser import ConfigParser
    console_input = input
    from urllib.request import Request, urlopen
    from queue import Queue
else:
    from urlparse import parse_qsl, urlparse, urljoin
    from urllib import quote, urlencode
    from ConfigParser import ConfigParser
    console_input = raw_input
    from urllib2 import Request, urlopen
    from Queue import Queue

_DEFAULT_LOG_LEVEL = 2
_DEFAULT_LOG_FILE = 'python-probe.log'


def import_module(mod_name):
    try:
        return importlib.import_module(mod_name)
    except ImportError:
        pass


def wrap(f, pre_func=None, post_func=None, orig=None):
    """
    orig: sometimes the original function might be different than f. Like what 
    we do to patch sys.stdout: we convert it to StringIO and then patch.
    """

    def wrapper(*args, **kwargs):
        if pre_func:
            pre_func(*args, **kwargs)
        try:
            return f(*args, **kwargs)
        finally:
            if post_func:
                post_func(*args, **kwargs)

    if orig is not None:
        wrapper._orig = orig
    else:
        wrapper._orig = f

    return wrapper


def unwrap(obj, name):

    f = getattr(obj, name)

    # function wrapped?
    if getattr(f, "_orig", None) is None:
        return

    setattr(obj, name, f._orig)


def get_probed_runtime():
    return "%s %s+%s" % (
        platform.python_implementation(), platform.python_version(),
        platform.platform()
    )


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


class _PoolWorker(Thread):

    def __init__(self, tasks):
        Thread.__init__(self)
        self.tasks = tasks
        self.daemon = True
        self.start()

    def run(self):
        while True:
            func, args, kwargs = self.tasks.get()
            try:
                if func is None:
                    break
                func(*args, **kwargs)
            except Exception as e:
                print(e)
            finally:
                self.tasks.task_done()

    def shutdown(self):
        self.tasks.put((None, None, None))


class ThreadPool(object):

    def __init__(self, size=16):
        self.tasks = Queue(size)
        self._workers = []
        for _ in range(size):
            self._workers.append(_PoolWorker(self.tasks))

    def apply(self, fn, args=(), kwargs={}):
        if is_testing():
            fn(*args, **kwargs)
        else:
            self.tasks.put((fn, args, kwargs))

    def close(self):
        for w in self._workers:
            w.shutdown()
        for w in self._workers:
            w.join()
