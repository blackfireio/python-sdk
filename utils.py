import os
import sys
import json
import traceback
import logging
import platform
import importlib
from threading import Thread
import _blackfire_profiler as _bfext

try:
    # platform checks are done whenever we access resource module
    import resource
except:
    pass

IS_PY3 = sys.version_info > (3, 0)

if IS_PY3:
    from urllib.parse import parse_qsl, quote, urlparse, urlencode, urljoin
    from configparser import ConfigParser
    console_input = input
    from urllib.request import Request, urlopen, ProxyHandler, build_opener, install_opener
    from queue import Queue
else:
    from urlparse import parse_qsl, urlparse, urljoin
    from urllib import quote, urlencode
    from ConfigParser import ConfigParser
    console_input = raw_input
    from urllib2 import Request, urlopen, ProxyHandler, build_opener, install_opener
    from Queue import Queue

_DEFAULT_LOG_LEVEL = 2
_DEFAULT_LOG_FILE = 'python-probe.log'


def install_proxy_handler(http_proxy, https_proxy):
    proxies = {}
    if http_proxy:
        proxies['http'] = http_proxy
    if https_proxy:
        proxies['https'] = https_proxy
    proxy_support = ProxyHandler()
    opener = build_opener(proxy_support)
    install_opener(opener)


def read_blackfireyml_content():
    bf_yaml_files = [".blackfire.yaml", ".blackfire.yml"]
    MAX_FOLDER_COUNT = 255  # be defensive

    i = 0
    cwd = os.getcwd()
    while i < MAX_FOLDER_COUNT:
        for fname in bf_yaml_files:
            fpath = os.path.join(cwd, fname)
            if os.path.exists(fpath):
                try:
                    with open(fpath, "r") as f:
                        result = f.read()
                        return result
                except IOError:
                    pass  # suppress PermissionDenied

        # move up
        prev_cwd = cwd
        cwd = os.path.abspath(os.path.join(cwd, os.pardir))
        if prev_cwd == cwd:  # root dir found
            break

        i += 1


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


def get_cpu_count():
    """We don't want to use multiprocessing.cpu_count as it does not work well
    with AWS lambda due to SHM initialization.

    Returns the number of logical CPUs in the system (same as os.cpu_count() in Python 3.4).
    """
    plat_sys = platform.system()
    if plat_sys == "Linux":
        try:
            return os.sysconf("SC_NPROCESSORS_ONLN")
        except ValueError:
            ncpus = 0
            with open('/proc/cpuinfo') as f:
                for line in f:
                    if line.lower().startswith(b'processor'):
                        ncpus += 1
        return ncpus

    return _bfext.get_cpu_count_logical()


def get_memory_usage():
    plat_sys = platform.system()
    pid = os.getpid()
    if plat_sys == "Linux":
        with open("/proc/%s/statm" % (os.getpid(), ), "rb") as f:
            _, rss, _, _, _, _, _ = \
                [int(x) * os.sysconf("SC_PAGE_SIZE") for x in f.readline().split()[:7]]
        peak_usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024
        return rss, peak_usage
    elif plat_sys == "Darwin":
        usage, _ = _bfext.get_memory_usage(pid)
        peak_usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return usage, peak_usage
    elif plat_sys == "Windows":
        return _bfext.get_memory_usage(pid)


def get_load_avg():
    try:
        load_avg = os.getloadavg()
        return " ".join([str(x) for x in load_avg])
    except:
        pass  # os.getloadavg not available in Windows


def _get_log_level(logger, level):
    _LOG_LEVELS = {
        5: logging.DEBUG,
        4: logging.DEBUG,
        3: logging.INFO,
        2: logging.WARNING,
        1: logging.ERROR
    }

    try:
        level = int(level)
        return _LOG_LEVELS[level]
    except:
        logger.error(
            "BLACKFIRE_LOG_LEVEL is set to %s however it should be a number between 1 and 4 (1: error, 2: warning, 3: info, 4: debug). Default is '%d'." % \
                (level, _DEFAULT_LOG_LEVEL)
        )
        return _LOG_LEVELS[_DEFAULT_LOG_LEVEL]


def get_logger(name, log_file=None, log_level=None, include_line_info=True):
    # Normally basicConfig initialized the root logger but we need to support PY2/PY3
    # in same code base, so we use a flag to determine if logger is initialized or not

    log_file = log_file or os.environ.get(
        'BLACKFIRE_LOG_FILE', _DEFAULT_LOG_FILE
    )
    log_level = log_level or os.environ.get(
        'BLACKFIRE_LOG_LEVEL', _DEFAULT_LOG_LEVEL
    )
    logger = logging.getLogger(name)
    log_level = _get_log_level(logger, log_level)
    logger.setLevel(log_level)

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
