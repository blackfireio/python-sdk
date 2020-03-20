import os
import sys
import traceback
import logging

PSUTIL_AVAIL = True
try:
    import psutil
except:
    PSUTIL_AVAIL = False

RESOURCE_AVAIL = True
try:
    import resource
except:
    RESOURCE_AVAIL = False

IS_PY3 = sys.version_info > (3, 0)

if IS_PY3:
    from urllib.parse import parse_qsl, quote, urlparse, urlencode, urljoin
    from configparser import ConfigParser
    console_input = input
else:
    from urlparse import parse_qsl, urlparse, urljoin
    from urllib import quote, urlencode
    from ConfigParser import ConfigParser
    console_input = raw_input


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


def get_mem_info():
    usage = peak_usage = 0

    if PSUTIL_AVAIL:
        mem_info = psutil.Process().memory_info()
        usage = mem_info.rss  # this is platform independent
        if os.name == 'nt':
            # psutil uses GetProcessMemoryInfo API to get PeakWorkingSet
            # counter. It is in bytes.
            peak_usage = mem_info.peak_wset
        else:
            # TODO: Note: Current process is also important in this regard because
            # if process forks child processes, they will not be returned.
            # we might want to change this behavior in future.

            # TODO: Docs say this is in KB but I say opposite in my tests.. look in detail
            if RESOURCE_AVAIL:
                peak_usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    return (usage, peak_usage)


def get_load_avg():
    load_avg = (0, 0, 0)
    try:
        if PSUTIL_AVAIL:
            load_avg = psutil.getloadavg()
        else:
            load_avg = os.getloadavg()
    except:
        traceback.print_exc()
    return " ".join([str(x) for x in load_avg])


def init_logger(log_file, log_level, name="python-probe"):
    # Normally basicConfig initialized the root logger but we need to support PY2/PY3
    # in same code base, so we use a flag to determine if logger is initialized or not

    _LOG_LEVELS = {
        4: logging.DEBUG,
        3: logging.INFO,
        2: logging.WARNING,
        1: logging.ERROR
    }

    _logger = logging.getLogger(name)
    _logger.setLevel(_LOG_LEVELS[log_level])
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - "
        "%(message).8192s"
    )
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    file_handler = logging.FileHandler(log_file, 'a')
    file_handler.setFormatter(formatter)

    _logger.handlers = [
        console_handler,
        file_handler,
    ]


def get_logger(name="python-probe"):
    return logging.getLogger(name)


def get_home_dir():
    # This function is cross platform way to retrieve HOME dir.
    # See: https://docs.python.org/3/library/os.path.html#os.path.expanduser
    return os.path.expanduser("~")
