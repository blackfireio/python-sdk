import threading

_nw = threading.local()


def get_counters():
    if getattr(_nw, 'enabled', None):
        if not getattr(_nw, 'in_bytes', None):
            _nw.in_bytes = 0
        if not getattr(_nw, 'out_bytes', None):
            _nw.out_bytes = 0
        return _nw


def enable():
    """
    We need an API to explicitly enable() the `nw` hooks because BF itself uses
    socket APIs to communicate with the Agent. With this API, we make sure those
    happen after Agent communication and just before profiled application starts.
    """
    _nw.enabled = True


def disable():
    _nw.enabled = False
