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
    TODO: Comment why we need this
    """
    _nw.enabled = True


def disable():
    _nw.enabled = False
