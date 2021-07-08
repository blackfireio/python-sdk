import threading

_nw = threading.local()


def get_counters():
    if not getattr(_nw, 'in_bytes', None):
        _nw.in_bytes = 0
    if not getattr(_nw, 'out_bytes', None):
        _nw.out_bytes = 0
    return _nw
