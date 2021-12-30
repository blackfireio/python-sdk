import threading
from blackfire.utils import ContextDict

_nw = ContextDict('bf_nw_counters')


class NwCounters:

    def __init__(self):
        self.i = 0
        self.o = 0


def get_counters():
    if _nw.get('enabled'):
        counters = _nw.get('counters')
        if counters is None:
            counters = NwCounters()
            _nw.set('counters', counters)
        return counters

def enable():
    """
    We need an API to explicitly enable() the `nw` hooks because BF itself uses
    socket APIs to communicate with the Agent. With this API, we make sure those
    happen after Agent communication and just before profiled application starts.
    """
    _nw.set('enabled', True)


def disable():
    _nw.set('enabled', False)
