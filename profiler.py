import os
import sys
import json
import warnings
import threading
import _blackfire_profiler as _bfext
from contextlib import contextmanager
from collections import Counter
from blackfire.utils import urlencode, IS_PY3, get_logger
from blackfire.exceptions import *

__all__ = ['start', 'stop', 'get_traces', 'clear_traces', 'run']

log = get_logger(__name__, include_line_info=False)

_max_prefix_cache = {}
MAX_TIMESPAN_THRESHOLD = 1000000000


def _fn_matches_timespan_selector(names, timespan_selectors):
    '''
    This function is called from the C extension to match the timespan_selectors
    with the fn. name of the pit. It is called one per-pit and cached on the C 
    extension.
    '''
    name, name_formatted = names

    eq_set = timespan_selectors.get('=', set())
    if name in eq_set or name_formatted in eq_set:
        return 1

    prefix_set = timespan_selectors.get('^', set())

    # search in prefix by name
    prefix = ''
    for c in name:
        prefix += c
        if prefix in prefix_set:
            return 1

    # search in prefix by name_formatted
    prefix = ''
    for c in name_formatted:
        prefix += c
        if prefix in prefix_set:
            return 1

    return 0


def _format_funcname(module, name):
    global _max_prefix_cache

    # called internally each time a _pit is generated to set the .formatted_name
    # member. This formatted name is used internally to lookup instrumented functions
    dir_path = os.path.dirname(os.path.normpath(module))

    # some of these dirs in sys.path are overlapping each other, we need
    # to find a way to maximize the overlap length between two strings.
    # As this will be O(n^2), this might be slow if there are
    # too many trace lines. Thus, we will cache some already pre-processed
    # modules in order to reduce amortized complexity. Since this will
    # run only single time per-module, its amortized complexity will become
    # O(1) over time.
    max_prefix_len = _max_prefix_cache.get(dir_path, 0)
    if not max_prefix_len:
        for path in sys.path:
            if module.startswith(path):
                max_prefix_len = max(len(path), max_prefix_len)

    if max_prefix_len:
        cropped_fmodule = module[max_prefix_len:].strip(os.sep)
        _max_prefix_cache[dir_path] = max_prefix_len
        module = cropped_fmodule

    # we assume remaining module dirname is actually a package
    module = module.replace(os.sep, '.')

    # drop the extension
    module = os.path.splitext(module)[0]

    return "%s.%s" % (module, name)


def _set_threading_profile(on, _):

    def _profile_thread_callback(frame, event, arg):
        """
        _profile_thread_callback will only be called once per-thread.
        """
        _bfext._profile_event(frame, event, arg)

    if on:
        threading.setprofile(_profile_thread_callback)
    else:
        threading.setprofile(None)


# SessionIDManagers should derive from this class.
class BaseSessionIDManager(object):

    @classmethod
    def get(cls):
        pass

    @classmethod
    def reset(cls):
        pass


class _DefaultSessionIDManager(BaseSessionIDManager):

    _tlocal = threading.local()
    _counter = 0  # monotonic
    _counter_lock = threading.Lock()
    MAX_COUNTER_SIZE = (2**32) - 1  # counter should not be greater than uint32

    @classmethod
    def get(cls):
        try:
            return cls._tlocal._session_id
        except AttributeError:
            with cls._counter_lock:
                if cls._counter == cls.MAX_COUNTER_SIZE:
                    cls._counter = 0  # restart
                cls._counter += 1
                cls._tlocal._session_id = cls._counter

        return cls._tlocal._session_id

    @classmethod
    def reset(cls):
        cls._counter = 0
        cls._tlocal = threading.local()


# used from testing to set Probe state to a consistent state
def reset():
    _DefaultSessionIDManager.reset()

    initialize()


# the default session ID callback used when there is no session_id callback available
def _default_session_id_callback(*args):
    return _DefaultSessionIDManager.get()


def initialize(
    format_funcname=_format_funcname,
    timespan_selector=_fn_matches_timespan_selector,
    set_threading_profile=_set_threading_profile,
    session_id_callback=_default_session_id_callback,
):
    _bfext._initialize(locals(), log)


# a custom dict class to reach keys as attributes
class BlackfireTrace(Counter):
    __getattr__ = dict.__getitem__

    def __str__(self):
        return json.dumps(self, indent=4)

    def update_counters(self, other):
        # if we end up here, that means the traces are equal. That means we only
        # need to update the counters, rec_level/fn_args/name all these params are
        # used for checking equality
        self.call_count += other.call_count
        self.wall_time += other.wall_time
        self.cpu_time += other.cpu_time
        self.mem_usage += other.mem_usage
        self.peak_mem_usage += other.peak_mem_usage


def _generate_trace_key(omit_sys_path_dirs, trace):

    def _format_name(module, name, name_formatted, fn_args, rec_level):

        if omit_sys_path_dirs and name_formatted:
            module = ''
            name = name_formatted

        if module:
            module = os.path.splitext(module)[0] + '.'

        if fn_args:
            fn_args = '?' + urlencode(fn_args)
            fn_args = fn_args.replace('+', ' ')
            fn_args = fn_args.replace('%3A', ':')

        rec_level_suffix = ''
        if rec_level > 1:
            rec_level_suffix = '@%d' % (rec_level - 1)

        return ''.join([module, name, fn_args, rec_level_suffix])

    caller_formatted = _format_name(
        trace.caller_module,
        trace.caller_name,
        trace.caller_name_formatted,
        trace.caller_fn_args,
        trace.caller_rec_level,
    )
    if not caller_formatted:  # main function?
        _trace_key = trace.callee_name
    else:
        _trace_key = '%s==>%s' % (
            caller_formatted,
            _format_name(
                trace.callee_module,
                trace.callee_name,
                trace.callee_name_formatted,
                trace.callee_fn_args,
                trace.callee_rec_level,
            )
        )
    return _trace_key


class BlackfireTraces(dict):

    def __init__(self, omit_sys_path_dirs, extended):
        self._omit_sys_path_dirs = omit_sys_path_dirs
        self.timeline_traces = {}
        self._extended = extended
        self._timespan_key = 'Timespan' if extended else 'Threshold'

    def add(self, **kwargs):
        trace = BlackfireTrace(kwargs)
        _trace_key = _generate_trace_key(self._omit_sys_path_dirs, trace)

        # TODO: Some builtin functions have same name but different index
        #assert _trace_key not in self

        if _trace_key in self:
            # multiple ctx_id single session might endup same _trace_key being
            # used more than once. In that case, we update the BlackfireTrace(Counter)
            self[_trace_key].update_counters(trace)
        else:
            self[_trace_key] = trace

    def add_timeline(self, **kwargs):
        trace = BlackfireTrace(kwargs)
        _trace_key = _generate_trace_key(self._omit_sys_path_dirs, trace)

        if len(self.timeline_traces) % 2 == 0:
            key = '%s-%d-start: ' % (self._timespan_key, trace.timeline_index)
        else:
            key = '%s-%d-end: %s' % (
                self._timespan_key, trace.timeline_index, _trace_key
            )

        self.timeline_traces[key] = trace

    def __str__(self):
        result = ''
        for trace_key, trace in self.items():
            result += '%s//%d %d %d %d %d\n' % ( \
                        trace_key,
                        trace.call_count,
                        trace.wall_time,
                        trace.cpu_time,
                        trace.mem_usage,
                        trace.peak_mem_usage,)

        # add timeline entries
        if len(self.timeline_traces):
            result += '\n'
        for trace_key, trace in self.timeline_traces.items():
            result += '%s//%d %d %d %d\n' % ( \
                        trace_key,
                        trace.wall,
                        trace.cpu,
                        trace.mu,
                        trace.pmu)
        return result

    def to_bytes(self):
        traces = str(self)
        if IS_PY3:
            traces = bytes(traces, 'ascii')
        return traces

    def __add__(self, other):
        result = BlackfireTraces(
            self._omit_sys_path_dirs, extended=self._extended
        )
        for key, trace in self.items():
            try:
                new_trace = trace.copy()
                new_trace.update(other[key])
                result[key] = new_trace
            except KeyError:
                pass
        # add remaining
        for key, trace in other.items():
            if key not in result:
                result[key] = trace.copy()
        return result

    def pretty_print(self):
        print(json.dumps(self, indent=4))


class _BlackfireTracesBase(dict):

    def __init__(self, traces, timeline_traces, omit_sys_path_dirs):
        self._traces = traces
        self._timeline_traces = timeline_traces
        self._omit_sys_path_dirs = omit_sys_path_dirs

        self._add_traces()

    def _add_traces(self):

        def _is_special_function(fname_formatted):
            SPECIAL_FUNCS = [
                'blackfire.middleware._DjangoCursorWrapper',
                'blackfire.probe.add_marker',
            ]

            for sfn in SPECIAL_FUNCS:
                if sfn in fname_formatted:
                    return True

            return False

        for trace in self._traces:
            fname, fmodule, fname_formatted, flineno, fbuiltin, findex, fchildren, \
            fctxid, ffn_args, frec_level = trace

            assert findex not in self, trace  # assert no duplicate index exists

            dir_path = os.path.dirname(os.path.normpath(fmodule))
            last_dir = os.path.basename(dir_path)

            # Filter out profile specific modules like our profiler extension related
            # call stack
            if last_dir in ["blackfire"] or fmodule == '_blackfire_profiler':
                if fname_formatted and not _is_special_function(
                    fname_formatted
                ):
                    continue
            # we do not generate the traceformat directly as for each children,
            # we need to have the 'index' available. For this, we first add all
            # traces and then call to_traceformat(...)
            self[findex] = {
                "name": fname,
                "module": fmodule,
                "name_formatted": fname_formatted or '',
                "lineno": flineno,
                "is_builtin": fbuiltin,
                "children": fchildren,
                "ctx_id": fctxid,
                "fn_args": ffn_args or '',
                "rec_level": frec_level,
            }

    def to_traceformat(self, extended=False):
        """
        Function calls represent a caller ==> callee call pair followed by
        its costs (ct, wt, cpu, mu, pmu, ....etc.).
        """
        result = BlackfireTraces(self._omit_sys_path_dirs, extended)

        if not extended:
            for _, stat in self.items():
                for child in stat["children"]:
                    # we check this as we might have prevented some functions to be
                    # shown in the output
                    if child[0] in self:
                        caller = stat
                        callee = self[child[0]]
                        is_root = (caller == callee)

                        result.add(
                            caller_module=caller['module']
                            if not is_root else '',
                            caller_name=caller['name'] if not is_root else '',
                            caller_fn_args=caller["fn_args"]
                            if not is_root else '',
                            caller_rec_level=caller["rec_level"],
                            caller_name_formatted=caller["name_formatted"]
                            if not is_root else '',
                            callee_module=callee["module"],
                            callee_name=callee["name"],
                            callee_fn_args=callee["fn_args"],
                            callee_name_formatted=callee["name_formatted"],
                            callee_rec_level=callee["rec_level"],
                            call_count=child[1],
                            wall_time=child[3],
                            cpu_time=child[4],
                            mem_usage=child[5],
                            peak_mem_usage=child[6],
                            rec_level=callee["rec_level"],
                        )

        # add timeline traces
        i = 0
        for te in self._timeline_traces:
            # we check this as we might have prevented some functions to be
            # shown in the output
            if not te[0] in self or not te[1] in self:
                continue

            caller = self[te[0]]
            callee = self[te[1]]

            trace_dict = dict(
                caller_module=caller['module'],
                caller_name=caller['name'],
                caller_fn_args=caller["fn_args"],
                caller_rec_level=caller["rec_level"],
                caller_name_formatted=caller["name_formatted"],
                callee_module=callee["module"],
                callee_name=callee["name"],
                callee_fn_args=callee["fn_args"],
                callee_name_formatted=callee["name_formatted"],
                callee_rec_level=callee["rec_level"],
                timeline_index=i
            )

            # add the same trace dict twice with different metrics one for
            # Threshold-start and one for Threshold-End
            result.add_timeline(
                **dict(trace_dict, wall=te[2], cpu=te[3], mu=te[6], pmu=te[7])
            )
            result.add_timeline(
                **dict(trace_dict, wall=te[4], cpu=te[5], mu=te[8], pmu=te[9])
            )
            i += 1
        return result


def start(
    session_id=None,
    builtins=True,
    profile_cpu=True,
    profile_memory=True,
    profile_timespan=False,
    instrumented_funcs={},
    timespan_selectors={},
    timespan_threshold=MAX_TIMESPAN_THRESHOLD,  # ms
    apm_extended_trace=False,
    probe=None,
):
    global _max_prefix_cache

    if not isinstance(timespan_selectors, dict):
        raise BlackfireProfilerException(
            "timespan_selectors shall be an instance of 'dict'"
        )

    if not isinstance(instrumented_funcs, dict):
        raise BlackfireProfilerException(
            "instrumented_funcs shall be an instance of 'dict'"
        )

    # in fact we can use this cache this forever but the idea is maybe the sys.path
    # changes in some way and it would be nice to see the effect between every
    # start/stop pair.
    _max_prefix_cache = {}

    if session_id is None:
        session_id = _default_session_id_callback()

    _bfext.start(
        session_id,
        builtins,
        profile_cpu,
        profile_memory,
        profile_timespan,
        instrumented_funcs,
        timespan_selectors,
        timespan_threshold,
        apm_extended_trace,
        probe,
    )


def stop(session_id=None):
    if session_id is None:
        session_id = _default_session_id_callback()

    _bfext.stop(session_id)


def get_traces(session_id=None, omit_sys_path_dirs=True, extended=False):
    if session_id is None:
        session_id = _default_session_id_callback()

    traces, timeline_traces = _bfext.get_traces(session_id)
    traces = _BlackfireTracesBase(traces, timeline_traces, omit_sys_path_dirs)
    return traces.to_traceformat(extended)


@contextmanager
def run(builtins=False):
    start(builtins=builtins)
    try:
        yield
    finally:
        stop()


def clear_traces(session_id=None):
    if session_id is None:
        session_id = _default_session_id_callback()

    _bfext.clear_traces(session_id)


def get_traced_memory():
    return _bfext.get_traced_memory()


def get_sessions():
    return _bfext._get_sessions()


def get_current_probe(session_id=None):
    if session_id is None:
        session_id = _default_session_id_callback()

    return _bfext.get_current_probe(session_id)


def is_session_active(session_id=None):
    '''
    Checks if the running session is already active
    Maybe auto-instrumented code generated a session for the current thread and
    user requests manual instrumentation.
    '''
    if session_id is None:
        session_id = _default_session_id_callback()

    return _bfext.is_session_active(session_id)


# import time
if __name__ != '__main__':
    initialize()
