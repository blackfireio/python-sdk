import os
import sys
import json
import warnings
import _blackfire_profiler as _bfext
from contextlib import contextmanager
from collections import Counter
from blackfire.utils import PSUTIL_AVAIL, get_mem_info, urlencode, IS_PY3, get_logger
from blackfire.exceptions import *

TRACEMALLOC_AVAIL = True
try:
    import tracemalloc
except:
    TRACEMALLOC_AVAIL = False
    # warnings.warn(
    #     "tracemalloc module could not be imported. When tracemalloc "
    #     "is not available, memory results will be less accurate."
    # )

if not PSUTIL_AVAIL and not TRACEMALLOC_AVAIL:
    pass
    # warnings.warn(
    #     "tracemalloc or psutil modules could not be imported. Memory profiling "
    #     "results will not be available. Please contact support."
    # )

__all__ = ['start', 'stop', 'get_traces', 'clear_traces', 'run', 'is_running']


def _get_memory_usage():
    '''
    This function will be called from profiler upon exit/entry of functions
    to retrieve mem. related information for the current process.

    Most of the times reading memory usage of the system requires reading it
    from a special system file (e.x: Linux) which means we will make an I/O call.
    That means we might sometimes read non-current data as writes to the file
    might be delayed. So, before going to these OS dependent functionality we
    should try tracemalloc first which calculates mem. usage directly in Python
    C API. There is a backport of tracemalloc lib to other Python versions
    smaller than Py3.4 but the problem is this implementation requires a new
    interpreter API to be in place, so it requires re-compile of a new Python
    interpreter, which will not be trivial.

    Return values are in bytes.
    '''

    usage = peak_usage = 0

    # interpreter shutdown?
    if not sys or not len(sys.modules):
        return (0, 0)

    try:
        if TRACEMALLOC_AVAIL:
            usage, peak_usage = tracemalloc.get_traced_memory()
            tm_mem = tracemalloc.get_tracemalloc_memory()
            usage = max(usage - tm_mem, 0)
            peak_usage = max(peak_usage - tm_mem, 0)
        else:
            usage, peak_usage = get_mem_info()
    except Exception as e:
        get_logger().exception(e)

    return (usage, peak_usage)


_max_prefix_cache = {}
_timespan_selectors = {}
MAX_TIMESPAN_THRESHOLD = 1000000000


def _fn_matches_timespan_selector(name, name_formatted):
    '''
    This function is called from the C extension to match the timespan_selectors
    with the fn. name of the pit. It is called one per-pit and cached on the C 
    extension.
    '''
    global _timespan_selectors

    # interpreter shutdown?
    if not sys or not len(sys.modules):
        return 0

    eq_set = _timespan_selectors.get('=', set())
    if name in eq_set or name_formatted in eq_set:
        return 1

    prefix_set = _timespan_selectors.get('^', set())

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


def _format_func_name(module, name):
    global _max_prefix_cache

    # interpreter shutdown?
    if not sys or not len(sys.modules):
        return ''

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


_bfext._set_format_func_name_callback(_format_func_name)


# a custom dict class to reach keys as attributes
class BlackfireTrace(Counter):
    __getattr__ = dict.__getitem__

    def __str__(self):
        return json.dumps(self, indent=4)


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

    def __init__(self, omit_sys_path_dirs):
        self._omit_sys_path_dirs = omit_sys_path_dirs
        self.timeline_traces = {}

    def add(self, **kwargs):
        trace = BlackfireTrace(kwargs)
        _trace_key = _generate_trace_key(self._omit_sys_path_dirs, trace)

        # TODO: Some builtin functions have same name but different index
        #assert _trace_key not in self

        self[_trace_key] = trace

    def add_timeline(self, **kwargs):
        trace = BlackfireTrace(kwargs)
        _trace_key = _generate_trace_key(self._omit_sys_path_dirs, trace)

        if len(self.timeline_traces) % 2 == 0:
            key = 'Threshold-%d-start: ' % trace.timeline_index
        else:
            key = 'Threshold-%d-end: %s' % (trace.timeline_index, _trace_key)

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
        result = BlackfireTraces(self._omit_sys_path_dirs)
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


class _TraceEnumerator(dict):

    def __init__(self, omit_sys_path_dirs):
        self._omit_sys_path_dirs = omit_sys_path_dirs
        self._timeline_traces = []

    def _enum_func_cbk(self, stat):
        fname, fmodule, fname_formatted, flineno, fncall, fnactualcall, fbuiltin, \
            fttot_wall, ftsub_wall, fttot_cpu, ftsub_cpu, findex, fchildren, fctxid, \
            fmem_usage, fpeak_mem_usage, ffn_args, frec_level = stat

        assert findex not in self, stat  # assert no duplicate index exists

        dir_path = os.path.dirname(os.path.normpath(fmodule))
        last_dir = os.path.basename(dir_path)

        # Filter out profile specific modules like our profiler extension related
        # call stack
        if last_dir in ["blackfire"] or fmodule == '_blackfire_profiler':
            # We include some wrapper functions for easier instrumentation
            if fname_formatted and \
                'blackfire.middleware._DjangoCursorWrapper' not in fname_formatted:
                return

        # we do not generate the traceformat directly as for each children,
        # we need to have the 'index' available. For this, we first add all
        # traces and then call to_traceformat(...)
        self[findex] = {
            "name": fname,
            "module": fmodule,
            "name_formatted": fname_formatted or '',
            "lineno": flineno,
            "ncall": fncall,
            "nnonrecursivecall": fnactualcall,
            "is_builtin": fbuiltin,
            "twall": fttot_wall,
            "sub_twall": ftsub_wall,
            "tcpu": fttot_cpu,
            "sub_tcpu": ftsub_cpu,
            "children": fchildren,
            "ctx_id": fctxid,
            "mem_usage": fmem_usage,
            "peak_mem_usage": fpeak_mem_usage,
            "fn_args": ffn_args or '',
            "rec_level": frec_level,
        }

    def _enum_timeline_cbk(self, stat):
        self._timeline_traces.append(stat)

    def to_traceformat(self):
        """
        Function calls represent a caller ==> callee call pair followed by
        its costs (ct, wt, cpu, mu, pmu, ....etc.).
        """
        result = BlackfireTraces(self._omit_sys_path_dirs)
        for _, stat in self.items():
            # is root function?
            if stat["name"] == 'main()' and stat["module"] == '':
                result.add(
                    caller_module='',
                    caller_name='',
                    caller_fn_args='',
                    caller_name_formatted='',
                    caller_rec_level=1,
                    callee_module=stat["module"],
                    callee_name=stat["name"],
                    callee_fn_args=stat["fn_args"],
                    callee_name_formatted=stat["name_formatted"],
                    callee_rec_level=1,
                    call_count=stat["ncall"],
                    wall_time=stat["twall"] * 1000000,
                    cpu_time=stat["tcpu"] * 1000000,
                    mem_usage=stat["mem_usage"],
                    peak_mem_usage=stat["peak_mem_usage"],
                )

            for child in stat["children"]:
                # we check this as we might have prevented some functions to be
                # shown in the output
                if child[0] in self:
                    caller = stat
                    callee = self[child[0]]

                    result.add(
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
                        call_count=child[1],
                        wall_time=child[3] * 1000000,
                        cpu_time=child[5] * 1000000,
                        mem_usage=child[7],
                        peak_mem_usage=child[8],
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

            result.add_timeline(
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
                wall=te[2] * 1000000,
                cpu=te[3] * 1000000,
                mu=te[6],
                pmu=te[7],
                timeline_index=i,
            )
            result.add_timeline(
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
                wall=te[4] * 1000000,
                cpu=te[5] * 1000000,
                mu=te[8],
                pmu=te[9],
                timeline_index=i,
            )

            i += 1

        return result


def start(
    builtins=True,
    profile_cpu=True,
    profile_memory=True,
    profile_timespan=False,
    instrumented_funcs={},
    timespan_selectors={},
    timespan_threshold=MAX_TIMESPAN_THRESHOLD,  # ms
):
    global _max_prefix_cache, _timespan_selectors

    if is_running():
        return

    if not isinstance(timespan_selectors, dict):
        raise BlackfireProfilerException(
            "timespan_selectors shall be an instance of 'dict'"
        )

    if profile_memory and TRACEMALLOC_AVAIL:
        if tracemalloc.is_tracing():
            get_logger().warn(
                "tracemalloc is already tracing. This could affect the accuracy "
                "of the results of Blackfire. Please disable tracemalloc"
                " tracing first."
            )
        tracemalloc.start()

    # in fact we can use this cache this forever but the idea is maybe the sys.path
    # changes in some way and it would be nice to see the effect between every
    # start/stop pair.
    _max_prefix_cache = {}

    _timespan_selectors = {}

    profile_threads = False
    if profile_memory:
        _bfext.set_memory_usage_callback(_get_memory_usage)
    if profile_timespan:
        _timespan_selectors = timespan_selectors
        _bfext.set_timespan_selector_callback(_fn_matches_timespan_selector)
    _bfext.start(
        builtins,
        profile_threads,
        profile_cpu,
        profile_memory,
        profile_timespan,
        instrumented_funcs,
        timespan_threshold,
    )


def stop():
    _bfext.stop()

    if TRACEMALLOC_AVAIL:
        tracemalloc.stop()


def get_traces(omit_sys_path_dirs=True):
    '''
    We need these _pause/_resume functions. That is because enumerating stats
    are simply calling Python from C and that again can trigger a call_event on
    profiler side which again can mutate the internal hash table that we are
    enumerating. This might causes duplicate stats(or deadlocks! in some cases)
    to be enumerated.
    '''
    _bfext._pause()
    try:
        traces = _TraceEnumerator(omit_sys_path_dirs)
        _bfext.enum_func_stats(traces._enum_func_cbk)
        _bfext.enum_timeline_stats(traces._enum_timeline_cbk)
        return traces.to_traceformat()
    finally:
        _bfext._resume()


@contextmanager
def run(builtins=False):
    start(builtins=builtins)
    try:
        yield
    finally:
        stop()


def is_running():
    return bool(_bfext.is_running())


def clear_traces():
    _bfext._pause()
    try:
        _bfext.clear_stats()
    finally:
        _bfext._resume()
