import os
import sys
from blackfire import probe
from blackfire.utils import get_logger

log = get_logger(__name__)


def format_exc_for_display():
    # filename:lineno and exception message
    _, exc_obj, exc_tb = sys.exc_info()
    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
    return "%s:%s %s" % (fname, exc_tb.tb_lineno, exc_obj)


def try_enable_probe(query):
    probe_err = None
    try:
        probe.initialize(query=query, _method="middleware")

        probe.enable()
    except Exception as e:
        # TODO: Is this really quote or urlencode?
        probe_err = ('X-Blackfire-Error', '101 ' + format_exc_for_display())
        log.exception(e)
    return probe_err


def try_end_probe(response_status_code, response_len, **kwargs):
    try:
        headers = {}
        headers['Response-Code'] = response_status_code
        headers['Response-Bytes'] = response_len
        _agent_status_val = probe._agent_conn.agent_response.status_val

        context_dict = {}
        for k, v in kwargs.items():
            if v:
                context_dict[k] = v
        headers['Context'] = context_dict

        probe.end(headers=headers)

        return ('X-Blackfire-Response', _agent_status_val)
    except:
        return ('X-Blackfire-Error', '101 ' + format_exc_for_display())


def add_probe_response_header(http_response, probe_response):
    http_response[probe_response[0]] = probe_response[1]


def reset_probe():
    probe.disable()
    probe.clear_traces()
