import os
import sys
from blackfire import probe, generate_config
from blackfire.utils import get_logger

log = get_logger(__name__)


def format_exc_for_display():
    # filename:lineno and exception message
    _, exc_obj, exc_tb = sys.exc_info()
    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
    return "%s:%s %s" % (fname, exc_tb.tb_lineno, exc_obj)


def try_enable_probe(query):
    probe_err = new_probe = None
    try:
        config = generate_config(query=query)
        new_probe = probe.Probe(config=config)
        new_probe.enable()
    except Exception as e:
        # TODO: Is this really quote or urlencode?
        probe_err = ('X-Blackfire-Error', '101 ' + format_exc_for_display())
        log.exception(e)
    return probe_err, new_probe


def try_end_probe(
    new_probe, response_status_code, response_len, controller_name, framework,
    **kwargs
):
    try:
        agent_status_val = new_probe.get_agent_prolog_response().status_val

        headers = {}
        headers['Response-Code'] = response_status_code
        headers['Response-Bytes'] = response_len
        headers['controller-name'] = controller_name
        headers['framework'] = framework

        context_dict = {}
        for k, v in kwargs.items():
            if v:
                context_dict[k] = v
        headers['Context'] = context_dict

        new_probe.end(headers=headers)

        return ('X-Blackfire-Response', agent_status_val)
    except:
        return ('X-Blackfire-Error', '101 ' + format_exc_for_display())


def add_probe_response_header(http_response, probe_response):
    http_response[probe_response[0]] = probe_response[1]
