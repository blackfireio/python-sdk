import os
import sys
from blackfire import probe, generate_config, agent, apm
from blackfire.utils import get_logger, UC, unicode_or_bytes
from blackfire.exceptions import *

log = get_logger(__name__)


def format_exc_for_display(e):
    # filename:lineno and exception message
    try:
        _, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        return "%s:%s %s" % (fname, exc_tb.tb_lineno, exc_obj)
    except:
        # sometimes this fails with 'module' object has no attribute 'exc_info'
        # where there is a custom exception handler (Flask) In those cases we will
        # simply use the exception object
        return str(e)


def try_validate_send_blackfireyml(config, blackfireyml_content):
    try:
        agent_conn = agent.Connection(config.agent_socket, config.agent_timeout)
        agent_conn.connect(config=config)

        resp_line = str(agent_conn.agent_response.status_val)

        if blackfireyml_content is None:
            resp_line += '&no-blackfire-yaml'
        else:
            # convert .blackfire.yml contents to UTF-8 encoded string and get the
            # length according to that. Otherwise blackfire-yml-size we set here
            # might be inconsistent with Content-Length header
            blackfireyml_content = UC(blackfireyml_content)
            blackfireyml_content = unicode_or_bytes(blackfireyml_content)
            resp_line += '&blackfire-yml-size=%d' % (len(blackfireyml_content))

        return ('X-Blackfire-Response', resp_line)

    except Exception as e:
        log.exception(e)


def try_enable_probe(
    query, client_id=None, client_token=None, title=None, ctx_var=None
):
    probe_err = new_probe = None
    try:
        config = generate_config(
            query=query,
            client_id=client_id,
            client_token=client_token,
            title=title,
            ctx_var=ctx_var
        )
        new_probe = probe.Probe(config=config)
        new_probe.clear_traces()
        new_probe.enable()
    except BlackfireInvalidSignatureError:
        # do not send error if signature validation fails
        probe_err = BlackfireInvalidSignatureError
        log.error("Signature validation failed. [%s]", config)
    except Exception as e:
        # TODO: Is this really quote or urlencode?
        probe_err = ('X-Blackfire-Error', '101 ' + format_exc_for_display(e))
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

        # custom transaction name overrides controller name setting
        headers['controller-name'
                ] = new_probe.transaction_name or controller_name
        headers['framework'] = framework

        context_dict = {}
        for k, v in kwargs.items():
            if v:
                context_dict[k] = v
        headers['Context'] = context_dict

        new_probe.end(headers=headers)

        return ('X-Blackfire-Response', agent_status_val)
    except Exception as e:
        log.exception(e)
        return ('X-Blackfire-Error', '101 ' + format_exc_for_display(e))


def try_apm_start_transaction(**kwargs):
    try:
        return apm._start_transaction(**kwargs)
    except Exception as e:
        log.exception(e)


def try_apm_stop_and_queue_transaction(**kwargs):
    try:
        apm._stop_and_queue_transaction(**kwargs)
    except Exception as e:
        log.exception(e)


def add_probe_response_header(http_response, probe_response):
    # do not add any response header if signature is invalid
    if probe_response is BlackfireInvalidSignatureError:
        return
    http_response[probe_response[0]] = probe_response[1]
