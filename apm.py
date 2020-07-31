import random
import os
import _blackfire_profiler as _bfext
from blackfire.utils import get_logger, IS_PY3, json_prettify, run_in_thread_pool, ConfigParser
from blackfire import agent, DEFAULT_AGENT_SOCKET, DEFAULT_AGENT_TIMEOUT, DEFAULT_CONFIG_FILE
from blackfire.exceptions import BlackfireAPMException


class ApmConfig(object):

    def __init__(self):
        self.sample_rate = 1.0
        self.extended_sample_rate = 0.0
        self.key_pages = ()
        self.timespan_entries = ()
        self.fn_arg_entries = ()


class ApmProbeConfig(object):

    def __init__(self):
        self.agent_socket = os.environ.get(
            'BLACKFIRE_AGENT_SOCKET', DEFAULT_AGENT_SOCKET
        )
        self.agent_timeout = os.environ.get(
            'BLACKFIRE_AGENT_TIMEOUT', DEFAULT_AGENT_TIMEOUT
        )

        # read APM_ENABLED config from env.var > file.
        apm_enabled = 0
        config_file = DEFAULT_CONFIG_FILE
        if os.path.exists(config_file):
            config = ConfigParser()
            config.read(config_file)
            if 'blackfire' in config.sections():
                bf_section = dict(config.items('blackfire'))

                apm_enabled = int(bf_section.get('apm_enabled', '0').strip())

        self.apm_enabled = bool(
            int(os.environ.get('BLACKFIRE_APM_ENABLED', apm_enabled))
        )


# init shared configuration from the C extension, this data will persist among
# different interpreters in the same process
_apm_config = None
# init config for the APM for communicating with the Agent
_apm_probe_config = None

log = get_logger(__name__)


def initialize():
    global _apm_config, _apm_probe_config

    _apm_config = _bfext.get_or_set_ext_data("apm_config", ApmConfig())
    _apm_probe_config = _bfext.get_or_set_ext_data(
        "apm_probe_config", ApmProbeConfig()
    )

    log.debug(
        "APM Configuration initialized. [%s] [%s] [%s]",
        json_prettify(_apm_config.__dict__),
        json_prettify(_apm_probe_config.__dict__),
        os.getpid(),
    )


def trigger_trace():
    global _apm_config, _apm_probe_config

    return _apm_probe_config.apm_enabled and \
        _apm_config.sample_rate >= random.random()


def trigger_extended_trace():
    global _apm_config, _apm_probe_config

    return _apm_probe_config.apm_enabled and \
        _apm_config.extended_sample_rate >= random.random()


def _send_trace_async(data):
    agent_conn = agent.Connection(
        _apm_probe_config.agent_socket, _apm_probe_config.agent_timeout
    )

    try:
        agent_conn.connect()
        agent_conn.send(data)

        # verify agent responds success
        response_raw = agent_conn.recv()
        agent_resp = agent.BlackfireResponse().from_bytes(response_raw)
        if 'false' in agent_resp.status_val_dict['success']:
            raise BlackfireAPMException(agent_resp.status_val_dict['error'])

        # Update config if any configuration update received
        if len(agent_resp.args) or len(agent_resp.key_pages):
            new_apm_config = ApmConfig()
            try:
                new_apm_config.sample_rate = float(
                    agent_resp.args['sample-rate'][0]
                )
            except:
                pass
            try:
                new_apm_config.extended_sample_rate = float(
                    agent_resp.args['extended-sample-rate'][0]
                )
            except:
                pass

            new_apm_config.key_pages = tuple(agent_resp.key_pages)

            # update the process-wise global apm configuration. Once this is set
            # the new HTTP requests making initialize() will get this new config
            _bfext.set_ext_data("apm_config", new_apm_config)

        log.debug(
            "APM trace sent. [%s]",
            json_prettify(data),
        )

    # TODO: rm comment
    #except Exception as e:
    #    log.error("APM message could not be sent. [reason:%s]" % (e))
    finally:
        agent_conn.close()


def send_trace(request, **kwargs):
    data = """file-format: BlackfireApm
        sample-rate:{}
    """.format(_apm_config.sample_rate)
    for k, v in kwargs.items():
        if v:
            # convert `_` to `-` in keys. e.g: controller_name -> controller-name
            k = k.replace('_', '-')
            data += "%s: %s\n" % (k, v)
    data += "\n"

    if IS_PY3:
        data = bytes(data, 'ascii')

    # We should not have a blocking call in APM path. Do agent connection setup
    # socket send in a separate thread.
    run_in_thread_pool(_send_trace_async, args=(data, ))


def send_extended_trace(request, **kwargs):
    pass
