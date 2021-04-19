import time
import platform
from blackfire import probe, apm, VERSION, generate_config
from blackfire.utils import get_logger, get_probed_runtime, read_blackfireyml_content
from blackfire.hooks.utils import try_enable_probe, try_end_probe, \
    add_probe_response_header, try_validate_send_blackfireyml
from blackfire.hooks.django.utils import get_current_view_name

log = get_logger(__name__)


class _DjangoCursorWrapper:

    def __init__(self, cursor):
        self.cursor = cursor

    def on_query(self, method, sql, params, sql_formatted):
        try:
            return method(sql, params)
        finally:
            pass

    def _on_pre_query(self, method, sql, params):
        # Do some formatting here and call the real instrumented func
        sql_formatted = sql
        sql_formatted = sql_formatted.replace('"', '')
        sql_formatted = sql_formatted.replace('\'', '')
        self.on_query(method, sql, params, sql_formatted)

    def callproc(self, procname, params=None):
        return self._on_pre_query(self.cursor.callproc, procname, params)

    def execute(self, sql, params=None):
        return self._on_pre_query(self.cursor.execute, sql, params)

    def executemany(self, sql, param_list):
        return self._on_pre_query(self.cursor.executemany, sql, param_list)

    def __getattr__(self, attr):
        return getattr(self.cursor, attr)

    def __iter__(self):
        return iter(self.cursor)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()


class BlackfireDjangoMiddleware(object):

    def __init__(self, get_response):
        self.get_response = get_response
        # One-time configuration and initialization.

    def __call__(self, request):
        # bf yaml asked?
        if request.method == 'POST':
            if 'HTTP_X_BLACKFIRE_QUERY' in request.META:
                config = generate_config(
                    query=request.META['HTTP_X_BLACKFIRE_QUERY']
                )
                if config.is_blackfireyml_asked():
                    blackfireyml_content = read_blackfireyml_content()
                    agent_response = try_validate_send_blackfireyml(
                        config, blackfireyml_content
                    )
                    from django.http import HttpResponse

                    response = HttpResponse()
                    if agent_response:  # send response if signature is validated
                        response.content = blackfireyml_content or ''
                        add_probe_response_header(response, agent_response)

                    return response

        # regular profile
        if 'HTTP_X_BLACKFIRE_QUERY' in request.META:
            return self._profiled_request(
                request, request.META['HTTP_X_BLACKFIRE_QUERY']
            )

        # auto-profile triggered?
        trigger_auto_profile, key_page = apm.trigger_auto_profile(
            request.method, request.path, get_current_view_name(request)
        )
        if trigger_auto_profile:
            log.debug("DjangoMiddleware autoprofile triggered.")
            query = apm.get_autoprofile_query(
                request.method, request.path, key_page
            )

            return self._profiled_request(request, query)

        if apm.trigger_trace():
            return self._apm_trace(
                request, extended=apm.trigger_extended_trace()
            )

        # no instrumentation
        response = self.get_response(request)
        return response

    def _apm_trace(self, request, extended=False):
        apm.enable(extended)
        t0 = time.time()
        try:
            response = self.get_response(request)
        finally:
            mu, pmu = apm.get_traced_memory()
            apm.disable()
            now = time.time()
            elapsed_wt_usec = int((now - t0) * 1000000)
            apm.send_trace(
                request,
                extended,
                controller_name=get_current_view_name(request),
                wt=elapsed_wt_usec,
                mu=mu,
                pmu=pmu,
                timestamp=now,
                uri=request.path,
                framework="django",
                capabilities="trace",
                host=request.META.get('HTTP_HOST'),
                method=request.method,
                os=platform.system(),
                language="python",
                runtime=get_probed_runtime(),
                response_code=response.status_code,
                stdout=len(response.content),
                http_method=request.method,
                version=VERSION,
            )
        return response

    def _enable_sql_instrumentation(self):

        def wrap_cursor(connection):
            if not hasattr(connection, "_blackfire_cursor"):
                connection._blackfire_cursor = connection.cursor
                connection._blackfire_chunked_cursor = connection.chunked_cursor

                def cursor(*args, **kwargs):
                    return _DjangoCursorWrapper(
                        connection._blackfire_cursor(*args, **kwargs)
                    )

                def chunked_cursor(*args, **kwargs):
                    return _DjangoCursorWrapper(
                        connection._blackfire_chunked_cursor(*args, **kwargs)
                    )

                connection.cursor = cursor
                connection.chunked_cursor = chunked_cursor
                return cursor

        from django.db import connections
        try:
            for connection in connections.all():
                wrap_cursor(connection)
        except Exception as e:
            log.exception(e)

    def _disable_sql_instrumentation(self):

        def unwrap_cursor(connection):
            if hasattr(connection, "_blackfire_cursor"):
                del connection._blackfire_cursor
                del connection.cursor
                del connection.chunked_cursor

        from django.db import connections
        try:
            for connection in connections.all():
                unwrap_cursor(connection)
        except Exception as e:
            log.exception(e)

    def _profiled_request(self, request, query):
        log.debug("DjangoMiddleware._profiled_request called. [query=%s]",
            query)

        try:
            probe_err, new_probe = try_enable_probe(query)
            if not probe_err:
                self._enable_sql_instrumentation()

            # let user/django exceptions propagate through
            response = self.get_response(request)

            if probe_err:
                add_probe_response_header(response, probe_err)
                return response

            probe_resp = try_end_probe(
                new_probe,
                response_status_code=response.status_code,
                response_len=len(response.content),
                controller_name=get_current_view_name(request),
                framework="django",
                http_method=request.method,
                http_uri=request.path,
                https='1' if request.is_secure() else '',
                http_server_addr=request.META.get('SERVER_NAME'),
                http_server_software=request.META.get('SERVER_SOFTWARE'),
                http_server_port=request.META.get('SERVER_PORT'),
                http_header_host=request.META.get('HTTP_HOST'),
                http_header_user_agent=request.META.get('HTTP_USER_AGENT'),
                http_header_x_forwarded_host=request.META
                .get('HTTP_X_FORWARDED_HOST'),
                http_header_x_forwarded_proto=request.META
                .get('HTTP_X_FORWARDED_PROTO'),
                http_header_x_forwarded_port=request.META
                .get('HTTP_X_FORWARDED_PORT'),
                http_header_forwarded=request.META.get('HTTP_FORWARDED'),
            )

            add_probe_response_header(response, probe_resp)
            return response

        finally:
            log.debug("DjangoMiddleware._profiled_request ended.")

            # code that will be run no matter what happened above
            self._disable_sql_instrumentation()

            if new_probe:
                new_probe.disable()
                new_probe.clear_traces()
