
from blackfire import probe
from blackfire.utils import get_logger
from blackfire.hooks.utils import try_enable_probe, try_end_probe, add_probe_response_header, reset_probe

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

        # TODO: We would like to see non-anonymized SQL?
        # query = str(sql)
        # if params:
        #     try:
        #         query = sql % params
        #     except:
        #         query = 'SQL formatting failed. [%s:%s]' % (sql, params)
        # query = query.replace('"', '')
        # query = query.replace('\'', '')

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
        if 'HTTP_X_BLACKFIRE_QUERY' in request.META:
            return self._profiled_request(request)

        response = self.get_response(request)
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

    def _profiled_request(self, request):
        log.debug("DjangoMiddleware._profiled_request called.")
        try:
            probe_err = try_enable_probe(request.META['HTTP_X_BLACKFIRE_QUERY'])

            if not probe_err:
                self._enable_sql_instrumentation()

            # let user/django exceptions propagate through
            response = self.get_response(request)

            if probe_err:
                add_probe_response_header(response, probe_err)
                return response

            probe_resp = try_end_probe(
                response_status_code=response.status_code,
                response_len=len(response.content),
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

            reset_probe()
