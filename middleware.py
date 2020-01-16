import os
import sys
import traceback
from blackfire import probe
from blackfire.utils import quote
from django.db import connections


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


def enable_sql_instrumentation():

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

    for connection in connections.all():
        wrap_cursor(connection)


def disable_sql_instrumentation():

    def unwrap_cursor(connection):
        if hasattr(connection, "_blackfire_cursor"):
            del connection._blackfire_cursor
            del connection.cursor
            del connection.chunked_cursor

    for connection in connections.all():
        unwrap_cursor(connection)


class DjangoMiddleware(object):

    def __init__(self, get_response):
        self.get_response = get_response
        # One-time configuration and initialization.

    def __call__(self, request):
        if 'HTTP_X_BLACKFIRE_QUERY' in request.META:
            return self._profiled_response(request)

        response = self.get_response(request)
        return response

    def _profiled_response(self, request):

        def format_exc_for_display():
            # filename:lineno and exception message
            _, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return "%s:%s %s" % (fname, exc_tb.tb_lineno, exc_obj)

        probe_response = None
        try:
            try:
                query = request.META['HTTP_X_BLACKFIRE_QUERY']

                probe.initialize(query=query)

                probe.enable()
            except:
                # TODO: Is this really quote or urlencode?
                probe_response = (
                    'X-Blackfire-Error', '101 ' + format_exc_for_display()
                )

            # let user/django exceptions propagate through
            enable_sql_instrumentation()

            response = self.get_response(request)

            try:
                if not probe_response:
                    headers = {}
                    headers['Response-Code'] = response.status_code
                    headers['Response-Bytes'] = len(response.content)

                    context_dict = {
                        'http_method': request.method,
                        'http_uri': request.path,
                        'https': '1' if request.is_secure() else '',
                    }

                    # populate the context dict remaining items from META attr
                    meta_args = {
                        'SERVER_NAME': 'http_server_addr',
                        'SERVER_SOFTWARE': 'http_server_software',
                        'SERVER_PORT': 'http_server_port',
                        'HTTP_HOST': 'http_header_host',
                        'HTTP_USER_AGENT': 'http_header_user_agent',
                        'HTTP_X_FORWARDED_HOST': 'http_header_x_forwarded_host',
                        'HTTP_X_FORWARDED_PROTO':
                        'http_header_x_forwarded_proto',
                        'HTTP_X_FORWARDED_PORT': 'http_header_x_forwarded_port',
                        'HTTP_FORWARDED': 'http_header_forwarded',
                    }
                    for arg, key in meta_args.items():
                        value = request.META.get(arg)
                        if value:
                            context_dict[key] = value

                    headers['Context'] = context_dict
                    probe_response = (
                        'X-Blackfire-Response',
                        probe._agent_conn.agent_response.status_val
                    )

                    probe.end(headers=headers)
            except:
                probe_response = (
                    'X-Blackfire-Error', '101 ' + format_exc_for_display()
                )

            if probe_response:  # defensive
                response[probe_response[0]] = probe_response[1]

            return response
        finally:
            # code that will be run no matter what happened above
            disable_sql_instrumentation()

            probe.disable()
            probe.clear_traces()
