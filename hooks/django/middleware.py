from blackfire.utils import get_logger
from blackfire.hooks.utils import try_enable_probe, add_probe_response_header
from blackfire.hooks.django.utils import get_current_view_name
from blackfire.hooks.wsgi import BlackfireWSGIMiddleware

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
        sql_formatted = sql_formatted.replace('%s', '?')

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


def _enable_sql_instrumentation():

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


def _disable_sql_instrumentation():

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


class BlackfireDjangoMiddleware(BlackfireWSGIMiddleware):
    FRAMEWORK = 'django'

    def __init__(self, get_response):
        self.get_response = get_response

    def build_blackfire_yml_response(
        self, blackfireyml_content, agent_response, *args
    ):
        from django.http import HttpResponse

        response = HttpResponse()
        if agent_response:  # send response if signature is validated
            response.content = blackfireyml_content or ''
            add_probe_response_header(response, agent_response)
        return response

    def get_view_name(self, environ):
        return get_current_view_name(environ['PATH'])

    def get_app_response(self, environ, *args, **kwargs):
        response = self.get_response(environ["blackfire.orig_request"])

        environ['blackfire.status_code'] = response.status_code
        environ['blackfire.content_length'] = len(response.content)

        return response

    def enable_probe(self, query):
        probe_err, probe = super(BlackfireDjangoMiddleware,
                                 self).enable_probe(query)
        if not probe_err:
            _enable_sql_instrumentation()
        return probe_err, probe

    def end_probe(self, response, probe, probe_err, environ):
        if probe is None:
            return

        if probe_err:
            add_probe_response_header(response, probe_err)
            return response

        try:
            probe_response = super(BlackfireDjangoMiddleware, self).end_probe(
                response, probe, probe_err, environ
            )

            add_probe_response_header(response, probe_response)
            return response
        finally:
            _disable_sql_instrumentation()

    def __call__(self, request):
        # setup a proper environ dict and pass the request to a normal
        # WSGI middleware
        request.META['REQUEST_METHOD'] = request.method
        request.META['PATH_INFO'] = request.path_info
        request.META['REQUEST_URI'] = request.META['PATH'] = request.path
        request.META['blackfire.orig_request'] = request
        return super(BlackfireDjangoMiddleware,
                     self).__call__(environ=request.META, start_response=None)
