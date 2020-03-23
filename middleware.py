import os
import sys
import traceback
from blackfire import probe
from blackfire.utils import quote, get_logger


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


def format_exc_for_display():
    # filename:lineno and exception message
    _, exc_obj, exc_tb = sys.exc_info()
    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
    return "%s:%s %s" % (fname, exc_tb.tb_lineno, exc_obj)


def try_enable_probe(query):
    probe_err = None
    try:
        probe.initialize(query=query)

        probe.enable()
    except Exception as e:
        # TODO: Is this really quote or urlencode?
        probe_err = ('X-Blackfire-Error', '101 ' + format_exc_for_display())
        get_logger().exception(e)
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


def _add_probe_response_header(http_response, probe_response):
    http_response[probe_response[0]] = probe_response[1]


class FlaskMiddleware(object):

    def __init__(self, app):
        self.app = app
        self.wsgi_app = app.wsgi_app

        # TODO: Comment
        self._probe_err = None

    def __call__(self, environ, start_response):
        if 'HTTP_X_BLACKFIRE_QUERY' in environ:
            return self._profiled_request(
                environ=environ, start_response=start_response
            )
        return self.wsgi_app(environ, start_response)

    def _process_profiled_response(self, sender, response, **extra):
        get_logger().debug("FlaskMiddleware.finish_response signal called.")

        import flask
        request = flask.request

        # When signal is registered we might received other events from other
        # requests. Look at the request object of the current response to determine
        # for finishing the profile session
        if 'HTTP_X_BLACKFIRE_QUERY' not in request.environ:
            return

        try:
            if self._probe_err:
                _add_probe_response_header(response.headers, self._probe_err)
                return

            probe_resp = try_end_probe(
                response_status_code=response.status_code,
                response_len=response.headers['Content-Length'],
                http_method=request.method,
                http_uri=request.path,
                https='1' if request.is_secure else '',
                http_server_addr=request.environ.get('SERVER_NAME'),
                http_server_software=request.environ.get('SERVER_SOFTWARE'),
                http_server_port=request.environ.get('SERVER_PORT'),
                http_header_host=request.environ.get('HTTP_HOST'),
                http_header_user_agent=request.environ.get('HTTP_USER_AGENT'),
                http_header_x_forwarded_host=request.environ
                .get('HTTP_X_FORWARDED_HOST'),
                http_header_x_forwarded_proto=request.environ
                .get('HTTP_X_FORWARDED_PROTO'),
                http_header_x_forwarded_port=request.environ
                .get('HTTP_X_FORWARDED_PORT'),
                http_header_forwarded=request.environ.get('HTTP_FORWARDED'),
            )

            _add_probe_response_header(response.headers, probe_resp)
        except Exception as e:
            # signals run in the context of app. Do not fail app code on any error
            get_logger().exception(e)

    def _connect_req_finished_signal(self):
        # we are using request_finished because if we use start_response callback
        # to modify response headers, because end() shall be called when view has been called.
        # TODO: More comment
        try:
            from flask import request_finished
            request_finished.connect(
                self._process_profiled_response, sender=self.app
            )
        except Exception as e:
            get_logger().exception(e)

    def _disconnect_req_finished_signal(self):
        try:
            from flask import request_finished
            request_finished.disconnect(
                self._process_profiled_response, self.app
            )
        except Exception as e:
            get_logger().exception(e)

    def _profiled_request(self, environ, start_response):
        get_logger().debug("FlaskMiddleware._profiled_request called.")
        try:
            self._probe_err = try_enable_probe(
                environ['HTTP_X_BLACKFIRE_QUERY']
            )
            if not self._probe_err:
                self._connect_req_finished_signal()

            resp = self.wsgi_app(environ, start_response)
            return resp

        finally:
            get_logger().debug("FlaskMiddleware._profiled_request ended.")

            self._disconnect_req_finished_signal()

            self._probe_err = None

            probe.disable()
            probe.clear_traces()


class DjangoMiddleware(object):

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
            get_logger().exception(e)

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
            get_logger().exception(e)

    def _profiled_request(self, request):
        get_logger().debug("DjangoMiddleware._profiled_request called.")
        try:
            probe_err = try_enable_probe(request.META['HTTP_X_BLACKFIRE_QUERY'])

            if not probe_err:
                self._enable_sql_instrumentation()

            # let user/django exceptions propagate through
            response = self.get_response(request)

            if probe_err:
                _add_probe_response_header(response, probe_err)
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

            _add_probe_response_header(response, probe_resp)
            return response

        finally:
            get_logger().debug("DjangoMiddleware._profiled_request ended.")

            # code that will be run no matter what happened above
            self._disable_sql_instrumentation()

            probe.disable()
            probe.clear_traces()
