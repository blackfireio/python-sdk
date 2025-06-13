import os
from blackfire.exceptions import *
from blackfire import apm, generate_config
from blackfire.utils import get_logger, read_blackfireyml_content, html_escape
from blackfire.hooks.utils import try_enable_probe, try_end_probe, \
    try_validate_send_blackfireyml, try_apm_start_transaction, try_apm_stop_and_queue_transaction

log = get_logger(__name__)


def _headers_to_dict(headers):
    return dict((k, v) for (k, v) in headers)


def _catch_response_headers(environ, start_response):
    def _wrapper(status, headers, exc_info=None):
        try:
            environ['blackfire.status_code'] = int(status[:3])
            headers_dict = _headers_to_dict(headers)
            environ['blackfire.content_length'] = headers_dict.get(
                'Content-Length', 0
            )
        except Exception as e:
            log.exception(e)
        return start_response(status, headers, exc_info)

    return _wrapper

class _BlackfireJSProbeMiddleware(object):
    def __init__(self, app):
        self.app = app

    def _generate_snippet(self, environ):
        _JSTAG = (
            '<script async="true" data-browser-key="%s" '
            'data-sample-rate="%.6f" data-parent-trace-id="%s" '
            'data-transaction-name="%s" data-collector="%s" '
            'src="%s"></script>'
        )
        _JSTAG_NOSCRIPT = (
            '<noscript><img src="%s?k=%s" referrerpolicy="no-referrer-when-downgrade" style="display:none"/></noscript>'
        )

        try:
            browser_config = apm.get_browser_config()
            browser_probe_url = browser_config.get('browser-probe-url')
            if not browser_probe_url:
                return b""
            def _escape_config_val(name):
                val = browser_config.get(name, "")
                return html_escape(val)

            browser_key = _escape_config_val("browser-key")
            browser_sample_rate = _escape_config_val('browser-sample-rate')
            if browser_sample_rate != "":
                browser_sample_rate = int(browser_sample_rate)
            else:
                browser_sample_rate = 0
            trace_id = "" # TODO

            # _JSProbeMiddleware is the outermost, so we can try getting endpoint name
            view_name = environ.get('blackfire.endpoint', "")
            browser_collector_endpoint = _escape_config_val("browser-collector-endpoint")
            browser_pixel_url = _escape_config_val("browser-pixel-url")

            js_script = _JSTAG % (
                browser_key,
                browser_sample_rate,
                trace_id,
                view_name,
                browser_collector_endpoint,
                browser_probe_url
            )
            js_noscript = ''
            if browser_pixel_url:
                js_noscript = _JSTAG_NOSCRIPT % (browser_pixel_url, browser_key)
            return (js_script + js_noscript).encode("utf-8")
        except Exception as e:
            log.exception(e) # defensive
            return b""
    
    def __call__(self, environ, start_response):
        state = [None, None, None]
        def _capture(s, h, e=None):
            state[0], state[1], state[2] = s, h[:], e
            return lambda _=None: None # dummy write()

        app_iter = self.app(environ, _capture)

        status, headers, exc = state

        if headers is None:
            start_response(status, headers, exc)
            return app_iter
        
        hdict = {k.lower(): (i, v.lower()) for i, (k, v) in enumerate(headers)}
        ce = hdict.get("content-encoding", (None, ""))[1]
        if "html" not in hdict.get("content-type", (None, ""))[1] or \
            "chunked" in hdict.get("transfer-encoding", (None, ""))[1] or \
            ce not in ("", "identity"):
            start_response(status, headers, exc)
            return app_iter

        def _findTags(buf):
            buf = buf.lower()
            pos = buf.find(b"</head>")
            if pos == -1:
                pos = buf.find(b"</body>")
            return pos

        snippet = self._generate_snippet(environ)

        # this case is: there is no content-length header, and the body *MIGHT* be chunked
        # meaning user yielded the Response, so the content-length can be added by the 
        # WSGI server there will be no content-length header mutation so we can call
        # start_response early
        def _inject_chunked(app_iter):
            start_response(status, headers, exc)
            try:
                for chunk in app_iter:
                    # Note: We don't care the case where Chunks can separate the tags.
                    # Example: '<he' happens in Chunk1 and 'ad>' in Chunk2. This is 
                    # to reduce complexity as that case requires its own 
                    # buffering mechanism. Because: once we send Chunk1 back, we 
                    # can't add the snippet after the tag.
                    pos = _findTags(chunk)
                    if pos == -1: # no tag found, pass chunk
                        yield chunk
                    else:
                        chunk = chunk[:pos] + snippet + chunk[pos:]
                        yield chunk

                        # normally, we can use `yield from` here, but it will not 
                        # work with 2.7, so the only way is to iterate the rest 
                        # of the iterator, it has a bit perf. cost but same result
                        for remaining_chunk in app_iter:
                            yield remaining_chunk
                        # break, as we already sent the chunked response
                        break
            finally:
                if hasattr(app_iter, "close"):
                    app_iter.close()

        # if there is a content-length header, this means that the body is not chunked
        # and we can read whole body at once
        content_length_idx, content_length_val = hdict.get("content-length", (None, None))
        streaming_response = content_length_idx is None
        if not streaming_response:
            log.debug("Non-streaming response.")
            content_length_idx = int(content_length_idx)
            body = b"".join(app_iter)
            if hasattr(app_iter, "close"):
                app_iter.close()

            pos = _findTags(body)
            if pos != -1:
                body = body[:pos] + snippet + body[pos:]
                headers[content_length_idx] = (
                    "Content-Length",
                    str(int(content_length_val) + len(snippet)),
                )
            start_response(status, headers, exc)
            return [body]
        else:
            log.debug("Streaming response.")
            # we cannot yield here as yield+return is not valid in python 2.7 in 
            # same function and when we return like this, the app_iter will be 
            # consumed after a finally block
            return _inject_chunked(app_iter)


class BlackfireWSGIMiddleware(object):

    # Custom WSGI middlewares should override this value
    FRAMEWORK = 'Generic-WSGI'

    def __init__(self, app):
        # _app wraps the original app if browser monitoring is enabled. We need
        # this because there are middlewares that uses self.app (e.g: Odoo and Pyramid) 
        # for internal purposes. This way, we can keep the original app reference
        # and still use the wrapped app for browser monitoring.
        self._app = self.app = app
        if os.environ.get('BLACKFIRE_DISABLE_BROWSER_MONITORING') != '1':
            self._app = _BlackfireJSProbeMiddleware(self.app)
            log.debug("_BlackfireJSProbeMiddleware enabled.")

    def build_blackfire_yml_response(self, *args):
        '''This function is called to handle Blackfire builds. When a special build
        POST request received, this function gets called to build framework specific
        response that contains the blackfire.yaml file contents.
        '''
        raise NotImplemented('')

    def get_view_name(self, environ):
        '''This function is called at the start of wsgi.__call__ to retrieve the
        actual view function name. Usually, the view function is not retrieved by 
        here but we need this information to match controller-name field in APM
        key-pages.
        '''
        raise NotImplemented('')

    def get_app_response(self, *args, **kwargs):
        return self._app(*args, **kwargs)

    def enable_probe(self, query):
        return try_enable_probe(query)

    def end_probe(self, response, probe, probe_err, environ):
        if probe and probe_err is None:
            return try_end_probe(
                probe,
                response_status_code=environ.get('blackfire.status_code'),
                response_len=environ.get('blackfire.content_length', 0),
                controller_name=environ.get('blackfire.endpoint'),
                framework=self.FRAMEWORK,
                http_method=environ.get('REQUEST_METHOD'),
                http_uri=environ.get('REQUEST_URI'),
                https='1' if environ.get('wsgi.url_scheme') == 'https' else '',
                http_server_addr=environ.get('SERVER_NAME'),
                http_server_software=environ.get('SERVER_SOFTWARE'),
                http_server_port=environ.get('SERVER_PORT'),
                http_header_host=environ.get('HTTP_HOST'),
                http_header_user_agent=environ.get('HTTP_USER_AGENT'),
                http_header_x_forwarded_host=environ
                .get('HTTP_X_FORWARDED_HOST'),
                http_header_x_forwarded_proto=environ
                .get('HTTP_X_FORWARDED_PROTO'),
                http_header_x_forwarded_port=environ
                .get('HTTP_X_FORWARDED_PORT'),
                http_header_forwarded=environ.get('HTTP_FORWARDED'),
            )

    def _profile(self, query, environ, start_response):
        log.debug(
            "%s profile called. [query=%s]", self.__class__.__name__, query
        )

        # bf yaml asked?
        if environ['REQUEST_METHOD'] == 'POST':
            config = generate_config(query=query)
            if config.is_blackfireyml_asked():
                log.debug(
                    '%s autobuild triggered. Sending `.blackfire.yml` file.',
                    self.__class__.__name__,
                )
                blackfireyml_content = read_blackfireyml_content()
                agent_response = try_validate_send_blackfireyml(
                    config, blackfireyml_content
                )

                return self.build_blackfire_yml_response(
                    blackfireyml_content, agent_response, environ,
                    start_response
                )

        probe_err, probe = self.enable_probe(query)

        def _start_response(status, headers, exc_info=None):
            try:
                if probe_err:
                    if probe_err is not BlackfireInvalidSignatureError:
                        headers.append((probe_err[0], probe_err[1]))
                else:
                    headers.append(
                        (
                            'X-Blackfire-Response',
                            probe.get_agent_prolog_response().status_val
                        )
                    )
            except Exception as e:
                log.exception(e)

            return start_response(status, headers)

        response = None
        try:
            response = self.get_app_response(
                environ,
                _catch_response_headers(
                    environ, _start_response if probe else start_response
                )
            )
            return response
        finally:
            log.debug(
                "%s profile ended.",
                self.__class__.__name__,
            )

            self.end_probe(response, probe, probe_err, environ)

    def _trace(self, environ, start_response, extended=False):
        transaction = try_apm_start_transaction(extended=extended)
        try:
            response = self.get_app_response(
                environ, _catch_response_headers(environ, start_response)
            )
            return response
        finally:
            if transaction:
                try_apm_stop_and_queue_transaction(
                    controller_name=transaction.name
                    or environ.get('blackfire.endpoint'),
                    uri=environ.get('PATH_INFO'),
                    framework=self.FRAMEWORK,
                    http_host=environ.get('HTTP_HOST'),
                    method=environ.get('REQUEST_METHOD'),
                    response_code=environ.get('blackfire.status_code'),
                    stdout=environ.get('blackfire.content_length', 0),
                )

    def __call__(self, environ, start_response):
        # method/path_info are mandatory in WSGI spec.
        method = environ['REQUEST_METHOD']
        path_info = environ.get('PATH_INFO', '')  # defensive
        view_name = environ['blackfire.endpoint'] = self.get_view_name(environ)

        # profile
        query = environ.get('HTTP_X_BLACKFIRE_QUERY')
        if query:
            return self._profile(query, environ, start_response)

        # auto-profile
        # path_info is used for matching the key-page controller-name. The key is
        # always present as per WSGI spec and gives more consistent values while
        # switching between staging/prod servers.
        # See https://docs.djangoproject.com/en/4.0/ref/request-response/#django.http.HttpRequest.path_info
        # for more information
        # Also see: https://wsgi.readthedocs.io/en/latest/definitions.html#envvar-PATH_INFO
        trigger_auto_profile, key_page = apm.trigger_auto_profile(
            method, path_info, view_name
        )
        if trigger_auto_profile:
            log.debug("%s autoprofile triggered.", self.__class__.__name__)
            query = apm.get_autoprofile_query(method, path_info, key_page)
            if query:
                return self._profile(query, environ, start_response)
        
        # for monitoring, we need to check if uwsgi is running with threads-enabled
        # otherwise, the monitoring thread will not work properly. Note that import uwsgi
        # is only valid in uWSGI's request context
        try:
            import uwsgi
            if not uwsgi.opt.get("enable-threads"):
                log.warn("enable-threads option must be set to true for Blackfire Monitoring to work")
                return self.get_app_response(environ, start_response)
        except ImportError:
            pass

        # monitoring
        if apm.trigger_trace():
            return self._trace(
                environ, start_response, extended=apm.trigger_extended_trace()
            )

        return self.get_app_response(environ, start_response)
