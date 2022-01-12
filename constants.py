import sys
import sysconfig
from blackfire.utils import get_logger

log = get_logger(__name__)


def _get_sys_config_params(*args):
    result = []
    for arg in args:
        v = sysconfig.get_config_var(arg)
        if v:
            result += [v.strip()]
    return " ".join(result)


def _on_except(func=None, return_val=None):

    def inner_func(func):

        def _wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except:
                return return_val

        return _wrapper

    return inner_func


class BlackfireConstants(object):
    '''
    This constants are sent back to the Agent in `Constants` headers and they appear
    as runtime.constants metric defs./scenarios...etc
    '''

    @classmethod
    def get(cls, val):
        fn = getattr(cls, val.lower(), None)
        if fn is None:
            log.error("Unsupported Blackfire-Const value. [%s]", val)
            return None

        return fn()

    # Constant definitions
    @classmethod
    @_on_except(return_val="0.0.0")
    def python_version(cls):
        return "%d.%d.%d" % (
            sys.version_info.major, sys.version_info.minor,
            sys.version_info.micro
        )

    @classmethod
    @_on_except()
    def python_debug_flag(cls):
        return bool(sysconfig.get_config_var('Py_DEBUG'))

    @classmethod
    @_on_except()
    def python_pgo_flag(cls):
        return '-fprofile-use' in _get_sys_config_params(
            'PY_CFLAGS', 'PY_CFLAGS_NODIST'
        )

    @classmethod
    @_on_except()
    def django_version(cls):
        import django
        return django.get_version()

    @classmethod
    @_on_except()
    def flask_version(cls):
        import flask
        return flask.__version__

    @classmethod
    @_on_except()
    def django_debug_flag(cls):
        from django.conf import settings
        return settings.DEBUG

    @classmethod
    @_on_except()
    def django_db_conn_max_age(cls):
        from django.db import connection
        return connection.settings_dict['CONN_MAX_AGE']

    @classmethod
    @_on_except()
    def flask_debug_flag(cls):
        from flask import current_app
        return current_app.debug

    @classmethod
    @_on_except()
    def is_flask_app(cls):
        # current_app will throw an error if not called from a context a request
        from flask import current_app
        return True

    @classmethod
    @_on_except()
    def is_django_app(cls):
        from django.conf import settings
        # configure() will throw error if Django app is configured properly
        settings.configure()
        return True
