import sys
from blackfire.utils import wrap, unwrap, get_logger, IS_PY3
from blackfire.hooks.sys import SysHooks

log = get_logger(__name__)


def patch():
    # already patched?
    if getattr(sys, '_blackfire_patch', False):
        return

    try:
        sys.exit = wrap(sys.exit, pre_func=SysHooks.sys_exit)

        # In Py2, stdout.write is a read-only attribute. To overcome this,
        # we change stdout to StringIO first and then monkey patch.
        old_stdout_write = old_stderr_write = None
        if not IS_PY3:
            # save current funcs as we need to call them as post_func because
            # we will change the stdout to be a StringIO
            old_stdout_write = sys.stdout.write
            old_stderr_write = sys.stderr.write

            from StringIO import StringIO
            sys.stdout = StringIO()
            sys.stderr = StringIO()

        sys.stdout.write = wrap(
            sys.stdout.write,
            pre_func=SysHooks.sys_stdout_write,
            post_func=old_stdout_write,
            orig=old_stdout_write
        )
        sys.stderr.write = wrap(
            sys.stderr.write,
            pre_func=SysHooks.sys_stderr_write,
            post_func=old_stderr_write,
            orig=old_stderr_write,
        )
        sys.excepthook = wrap(sys.excepthook, pre_func=SysHooks.sys_excepthook)

        setattr(sys, '_blackfire_patch', True)

        return True
    except Exception as e:
        log.exception(e)

    return False


def unpatch():
    if not getattr(sys, '_blackfire_patch', False):
        return

    unwrap(sys, "exit")
    unwrap(sys.stdout, "write")
    unwrap(sys.stderr, "write")
    unwrap(sys, "excepthook")

    setattr(sys, '_blackfire_patch', False)
