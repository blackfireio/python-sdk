import os
import sys
from distutils.sysconfig import get_python_lib
from blackfire.utils import console_input
from blackfire import _install_bootstrap, _uninstall_bootstrap


def hello_world():
    print(
        '\nHello! Please do not mess with this complex function. You are warned!\n'
    )


if len(sys.argv) > 1:
    cmd = sys.argv[1]
    if cmd == 'install-bootstrap':
        q = "This command will install Python pre-interpreter hook files in %s. " \
            "By installing this pre-interpreter hook, you will be able to use " \
            "`blackfire run` without any change to your code. Learn more at " \
            "`https://blackfire.io/docs`.\n\nDo you confirm installation? [Y/n]: " % \
            (get_python_lib())
        r = console_input(q).lower().strip()
        if not r or r == 'y':
            _install_bootstrap()
    elif cmd == 'uninstall-bootstrap':
        q = "This command will uninstall Python pre-interpreter hook files." \
            "\n\nDo you confirm? [y/N]: "
        r = console_input(q).lower().strip()
        if r == 'y':
            _uninstall_bootstrap()
    elif cmd == 'hello-world':
        hello_world()
    else:
        raise Exception('There is no such command: (%s)' % (cmd))
