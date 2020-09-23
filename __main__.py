import os
from distutils.sysconfig import get_python_lib
from blackfire.utils import console_input
from blackfire import _install_bootstrap, _uninstall_bootstrap
import argparse


def get_parser():
    parser = argparse.ArgumentParser(description="This command will [un]install Python pre-interpreter hook files." \
            "By installing this pre-interpreter hook, you will be able to use " \
            "`blackfire run` without any change to your code. Learn more at https://blackfire.io/docs.")

    parser.add_argument('operation', choices=['install-bootstrap', 'uninstall-bootstrap', 'hello-world'], help="Operation to perform.")    

    parser.add_argument('--site-packages-dir', action='store', default=None, help="Overrides python's `get_python_lib()` reported directory for site-packages-dir installation.")

    return parser

def hello_world():
    print(
        '\nHello! Please do not mess with this complex function. You are warned!\n'
    )

options = get_parser().parse_args()


cmd = options.operation
if cmd == 'install-bootstrap':
    q = "Do you confirm installation? [Y/n]: " 
    r = console_input(q).lower().strip()
    if not r or r == 'y':
        _install_bootstrap(override_site_packages_dir=options.site_packages_dir)
elif cmd == 'uninstall-bootstrap':
    q = "This command will uninstall Python pre-interpreter hook files." \
        "\n\nDo you confirm? [y/N]: "
    r = console_input(q).lower().strip()
    if r == 'y':
        _uninstall_bootstrap(options.site_packages_dir)
elif cmd == 'hello-world':
    hello_world()
else:
    raise Exception('There is no such command: (%s)' % (cmd))
