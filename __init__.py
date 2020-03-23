import re
import io
import os
import sys
import traceback
from blackfire.utils import *
from distutils.sysconfig import get_python_lib

__all__ = ['BlackfireConfiguration', 'VERSION', 'process_bootstrap']

ext_dir = os.path.dirname(os.path.abspath(__file__))
with io.open(os.path.join(ext_dir, 'VERSION')) as f:
    VERSION = f.read().strip()


def _uninstall_bootstrap():
    site_packages_dir = get_python_lib()
    bootstrap_pth_file = os.path.join(
        site_packages_dir, 'zzz_blackfire_bootstrap.pth'
    )
    bootstrap_file = os.path.join(site_packages_dir, '_blackfire_bootstrap.py')

    if os.path.exists(bootstrap_pth_file):
        os.remove(bootstrap_pth_file)
    if os.path.exists(bootstrap_file):
        os.remove(bootstrap_file)

    print("The pre-interpreter hook files has been uninstalled.")


def _install_bootstrap():
    # add zzz_bootstrap.pth to site-packages dir for the init code. This is to
    # run code at pre-interpreter startup. This is especially needed for 'blackfire run'
    # cmd as we will enable profiler if BLACKFIRE_QUERY is in env. vars. There seems to be
    # only 2 ways to do this, which are also hecky. Python has no documented way of
    # doing these:
    #   1/ Add sitecustomize.py or modify if there is an existing one,
    #   2/ Add a custom .pth file to site-packages dir
    # We selected option 2 as it is nearly impossible to revert the changes we made
    # to the orig. sitecustomize on uninstall. So, the second way is cleaner
    # at least for uninstall operations. There are also other libs choosing this
    # approach. See: https://nedbatchelder.com/blog/201001/running_code_at_python_startup.html
    site_packages_dir = None
    try:
        site_packages_dir = get_python_lib()
        # generate the .pth file to be loaded at startup
        bootstrap_pth_file = os.path.join(
            site_packages_dir, 'zzz_blackfire_bootstrap.pth'
        )
        with open(bootstrap_pth_file, "w") as f:
            f.write("import _blackfire_bootstrap\n")
        # generate the .py file that will be imported *safely* from the .pth file.
        # This is to ensure even blackfire is uninstalled from the system this import
        # fail will not be affecting the interpreter.
        bootstrap_file = os.path.join(
            site_packages_dir, '_blackfire_bootstrap.py'
        )
        with open(bootstrap_file, "w") as f:
            f.write(
                "try:\n"
                "    import blackfire; blackfire.process_bootstrap();\n"
                "except:\n"
                "    pass\n"
            )

        print(
            "The pre-interpreter hook files has been installed. These files can "
            "be removed by running `python -m uninstall-bootstrap`.\n\nYou can try "
            "blackfire by running `blackfire run %s -m blackfire hello-world`" %
            (os.path.basename(sys.executable).strip())
        )

    except Exception as e:
        print(
            "Exception occurred while installing pre-interpreter hooks files to %s."
            "'blackfire run' command might not work properly.[exc=%s]" %
            (site_packages_dir, e)
        )


def process_bootstrap():
    query = os.environ.get('BLACKFIRE_QUERY', None)
    if query:
        del os.environ['BLACKFIRE_QUERY']
        try:
            from blackfire.probe import initialize, enable
            initialize(query=query)
            enable(end_at_exit=True)
        except:
            # As this is called in import time, tracebacks cannot be seen
            # this is to ensure traceback is available if exception occurs
            traceback.print_exc()


class BlackfireConfiguration(object):

    def __init__(self, query, **kwargs):
        """
        query: is the BLACKFIRE_QUERY url encoded string that contains the signed params
        signature ...etc.
        """

        for k, v in kwargs.items():
            setattr(self, k, v)

        matches = re.split('(?:^|&)signature=(.+?)(?:&|$)', query, 2)

        self.challenge = matches[0]
        self.signature = matches[1]
        self.args_raw = matches[2]

        self.args = dict(parse_qsl(self.args_raw))

    def __repr__(self):
        import json
        return json.dumps(self.__dict__, indent=4)

    def __getattribute__(self, name):
        value = None
        try:
            value = object.__getattribute__(self, name)
        except AttributeError:
            raise AttributeError(
                'BlackfireConfiguration object has no attribute=%s.' % (name)
            )

        return value
