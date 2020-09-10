class SysHooks(object):

    exit_code = 0
    stdout_len = 0
    stderr_len = 0

    @classmethod
    def sys_exit(cls, code):
        cls.exit_code = code

    @classmethod
    def sys_excepthook(cls, exc_type, exc_value, exc_traceback):
        cls.exit_code = 1

    @classmethod
    def sys_stdout_write(cls, s):
        cls.stdout_len += len(s)

    @classmethod
    def sys_stderr_write(cls, s):
        cls.stderr_len += len(s)
