import ssl
import socket
from blackfire.utils import wrap, unwrap, get_logger, IS_PY3
from blackfire.hooks import nw

log = get_logger(__name__)

_orig_socket_class = None

# we hook _socket.socket for Python2 as socket.socket does not completely cover
# all paths leading to nw_out/nw_in. See _fileobject class for example. For Py3,
# deriving from socket.socket is enough. Note that, SSL sockets use a different
# path and we have different hooks for those in ssl.py
if IS_PY3:
    WRAP_BASE_CLASS = socket.socket
else:
    WRAP_BASE_CLASS = socket._socket.socket


class _WrappedSocket(WRAP_BASE_CLASS):

    def recv(self, *args, **kwargs):
        result = super(_WrappedSocket, self).recv(*args, **kwargs)

        try:  # defensive
            nw.get_counters().i += len(result)
        except:
            pass
        return result

    def recv_into(self, *args, **kwargs):
        result = super(_WrappedSocket, self).recv_into(*args, **kwargs)

        try:  # defensive
            nw.get_counters().i += int(result)
        except:
            pass
        return result

    def recv_from(self, *args, **kwargs):
        result = super(_WrappedSocket, self).recv_from(*args, **kwargs)

        try:  # defensive
            # first item is a string or bytes representing the data received
            nw.get_counters().i += len(result[0])
        except:
            pass
        return result

    def sendall(self, *args, **kwargs):
        result = super(_WrappedSocket, self).sendall(*args, **kwargs)

        # update nw_out after socket operation finished successfully
        try:  # defensive
            nw.get_counters().o += len(args[0])
        except:
            pass
        return result

    def sendto(self, *args, **kwargs):
        result = super(_WrappedSocket, self).sendto(*args, **kwargs)

        try:  # defensive
            nw.get_counters().o += int(result)
        except:
            pass
        return result

    def send(self, *args, **kwargs):
        result = super(_WrappedSocket, self).send(*args, **kwargs)

        try:  # defensive
            nw.get_counters().o += int(result)
        except:
            pass
        return result


def _ssl_sock_read(*args, **kwargs):
    """
    From ssl.SSLSocket.read docstring:
    
    > Read up to 'len' bytes from the SSL object and return them.
      If 'buffer' is provided, read into this buffer and return the number of
      bytes read.
      So, it is possible that ssl_read returns an integer or a byte/string.
    """
    try:
        result = kwargs.pop("_result")
        if isinstance(result, int):
            nw.get_counters().i += result
        else:
            nw.get_counters().i += len(result)
    except:
        pass


def _ssl_sock_write(*args, **kwargs):
    # ssl.SSLSocket.write returns the number of bytes written
    try:
        nw.get_counters().o += kwargs.pop("_result")
    except:
        pass


def patch():
    global _orig_socket_class

    # already patched?
    if getattr(socket, '_blackfire_patch', False):
        return

    try:
        # Although we could choose to use wrap() to monkey patch individual
        # socket functions, we did not go that way. Py 2.7 uses a Wrapper class
        # for the socket class which defines socket methods as __slots__. This makes
        # socket methods read-only. That is the reason why we chose to wrap the
        # class, instead
        if IS_PY3:
            _orig_socket_class = socket.socket
            socket.socket = _WrappedSocket
        else:
            _orig_socket_class = socket._realsocket
            socket._realsocket = _WrappedSocket

        # ssl module uses these SSLSocket.read/write functions to read/write
        # to/from a SSL socket. They are wrappers for the _ssl.c C extension
        # which is again a wrapper for openssl.
        ssl.SSLSocket.read = wrap(
            ssl.SSLSocket.read,
            post_func=_ssl_sock_read,
            call_post_func_with_result=True
        )
        ssl.SSLSocket.write = wrap(
            ssl.SSLSocket.write,
            post_func=_ssl_sock_write,
            call_post_func_with_result=True
        )

        setattr(socket, '_blackfire_patch', True)

        log.debug('nw modules patched.')

        return True
    except Exception as e:
        log.exception(e)

    return False


def unpatch():
    global _orig_socket_class

    if not getattr(socket, '_blackfire_patch', False):
        return

    unwrap(ssl.SSLSocket, "read")
    unwrap(ssl.SSLSocket, "write")

    if _orig_socket_class:  # defensive
        if IS_PY3:
            socket.socket = _orig_socket_class
        else:
            socket._realsocket = _orig_socket_class

    setattr(socket, '_blackfire_patch', False)
