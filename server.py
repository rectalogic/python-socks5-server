import functools
import logging
import select
import socket
import struct
import sys
from enum import IntEnum
from socketserver import BaseRequestHandler, BaseServer, TCPServer, ThreadingMixIn
import typing as ta

logging.basicConfig()
log = logging.getLogger(__name__)

# Constants
SOCKS_VERSION = 5
RESERVED = 0
FAILURE = 0xFF
CONNECTION_TIMEOUT = 60 * 15 * 1000
COPY_LOOP_BUFFER_SIZE = 4096
BIND_PORT = (
    0  # set to 0 if we are binding an address, lets the kernel decide a free port
)

# Buffer sizes
GREETING_SIZE = 2
AUTH_METHOD_SIZE = 1
VERSION_SIZE = 1
CONN_NO_PORT_SIZE = 4
CONN_PORT_SIZE = 2
DOMAIN_SIZE = 1


class SocksCommand(IntEnum):
    CONNECT = 1
    BIND = 2
    UDP_ASSOCIATE = 3


class AuthMethod(IntEnum):
    NoAuth = 0
    GSSAPI = 1
    UsernamePassword = 2
    Invalid = 0xFF


class StatusCode(IntEnum):
    Success = 0
    GeneralFailure = 1
    NotAllowed = 2
    NetUnreachable = 3
    HostUnreachable = 4
    ConnRefused = 5
    TTLExpired = 6
    CommandNotSupported = 7
    AddressTypeNotSupported = 8


class AddressDataType(IntEnum):
    IPv4 = 1
    DomainName = 3
    IPv6 = 4


class SOCKS5ProxyServer(ThreadingMixIn, TCPServer):
    """Initialise the socket server"""

    def __init__(
        self,
        bind_address: str | None = None,
        port: int = 2080,
        listen_ip: str = "0.0.0.0",
    ):
        bind_addr = None
        if bind_address:
            # This should error out if invalid
            # This allows us to parse the address given by a user on the start of the server
            bind_addr_info = socket.getaddrinfo(
                bind_address,
                BIND_PORT,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
                flags=socket.AI_PASSIVE,
            )
            if len(bind_addr_info) > 0:
                bind_addr = bind_addr_info[0][4]  # Is picking first a good idea?
            else:
                log.fatal("Failed to resolve bind address")
                sys.exit(1)

        host_port_tuple = (listen_ip, port)
        super().__init__(
            host_port_tuple, functools.partial(SOCKS5ProxyHandler, bind_addr)
        )


class SOCKS5ProxyHandler(BaseRequestHandler):
    """The handler used for a request from a client.
    Make sure _bind is set in self.server (like in SOCKS5ProxyServer) if a custom server uses this handler
    in order to use binding for the request socket
    """

    def __init__(
        self,
        bind_address: str | None,
        request: socket.socket,
        client_address: ta.Any,
        server: BaseServer,
    ):
        self.bind_address = bind_address
        self._address_type = AddressDataType.IPv4
        self._remote: socket.socket|None = None
        super().__init__(request, client_address, server)

    def handle(self):
        log.info("Accepting connection from %s:%s" % self.client_address)

        # Handle the greeting
        # Greeting header
        header = self._recv(
            GREETING_SIZE, lambda: self._send_greeting_failure(AuthMethod.Invalid)
        )
        if header is None:
            return
        version, nmethods = struct.unpack("!BB", header)
        # Only accept SOCKS5
        if version != SOCKS_VERSION:
            self._send_greeting_failure(AuthMethod.NoAuth)
            return
        # We need at least one method
        if nmethods < 1:
            self._send_greeting_failure(AuthMethod.Invalid)
            return

        # Get available methods
        methods = self._get_available_methods(nmethods)
        log.debug(f"Received methods {methods}")

        # Accept only no auth
        if AuthMethod.NoAuth not in set(methods):
            self._send_greeting_failure(AuthMethod.Invalid)
            return

        # Choose an authentication method and send it to the client
        self._send(struct.pack("!BB", SOCKS_VERSION, AuthMethod.NoAuth))

        # Auth/greeting handled...
        log.debug("Successfully authenticated")

        # Handle the request
        conn_buffer = self._recv(
            CONN_NO_PORT_SIZE, lambda: self._send_failure(StatusCode.GeneralFailure)
        )
        if conn_buffer is None:
            return
        version, cmd, rsv, address_type = struct.unpack("!BBBB", conn_buffer)
        # Do this so we can send an address_type in our errors
        # We don't want to send an invalid one back in an error so we will handle an invalid address type first
        # Microsocks just always sends IPv4 instead
        if address_type not in (
            AddressDataType.IPv4,
            AddressDataType.IPv6,
            AddressDataType.DomainName,
        ):
            self._send_failure(StatusCode.AddressTypeNotSupported)
            return
        self._address_type = address_type

        if version != SOCKS_VERSION:
            self._send_failure(StatusCode.GeneralFailure)
            return
        if cmd != SocksCommand.CONNECT:  # We only support connect
            self._send_failure(StatusCode.CommandNotSupported)
            return
        if rsv != RESERVED:  # Malformed packet
            self._send_failure(StatusCode.GeneralFailure)
            return

        log.debug(f"Handling request with address type: {self._address_type}")

        if (
            self._address_type == AddressDataType.IPv4
            or self._address_type == AddressDataType.IPv6
        ):  # IPv4 or IPv6
            address_family = (
                socket.AF_INET
                if self._address_type == AddressDataType.IPv4
                else socket.AF_INET6
            )
            minlen = 4 if self._address_type == AddressDataType.IPv4 else 16
            raw = self._recv(
                minlen, lambda: self._send_failure(StatusCode.GeneralFailure)
            )  # Raw IP address bytes
            if raw is None:
                return
            # Convert the IP address from binary to text
            try:
                address = socket.inet_ntop(address_family, raw)
            except Exception:
                log.exception(f"Could not convert packed IP {raw} to string")
                self._send_failure(StatusCode.GeneralFailure)
                return
        elif self._address_type == AddressDataType.DomainName:  # Domain name
            domain_buffer = self._recv(
                DOMAIN_SIZE, lambda: self._send_failure(StatusCode.GeneralFailure)
            )
            if domain_buffer is None:
                return
            domain_length = domain_buffer[0]
            if domain_length > 255:  # Invalid
                self._send_failure(StatusCode.GeneralFailure)
            address = self._recv(
                domain_length, lambda: self._send_failure(StatusCode.GeneralFailure)
            )
            if address is None:
                return
        else:
            self._send_failure(StatusCode.AddressTypeNotSupported)
            return

        port_buffer = self._recv(
            CONN_PORT_SIZE, lambda: self._send_failure(StatusCode.GeneralFailure)
        )
        if port_buffer is None:
            return
        port = struct.unpack("!H", port_buffer)[0]

        # Translate our address and port into data from which we can create a socket connection
        try:
            remote_info = socket.getaddrinfo(
                address,
                port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
                flags=socket.AI_PASSIVE,
            )
            # Pick the first one returned, probably IPv6 if IPv6 is available or IPv4 if not
            # TO-DO: Try as many as possible in a loop instead of picking only the first returned
            remote_info = remote_info[0]
        except (
            Exception
        ):  # There's no suitable errorcode in RFC1928 for DNS lookup failure
            log.exception("DNS lookup")
            self._send_failure(StatusCode.GeneralFailure)
            return

        af, socktype, proto, _, sa = remote_info

        # Connect to the socket
        try:
            # Make the socket
            self._remote = socket.socket(af, socktype, proto)
            # Bind it to an IP
            if self.bind_address:
                self._remote.bind(self.bind_address)
            self._remote.connect(sa)
            bind_address = self._remote.getsockname()
            log.info(f"Connected to {address} {port}")

            # Get the bind address and port
            addr = socket.inet_pton(af, bind_address[0])
            port = bind_address[1]
            log.debug(f"Bind address {bind_address[0]} {port}")
        except Exception:
            log.exception("bind failed")
            # TO-DO: Get the actual failure code instead of giving ConnRefused each time
            self._send_failure(StatusCode.ConnRefused)
            return

        if af == socket.AF_INET:
            address_type = AddressDataType.IPv4
            address_format = "4s"
        elif af == socket.AF_INET6:
            address_type = AddressDataType.IPv6
            address_format = "16s"
        else:
            log.fatal("Unknown address family %d", af)
            self._send_failure(StatusCode.ConnRefused)
            return
        # TO-DO: Are the BND.ADDR and BND.PORT returned correct values?
        self._send(
            struct.pack(
                f"!BBBB{address_format}H",
                SOCKS_VERSION,
                StatusCode.Success,
                RESERVED,
                address_type,
                addr,
                port,
            )
        )

        # Run the copy loop
        self._copy_loop(self.request, self._remote)
        self._exit(True)

    def _send(self, data: bytes):
        """Convenience method to send bytes to a client"""
        return self.request.sendall(data)

    def _recv(self, bufsize, failure_method: ta.Callable | None = None) -> bytes | None:
        """Convenience method to receive bytes from a client
        If bufsize is less than the size of the data received, then failure_method is called with code as a parameter and kills the thread
        """
        buf = self.request.recv(bufsize)
        if len(buf) < bufsize:
            if failure_method:
                failure_method()
            else:
                self._exit()  # Kill thread if we aren't calling the failure methods (they already do this)
            return None
        return buf

    def _shutdown_client(self):
        """Convenience method to shutdown and close the connection with a client"""
        self.server.shutdown_request(self.request)

    def _exit(self, dontExit: bool = False):
        """Convenience method to exit the thread and cleanup any connections"""
        self._shutdown_client()
        if self._remote:
            # self._remote.shutdown(socket.SHUT_RDWR)
            self._remote.close()
        if not dontExit:
            sys.exit()

    def _get_available_methods(self, n: int) -> list[int]:
        """Receive the methods a client supported and return them as a list"""
        methods: list[int] = []
        for i in range(n):
            method = self._recv(
                AUTH_METHOD_SIZE,
                lambda: self._send_greeting_failure(AuthMethod.Invalid),
            )
            if method is not None:
                methods.append(ord(method))
        return methods

    def _send_greeting_failure(self, code: AuthMethod):
        """Convinence method to send a failure message to a client in the greeting stage"""
        self._send(struct.pack("!BB", SOCKS_VERSION, code))
        self._exit()

    def _send_failure(self, code: StatusCode):
        """Convinence method to send a failure message to a client in the socket stage"""
        self._send(
            struct.pack(
                "!BBBBIH", SOCKS_VERSION, code, RESERVED, self._address_type, 0, 0
            )
        )
        self._exit()

    def _copy_loop(self, client: socket.socket, remote: socket.socket):
        """Waits for network activity and forwards it to the other connection"""
        while True:
            # Wait until client or remote is available for read
            #
            # Alternatively use poll() instead of select() due to these reasons
            # https://github.com/rofl0r/microsocks/commit/31557857ccce5e4fdd2cfdae7ab640d589aa2b41
            # May not be ideal for a cross platform implementation however
            r, w, e = select.select([client, remote], [], [], CONNECTION_TIMEOUT)

            # Kill inactive/unused connections
            if not r and not w and not e:
                self._send_failure(StatusCode.TTLExpired)
                return

            for sock in r:
                try:
                    data = sock.recv(COPY_LOOP_BUFFER_SIZE)
                except Exception:
                    log.exception("Copy loop failed to read")
                    return

                if not data or len(data) <= 0:
                    return

                outfd = remote if sock is client else client
                try:
                    outfd.sendall(data)  # Python has its own sendall implemented
                except Exception:
                    log.exception("Copy loop failed to send all data")
                    return


if __name__ == "__main__":
    # TO-DO: Add CLI args for options
    # Add to seperate file?

    log.setLevel(logging.DEBUG)

    # Options are completely optional
    with SOCKS5ProxyServer() as server:
        server.serve_forever()
