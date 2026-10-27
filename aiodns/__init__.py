"""DNSpy: an async DNS resolver, message codec, and inspector.

Two things live here that every other module reaches for: the logging posture,
and the socket options used to keep UDP datagrams from being fragmented.

**Logging.** A library must not configure logging for its host application, and
must not be silent either; the usual convention is to attach a
:class:`logging.NullHandler` to the top-level logger and let the application
decide. Previously each protocol object built its own ``logging.Logger(...)``
and attached a shared module-level :data:`console` handler to it, so importing
DNSpy and constructing a resolver caused output no matter what the application
had configured, and every extra object re-attached the same handler until each
line printed twice. ``console`` is still exported for anyone who was using it,
but it is no longer attached to anything.

**Path MTU discovery.** ``IP_MTU_DISCOVER``/``IP_PMTUDISC_DO`` are Linux
``IP``-level socket options (numbers 10 and 2). Setting them hard from
``connection_made`` raised :exc:`OSError` on any other platform -- on Windows
the option does not exist -- which means a resolver or server that worked on the
developer's box crashed at the first callback elsewhere. The values now come
from :mod:`socket` where available, are ``None`` where not, and callers gate on
:data:`PMTUD_SUPPORTED`.

This matters for DNS specifically because a response that exceeds the path MTU
gets fragmented, and fragment reassembly failure looks identical to packet loss
-- which is how an EDNS(0)-sized answer (RFC 6891 section 6.2.5) turns into a
timeout. Asking the kernel not to fragment makes the failure visible instead.
"""

import logging
import socket

__author__ = "b1tninja"
__version__ = "0.1.0"

#: ``IP_MTU`` socket option: query the path MTU of a connected socket.
IP_MTU = getattr(socket, "IP_MTU", 14)

#: ``IP_MTU_DISCOVER`` socket option -- Linux only (``None`` elsewhere).
IP_MTU_DISCOVER = getattr(socket, "IP_MTU_DISCOVER", None)

#: ``IP_PMTUDISC_DO``: do PMTU discovery and refuse to fragment.
IP_PMTUDISC_DO = getattr(socket, "IP_PMTUDISC_DO", None)

#: Whether this platform understands the PMTUD option pair at all.
PMTUD_SUPPORTED = IP_MTU_DISCOVER is not None and IP_PMTUDISC_DO is not None


def enable_path_mtu_discovery(transport, log=None) -> bool:
    """Ask the kernel not to fragment this socket's datagrams.

    Returns whether the option was actually set. Both the resolver and the
    server call this from ``connection_made``, and neither may treat failure as
    fatal: the option is Linux-specific, the socket may be IPv6 (where the
    equivalent is ``IPV6_MTU_DISCOVER``, a different number), and a restrictive
    container may refuse the call altogether. An earlier version called
    :meth:`~socket.socket.setsockopt` unguarded, which meant a datagram
    transport could not even open on Windows.

    :param transport: the asyncio transport whose socket should be adjusted.
    :param log: optional logger for a debug-level note about what happened.
    """
    sock = transport.get_extra_info("socket")
    if sock is None:
        return False
    if not PMTUD_SUPPORTED:
        if log is not None:
            log.debug("pmtud_unavailable(option=IP_MTU_DISCOVER platform_supported=False)")
        return False
    try:
        sock.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)
    except OSError as exc:
        if log is not None:
            log.debug("pmtud_failed(err=%s)", exc)
        return False
    return True


#: A ready-made stderr handler, for scripts that want DNSpy's messages without
#: configuring :mod:`logging`. Attaching handlers is the application's job.
console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
console.setFormatter(logging.Formatter("%(name)-12s: %(levelname)-8s %(message)s"))

# Library logging posture: silence unless the application opts in.
logging.getLogger(__name__).addHandler(logging.NullHandler())

__all__ = [
    "IP_MTU",
    "IP_MTU_DISCOVER",
    "IP_PMTUDISC_DO",
    "PMTUD_SUPPORTED",
    "console",
    "__version__",
]
