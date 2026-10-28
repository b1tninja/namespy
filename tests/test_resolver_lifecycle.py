"""Closing a resolver: the socket asyncio handed it, and the one it opened itself.

A ``RecursiveResolver`` ends up holding two datagram transports -- the endpoint
asyncio attached it to, and a private IPv6 one it creates for AAAA glue -- plus
whatever queries are waiting on answers that may never arrive. None of those
release themselves, and the mode this project is used in for measurement is the
one that builds resolvers in a loop, where an unclosed socket is a descriptor
leak with a ``ResourceWarning`` attached. These tests pin that ``async with`` and
``aclose()`` actually let go, including down the error path.
"""

import asyncio

import pytest

from namespy.resolver import RecursiveResolver


class _RecordingTransport:
    """A transport that only remembers whether it was closed."""

    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True

    def get_extra_info(self, name, default=None):
        return default


def _attached(**transports):
    """A resolver already connected, with *transports* in place of real sockets.

    ``connection_made`` is deliberately not called: it would start the real IPv6
    endpoint bring-up this test has no business performing.
    """
    resolver = RecursiveResolver()
    for name, transport in transports.items():
        setattr(resolver, name, transport)
    return resolver


async def test_aclose_closes_both_sockets():
    endpoint, v6 = _RecordingTransport(), _RecordingTransport()
    resolver = _attached(transport=endpoint, transport_v6=v6)

    await resolver.aclose()

    assert endpoint.closed, "the endpoint socket asyncio handed over stays open otherwise"
    assert v6.closed, "the private IPv6 socket is nobody's to close but the resolver's"
    assert resolver.transport is None
    assert resolver.transport_v6 is None


async def test_async_with_releases_the_socket_on_the_error_path():
    endpoint = _RecordingTransport()
    resolver = _attached(transport=endpoint)

    with pytest.raises(RuntimeError, match="the caller"):
        async with resolver:
            raise RuntimeError("the caller's problem, still the caller's")

    assert endpoint.closed


async def test_aclose_fails_what_is_still_waiting():
    """A query in flight must not be left awaiting a response that will never come.

    Cancelling the future instead would surface as ``CancelledError`` inside
    whoever awaits it -- and under ``asyncio.wait_for`` that reads as though the
    *caller's* task had been cancelled, which is the wrong story about who is
    shutting down.
    """
    resolver = RecursiveResolver()
    future = asyncio.get_running_loop().create_future()
    resolver.queue[("198.41.0.4", 1234)] = (object(), future)

    await resolver.aclose()

    assert resolver.queue == {}
    assert future.done()
    with pytest.raises(RuntimeError, match="resolver closed"):
        future.result()


async def test_aclose_cancels_the_ipv6_bringup_still_running():
    """The background socket creation must be stopped, not completed.

    Letting it finish would open one more socket immediately after the resolver
    decided it was done with sockets.
    """
    resolver = RecursiveResolver()
    gate = asyncio.Event()
    started = asyncio.Event()

    async def bring_up():
        started.set()
        await gate.wait()

    task = asyncio.get_running_loop().create_task(bring_up())
    await started.wait()
    resolver._v6_ready = task

    await resolver.aclose()

    assert task.cancelled()
    assert resolver._v6_ready is None


async def test_aclose_is_idempotent():
    """Closing twice, or closing something that never connected, is not an error.

    ``cli_query`` closes the endpoint transport it was handed *and* the resolver;
    asyncio treats a second ``close()`` as a no-op, and this pins that the
    resolver's own bookkeeping does not turn the overlap into an exception.
    """
    endpoint = _RecordingTransport()
    resolver = _attached(transport=endpoint)

    await resolver.aclose()
    await resolver.aclose()
    await RecursiveResolver().aclose()

    assert endpoint.closed
