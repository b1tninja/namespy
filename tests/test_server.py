"""The datagram server: refusal paths, reply shape, and bounded egress.

``DnsServer`` is the only part of this library that listens, so these tests aim
at what an off-path sender can influence: a datagram that fails to parse must not
raise out of a protocol callback, a query that cannot be answered must be
*answered* (with an RCODE and the echoed question) rather than dropped, and the
number of upstream lookups triggered per inbound datagram must stay provably
below one.

The resolver is replaced with a stub for the refusal and reply-shape cases, and
driven through its real ``_send_for_entry`` seam for the one integration case, so
the server is not tested against a mock of itself.

.. rubric:: References

* RFC 1035 section 4.3 (server behaviour, including what to do with a bad query)
* RFC 5358 section 4 (BCP 140: an open recursion service must not be the default)
* RFC 5452 sections 4.2-4.3 and 9.1 (a client matches a reply on ID *and* the
  question section)
* RFC 5625 section 6.2 (do not listen where you do not control the clients) and
  section 6.3 (malformed traffic may be dropped); the bound on concurrent
  upstream work is a design decision, not a specification number
* RFC 6891 sections 6.1.1, 6.1.3, 6.2.4 and 7 (a response to an OPT query must
  carry an OPT of the responder's own; one OPT per message, and never a
  forwarded one; BADVERS for an unimplemented VERSION; no OPT for a requestor
  that did not ask)
"""

import asyncio
import ipaddress
import random

import pytest

from namespy.cache import MemoryDnsCache
from namespy.edns import (
    COOKIE_OPTION_CODE,
    NSID_OPTION_CODE,
    PADDING_OPTION_CODE,
    EdnsOption,
    extended_dns_error_option,
    extended_errors_of,
    nsid_of,
)
from namespy.enums import (
    DnsOpCode,
    DnsQClass,
    DnsQR,
    DnsQType,
    DnsResponseCode,
    DnsRType,
)
from namespy.names import DomainName
from namespy.packet import OPT_RTYPE, DnsPacket, DnsQuestion, DnsRecord, Query, Response
from namespy.rdata import RData_A
from namespy.resolver import RecursiveResolver
from namespy.server import EDNS_VERSION_SUPPORTED, RESPONDER_PAYLOAD_SIZE, DnsServer

HOST = DomainName("www.example.com.")
HOST_IP = ipaddress.IPv4Address("93.184.216.34")
ADDR = ("127.0.0.1", 5353)


class FakeTransport:
    """Records what the server sends; exposes no socket, as a pipe transport would."""

    def __init__(self):
        self.sent = []

    def get_extra_info(self, name, default=None):
        return default

    def sendto(self, data, addr):
        self.sent.append((bytes(data), addr))

    @property
    def replies(self):
        return [DnsPacket.parse(data)[0] for data, _addr in self.sent]


def make_server(resolver=None, **kwargs):
    resolver = resolver if resolver is not None else RecursiveResolver(cache=MemoryDnsCache())
    server = DnsServer(resolver, **kwargs)
    transport = FakeTransport()
    server.connection_made(transport)
    return server, resolver, transport


def query_packet(name=HOST, qtype=DnsQType.A, packet_id=0xABCD):
    return Query(ID=packet_id, questions=[DnsQuestion(name, qtype, DnsQClass.IN)])


async def drain(server, timeout=1.0):
    """Await everything the server has spawned, so assertions see settled state."""
    tasks = list(server._tasks)
    if tasks:
        await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout)
    return tasks


def answered_response(packet):
    return Response(
        ID=packet.ID,
        QR=DnsQR.RESPONSE,
        RA=True,
        questions=list(packet.questions),
        answers=[
            DnsRecord(
                packet.questions[0].name,
                DnsRType.A,
                DnsQClass.IN,
                300,
                rdata=RData_A(HOST_IP),
            )
        ],
    )


# --------------------------------------------------------------- construction


def test_resolver_type_is_enforced():
    with pytest.raises(TypeError, match="RecursiveResolver"):
        DnsServer(object())


def test_connection_made_survives_a_transport_without_a_socket():
    """Path MTU discovery is Linux-only, so opening a transport must not need it."""
    server, _resolver, transport = make_server()
    assert server.transport is transport


def test_concurrency_floor_is_one():
    server, _resolver, _transport = make_server(max_concurrent_lookups=0)
    assert server.max_concurrent_lookups == 1


# ----------------------------------------------------------- inbound garbage


def test_truncated_datagram_replies_formerr_and_does_not_raise():
    """A parse failure escaping a protocol callback would kill the transport."""
    server, _resolver, transport = make_server()
    server.datagram_received(b"\x00\x01\x00", ADDR)

    assert transport.sent, "a malformed datagram must still get an answer"
    reply = transport.replies[0]
    assert reply.RCODE == DnsResponseCode.FORMAT_ERROR
    assert reply.QR == DnsQR.RESPONSE
    assert reply.QDCOUNT == 0, "nothing parsed, so there is nothing to echo"
    assert not server._tasks, "a datagram that never parsed must spawn no work"


def test_datagram_claiming_more_questions_than_it_has_is_refused():
    header = b"\x12\x34\x01\x00\x00\x05\x00\x00\x00\x00\x00\x00"
    server, _resolver, transport = make_server()
    server.datagram_received(header, ADDR)

    assert transport.replies[0].RCODE == DnsResponseCode.FORMAT_ERROR
    assert not server._tasks


def test_random_bytes_never_escape_as_an_exception():
    """Feed the callback directly: no octet sequence may raise out of it."""
    server, _resolver, _transport = make_server()
    rng = random.Random(20261027)
    for _ in range(400):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 40)))
        server.datagram_received(blob, ADDR)


# ------------------------------------------------------------ refusal paths


async def test_incoming_response_is_ignored():
    server, _resolver, transport = make_server()
    packet = query_packet()
    packet.QR = DnsQR.RESPONSE

    await server.respond_to_packet(packet, ADDR)
    assert transport.sent == []


async def test_multiple_questions_are_refused_rather_than_partly_answered():
    """Answering one of N questions without saying which is worse than refusing."""
    server, _resolver, transport = make_server()
    packet = Query(
        ID=0x42,
        questions=[
            DnsQuestion(HOST, DnsQType.A, DnsQClass.IN),
            DnsQuestion(HOST, DnsQType.AAAA, DnsQClass.IN),
        ],
    )

    await server.respond_to_packet(packet, ADDR)
    reply = transport.replies[0]
    assert reply.RCODE == DnsResponseCode.FORMAT_ERROR
    assert reply.ID == 0x42
    assert reply.QDCOUNT == 2, "the question section must be echoed for matching"


async def test_unsupported_opcode_is_not_implemented_not_dropped():
    """RFC 2929 section 3.1: an unimplemented opcode gets NOTIMP, not silence."""
    server, _resolver, transport = make_server()
    packet = query_packet()
    packet.OPCODE = DnsOpCode.STATUS

    await server.respond_to_packet(packet, ADDR)
    assert transport.replies[0].RCODE == DnsResponseCode.NOT_IMPLEMENTED


async def test_resolution_failure_becomes_servfail():
    server, resolver, transport = make_server()

    async def no_answer(_packet):
        return None

    resolver.resolve = no_answer
    server.datagram_received(bytes(query_packet()), ADDR)
    await drain(server)

    assert transport.replies[0].RCODE == DnsResponseCode.SERVER_FAILURE


async def test_late_result_after_transport_change_stays_silent():
    server, resolver, transport = make_server()

    async def invalid_state(_packet):
        raise asyncio.InvalidStateError("transport closed mid-flight")

    resolver.resolve = invalid_state
    server.datagram_received(bytes(query_packet()), ADDR)
    await drain(server)

    assert transport.sent == []


# ---------------------------------------------------------------- happy path


async def test_answer_is_forwarded_with_the_query_id_and_question():
    server, resolver, transport = make_server()

    async def fake_resolve(packet):
        return answered_response(packet)

    resolver.resolve = fake_resolve
    server.datagram_received(bytes(query_packet()), ADDR)
    await drain(server)

    assert len(transport.sent) == 1
    data, addr = transport.sent[0]
    assert addr == ADDR
    reply = DnsPacket.parse(data)[0]
    assert reply.QR == DnsQR.RESPONSE
    assert reply.RA is True
    # RFC 5452 section 9.1: ID alone is 16 bits of matching; the echoed question
    # is what lets a client reject a forged reply that happened to guess the ID.
    assert reply.ID == 0xABCD
    assert reply.questions[0].name == HOST
    assert int(reply.questions[0].qtype) == int(DnsQType.A)
    assert bytes(reply.answers[0].rdata) == HOST_IP.packed


async def test_recursive_walk_result_is_relayed_end_to_end():
    """Drive the real resolver through its send seam, not a stub of resolve()."""
    resolver = RecursiveResolver(cache=MemoryDnsCache())
    server, _resolver, transport = make_server(resolver=resolver)

    async def authoritative(entry, questions):
        return Response(
            ID=0,
            QR=DnsQR.RESPONSE,
            AA=True,
            questions=list(questions),
            answers=[
                DnsRecord(questions[0].name, DnsRType.A, DnsQClass.IN, 60, rdata=RData_A(HOST_IP))
            ],
        )

    resolver._send_for_entry = authoritative
    server.datagram_received(bytes(query_packet()), ADDR)
    await drain(server)

    reply = transport.replies[0]
    assert reply.AA is True
    assert len(reply.answers) == 1
    # The trace lives on the resolver's response object, not on the wire: nothing
    # in RFC 1035 carries it, so the walk is observed on the resolver rather than
    # in the datagram that went out.
    assert resolver.last_trace is not None
    assert resolver.last_trace.events


# ------------------------------------------------------- EDNS(0) on the way out
#
# RFC 6891 section 6.1.1 obliges a responder to answer an OPT-bearing query
# with an OPT record of its own, section 7 forbids one for a query that had
# none, section 6.1.1 also says OPT "MUST NOT be cached, forwarded", section
# 6.1.1 demands FORMERR for a query carrying more than one, and section 6.1.3
# demands BADVERS for a VERSION the responder does not implement. Each of those
# sentences is a test below, plus the one case none of them covers: an extended
# RCODE that the client cannot be shown.


def opt_record(payload_size=1232, version=0, flags=0):
    """A bare OPT pseudo-record to stitch into a stub resolver's reply."""
    ttl = ((version & 0xFF) << 16) | (flags & 0xFFFF)
    return DnsRecord(DomainName("."), OPT_RTYPE, payload_size, ttl)


def stub_reply(packet, *, rcode=None, additional=()):
    """A relay-shaped answer, optionally carrying an upstream server's OPT."""
    return Response(
        ID=packet.ID,
        QR=DnsQR.RESPONSE,
        RA=True,
        RCODE=int(DnsResponseCode.NO_ERROR if rcode is None else rcode),
        questions=list(packet.questions),
        additional_records=list(additional),
    )


async def answer_with(resolver, reply_factory):
    async def stub(packet):
        return reply_factory(packet)

    resolver.resolve = stub


async def test_opt_in_the_query_buys_an_opt_of_our_own_in_the_reply() -> None:
    """Section 6.1.1's MUST, and the OPT is *ours*: 4096 was the client's
    number, the reply carries this host's reassembly limit (section 6.2.4)."""
    server, resolver, transport = make_server()
    await answer_with(resolver, stub_reply)

    query = query_packet().add_edns(4096)
    server.datagram_received(bytes(query), ADDR)
    await drain(server)

    reply = transport.replies[0]
    assert reply.opt() is not None, "an extended requestor must get an OPT back"
    assert RESPONDER_PAYLOAD_SIZE == reply.requestor_payload_size
    assert EDNS_VERSION_SUPPORTED == reply.edns_version
    assert 1 == sum(1 for r in reply.additional_records if int(r.rtype) == OPT_RTYPE)
    assert reply.questions[0].name == HOST  # the question is still first, section 6.1.1


async def test_unextended_query_is_answered_without_an_opt() -> None:
    """Section 7: no OPT in the request means the requestor "does not implement
    any part of this specification and ... the responder MUST NOT include an OPT
    record in its response"."""
    server, resolver, transport = make_server()
    await answer_with(resolver, stub_reply)

    server.datagram_received(bytes(query_packet()), ADDR)
    await drain(server)

    assert transport.replies[0].opt() is None


async def test_an_upstream_opt_is_never_forwarded_as_our_own() -> None:
    """The recursive walk hands back the authoritative server's message, OPT and
    all. Section 6.1.1: "OPT RRs MUST NOT be cached, forwarded" -- and its 512
    and its DO bit describe that server, not this one."""
    server, resolver, transport = make_server()
    upstream = opt_record(512, flags=0x8000)  # small stack, DO set
    await answer_with(resolver, lambda p: stub_reply(p, additional=[upstream]))

    server.datagram_received(bytes(query_packet().add_edns(1232)), ADDR)
    await drain(server)

    reply = transport.replies[0]
    assert RESPONDER_PAYLOAD_SIZE == reply.requestor_payload_size, "the 512 was theirs"
    assert not reply.ad, "a DO bit borrowed from an upstream answer claims nothing"
    assert 1 == sum(1 for r in reply.additional_records if int(r.rtype) == OPT_RTYPE)


async def test_a_query_with_two_opt_records_is_formerr_before_any_work() -> None:
    # Section 6.1.1: an OPT RR MUST be the only one in the message, and a query
    # with more than one MUST be answered FORMERR. Refused before the resolver
    # is consulted, so a hostile datagram cannot purchase a recursive walk.
    server, resolver, transport = make_server()
    looked_up = []

    async def stub(packet):
        looked_up.append(packet)
        return stub_reply(packet)

    resolver.resolve = stub

    # Both records go in through the constructor: `additional_records` hands
    # back a copy, so appending to it would emit octets ARCOUNT does not count.
    query = Query(
        ID=0xABCD,
        questions=[DnsQuestion(HOST, DnsQType.A, DnsQClass.IN)],
        additional_records=[opt_record(1232), opt_record(512)],
    )
    server.datagram_received(bytes(query), ADDR)
    await drain(server)

    reply = transport.replies[0]
    assert int(DnsResponseCode.FORMAT_ERROR) == int(reply.RCODE)
    assert [] == looked_up
    # The request was extended, so section 6.1.1's MUST still covers the error.
    assert reply.opt() is not None


async def test_an_unimplemented_edns_version_answers_badvers() -> None:
    # Section 6.1.3: a responder that does not implement the requested VERSION
    # MUST answer BADVERS, while the response OPT carries the highest level the
    # responder does implement -- which is the whole point of the exchange.
    server, resolver, transport = make_server()
    await answer_with(resolver, stub_reply)

    server.datagram_received(bytes(query_packet().add_edns(1232, version=1)), ADDR)
    await drain(server)

    reply = transport.replies[0]
    assert int(DnsResponseCode.BADVERS) == int(reply.extended_rcode)
    assert EDNS_VERSION_SUPPORTED == reply.edns_version
    assert 0 == int(reply.RCODE) & 0xF, "BADVERS is 16, so the header nibble stays clear"


async def test_an_extended_rcode_reaches_an_extended_client() -> None:
    # The upper eight bits only travel if the responder supplies the OPT that
    # holds them (section 6.1.3's EXTENDED-RCODE field).
    server, resolver, transport = make_server()
    await answer_with(resolver, lambda p: stub_reply(p, rcode=23))

    server.datagram_received(bytes(query_packet().add_edns(1232)), ADDR)
    await drain(server)

    assert 23 == int(transport.replies[0].extended_rcode)


async def test_an_extended_rcode_for_an_unextended_client_becomes_servfail() -> None:
    # No carrier, no message: section 7 forbids the OPT this client would need,
    # and masking 23 down to its low nibble would report FORMERR for an answer
    # that failed for an unrelated reason. SERVFAIL is the honest remainder.
    server, resolver, transport = make_server()
    await answer_with(resolver, lambda p: stub_reply(p, rcode=23, additional=[opt_record(4096)]))

    server.datagram_received(bytes(query_packet()), ADDR)
    await drain(server)

    reply = transport.replies[0]
    assert int(DnsResponseCode.SERVER_FAILURE) == int(reply.RCODE)
    assert reply.opt() is None


# ----------------------------------------------- options inside that OPT RDATA
#
# The OPT record's RDATA is a list of option TLVs (RFC 6891 section 6.1.2), and
# that one section decides two opposite things about them: a code this server
# does not know "MUST be ignored", while a value that is "badly
# formatted" or carries "out-of-range values" earns a FORMERR that must still
# carry an OPT (section 7). RFC 5001 section 2.2 then supplies the asymmetry that
# makes an NSID server testable in both directions -- the request is the option
# with no payload, and the reply is the option with the server's own identity in
# it, never the client's. RFC 7830 section 6 subtracts one behaviour: padding is
# forbidden on a transport that is not encrypted, and plain UDP is all this
# server has.


def opt_with(rdata: bytes, payload_size: int = 1232) -> DnsRecord:
    """An OPT record carrying *rdata* as its option list, so a damaged option can
    be delivered inside an otherwise well-formed message."""
    return DnsRecord(DomainName("."), OPT_RTYPE, payload_size, 0, rdata=rdata)


def extended_query(options) -> Query:
    return query_packet().add_edns(1232, options=options)


async def test_an_identifier_goes_only_to_a_query_that_asked_for_it() -> None:
    """RFC 5001 section 2.2: "A name server MUST NOT send an NSID option back to a
    resolver which did not request it". A server configured with an identity is
    the only kind that can fail this, which is why the fixture has one."""
    server, resolver, transport = make_server(nsid=b"ns-a")
    await answer_with(resolver, stub_reply)

    server.datagram_received(bytes(query_packet().add_edns(1232)), ADDR)
    await drain(server)
    unasked = transport.replies[0]
    assert unasked.opt() is not None, "the request was extended, so section 6.1.1 still applies"
    assert nsid_of(unasked.edns_options()) is None, "an OPT is not a request for an identity"

    server.datagram_received(bytes(extended_query([EdnsOption(NSID_OPTION_CODE, b"")])), ADDR)
    await drain(server)
    assert b"ns-a" == nsid_of(transport.replies[1].edns_options())


async def test_a_server_with_no_identity_never_sends_the_option() -> None:
    """The default constructor advertises nothing, and answering a request with an
    empty NSID would be worse than silence: RFC 5001 section 2.1 makes the empty
    payload mean "this is the question", so a reply using it claims to be a
    question while sitting in a response."""
    server, resolver, transport = make_server()
    await answer_with(resolver, stub_reply)

    server.datagram_received(bytes(extended_query([EdnsOption(NSID_OPTION_CODE, b"")])), ADDR)
    await drain(server)

    reply = transport.replies[0]
    assert reply.opt() is not None
    assert nsid_of(reply.edns_options()) is None


async def test_an_identifier_written_by_the_requestor_is_ignored() -> None:
    """Section 2.2 again, second sentence: "The name server MUST ignore any NSID
    payload data that might be present in the request message". Echoing it would
    turn a debugging aid into an attacker-supplied string that a client's log
    would then read back as the identity of this server."""
    server, resolver, transport = make_server(nsid=b"ns-a")
    await answer_with(resolver, stub_reply)

    server.datagram_received(
        bytes(extended_query([EdnsOption(NSID_OPTION_CODE, b"client-wrote-this")])), ADDR
    )
    await drain(server)

    assert b"ns-a" == nsid_of(transport.replies[0].edns_options()), "ignore, never echo"


async def test_an_option_this_server_does_not_know_is_ignored_not_refused() -> None:
    """Section 6.1.2's "MUST be ignored" is an instruction about what to *do*, and
    the doing includes not complaining: a private experimental code is a
    deployment choice, not a defect, and refusing it would make this server the
    thing that breaks a peer's rollout."""
    server, resolver, transport = make_server()
    await answer_with(resolver, stub_reply)

    server.datagram_received(bytes(extended_query([EdnsOption(0xFFF0, b"whatever")])), ADDR)
    await drain(server)

    reply = transport.replies[0]
    assert int(DnsResponseCode.NO_ERROR) == int(reply.RCODE)
    assert () == reply.edns_options(), "ignored also means not echoed back"


async def test_a_misformed_option_is_formerr_and_still_carries_an_opt() -> None:
    """Section 7: "If there is a problem with processing the OPT record itself,
    such as an option value that is badly formatted ... a FORMERR MUST be
    returned. If this occurs, the response MUST include an OPT record." The second
    sentence is the one a responder forgets: without an OPT the FORMERR is
    indistinguishable from an unextended server, and section 6.2.2 has a requestor
    that detects "the remote end does not support EDNS(0)" retry unextended rather
    than learn that its own option was malformed."""
    server, resolver, transport = make_server()
    looked_up = []

    async def stub(packet):
        looked_up.append(packet)
        return stub_reply(packet)

    resolver.resolve = stub

    # The option claims eight octets of value and supplies two. The record itself
    # is self-consistent -- RDLENGTH matches the bytes on the wire -- so nothing
    # but a reading of the option list can notice, which is why the refusal has to
    # come from the option check rather than the generic parse-failure path.
    broken = Query(
        ID=0xABCD,
        questions=[DnsQuestion(HOST, DnsQType.A, DnsQClass.IN)],
        additional_records=[opt_with(b"\x00\x03\x00\x08ns")],
    )
    server.datagram_received(bytes(broken), ADDR)
    await drain(server)

    reply = transport.replies[0]
    assert int(DnsResponseCode.FORMAT_ERROR) == int(reply.RCODE)
    assert [] == looked_up, "a request that cannot be read should not buy a recursive walk"
    assert reply.opt() is not None, "section 7: the FORMERR of a bad option carries an OPT"


@pytest.mark.parametrize(
    ("octets", "acceptable"),
    [(8, True), (9, False), (15, False), (16, True), (40, True), (41, False)],
)
async def test_a_cookie_of_an_undreamt_of_length_is_refused_before_the_walk(
    octets, acceptable
) -> None:
    """RFC 7873 section 5.2.2 lists the COOKIE lengths a client may send -- 8, or 16
    through 40 -- and section 5.2 answers anything else with FORMERR. The 9-to-15
    band is the case worth pinning: such an option is not a short Server Cookie, it
    is a length that cannot be one, and a server that accepted it would be
    pretending to validate a cookie the client could never have produced."""
    server, resolver, transport = make_server()
    await answer_with(resolver, stub_reply)

    query = extended_query(
        [EdnsOption(COOKIE_OPTION_CODE, bytes([n % 256 for n in range(octets)]))]
    )
    server.datagram_received(bytes(query), ADDR)
    await drain(server)

    reply = transport.replies[0]
    assert acceptable == (int(DnsResponseCode.NO_ERROR) == int(reply.extended_rcode))


async def test_padding_asked_for_over_plain_udp_is_not_honoured() -> None:
    """RFC 7830 section 4: "Responders MUST pad DNS responses when the respective
    DNS query included the 'Padding' option, unless doing so would violate the
    maximum UDP payload size." Section 6 then withdraws the option: implementations
    "MUST NOT use this option if the DNS transport is not encrypted". This server's
    transport is UDP, so section 4 could only be obeyed by breaking section 6, and
    the sentence about encryption is the one that describes the situation this
    server is in. Refusing the padding must not cost the client the rest of its
    options."""
    server, resolver, transport = make_server(nsid=b"ns-a")
    await answer_with(resolver, stub_reply)

    query = extended_query(
        [EdnsOption(PADDING_OPTION_CODE, b""), EdnsOption(NSID_OPTION_CODE, b"")]
    )
    server.datagram_received(bytes(query), ADDR)
    await drain(server)

    reply = transport.replies[0]
    assert reply.edns_option(PADDING_OPTION_CODE) is None, "plaintext is plaintext"
    assert b"ns-a" == nsid_of(reply.edns_options()), "one refusal may not swallow the others"


# --------------------------------------------- Extended DNS Errors on the way out
#
# RFC 8914 gives a responder a second, optional channel: an ERROR option (code 15)
# whose "INFO-CODE ... provides the additional context for the RESPONSE-CODE of the
# DNS message" (section 2). Three of its sentences shape what happens here. Section 3
# refuses to bind any code to any RCODE -- "systems interpreting the extended error
# codes MUST NOT assume that a combination will make sense" -- so the pairings below
# are this server's choices, and the tests assert them rather than derive them. The
# same section orders the trimming: "servers SHOULD truncate messages by dropping EDE
# options before dropping other data from packets", which is why the option is
# appended last and why one test finds the exact octet where it stops fitting. Section
# 6 keeps the whole thing honest -- "EDE content should be treated only as diagnostic
# information and MUST NOT alter DNS protocol processing" -- so every test here also
# asserts an RCODE that is what it was before the option existed.
#
# The relay half of section 3, passing an upstream server's EDE on to the client, is
# what a forwarder does, and this server declines it deliberately: "whether or not (and
# how) to pass along EDE information on to their original client is implementation
# dependent". Its own refusals get their own explanations; the walk's go to the trace.


def failing_answer(packet) -> Response:
    """A SERVFAIL that nevertheless carries an A record -- the shape that lets the
    size test have something worth protecting when it decides what to drop."""
    return Response(
        ID=packet.ID,
        QR=DnsQR.RESPONSE,
        RA=True,
        RCODE=int(DnsResponseCode.SERVER_FAILURE),
        questions=list(packet.questions),
        answers=[
            DnsRecord(
                packet.questions[0].name, DnsRType.A, DnsQClass.IN, 300, rdata=RData_A(HOST_IP)
            )
        ],
    )


def oversized_failure(packet, minimum: int = 700) -> Response:
    """A SERVFAIL padded past *minimum* octets with A records of distinct labels.

    Distinct because RFC 1035 section 4.1.4's name compression would otherwise charge
    a pointer instead of a name and the padding would cost two octets a record; the
    point of the size is to sit above the 512-octet floor RFC 6891 section 6.2.3 forces
    on a small advertisement, so the test measures the explanation's octets rather than
    a floor that has nothing to do with it."""
    response = failing_answer(packet)
    index = 0
    while len(bytes(response)) < minimum:
        index += 1
        response.answers.append(
            DnsRecord(
                DomainName(f"pad{index}.example"),
                DnsRType.A,
                DnsQClass.IN,
                300,
                rdata=RData_A(HOST_IP),
            )
        )
    return response


def no_authority() -> list:
    """The option this server builds for SERVFAIL, spelled out here so the arithmetic
    in the size test stays visible instead of hiding in a helper's constant."""
    return [extended_dns_error_option(22, b"namespy: no authoritative answer")]


async def test_a_failure_that_needs_explaining_explains_itself() -> None:
    """Section 4.23's code 22 is "The resolver could not reach any of the authoritative
    name servers (or they potentially refused to reply)" -- precisely what a walk that
    ran out of servers has hit, and SERVFAIL alone does not say it. The wire is pinned
    as well as the parsed option because a transposed INFO-CODE is a different error
    read in a different language: 0x0016 is No Reachable Authority, 0x1600 belongs to
    nobody, and section 2 puts the field on the wire in "network most significant bit
    (MSB) byte order"."""
    server, resolver, transport = make_server()

    async def no_answer(_packet):
        return None

    resolver.resolve = no_answer
    server.datagram_received(bytes(extended_query([])), ADDR)
    await drain(server)

    reply = transport.replies[0]
    assert reply.RCODE == DnsResponseCode.SERVER_FAILURE, "the RCODE is what the client acts on"
    assert [22] == [error.info_code for error in extended_errors_of(reply.edns_options())]
    assert "namespy: no authoritative answer" == extended_errors_of(reply.edns_options())[0].text
    assert b"\x00\x0f\x00\x22\x00\x16" in bytes(reply), "option 15, length 34, INFO-CODE 22"


async def test_a_refusal_explains_what_was_refused() -> None:
    """Section 4.22 is "The requested operation or query is not supported", which is
    what NOTIMP already reports -- and a bare NOTIMP does not say *which* operation the
    client tripped over. Section 3 permits the pairing rather than prescribing it, so
    what is asserted is the pairing this server makes, plus the RCODE beneath it: an EDE
    may explain a refusal but must not quietly turn it into something else."""
    server, _resolver, transport = make_server()
    packet = extended_query([])
    packet.OPCODE = DnsOpCode.STATUS

    await server.respond_to_packet(packet, ADDR)

    reply = transport.replies[0]
    assert reply.RCODE == DnsResponseCode.NOT_IMPLEMENTED
    assert [21] == [error.info_code for error in extended_errors_of(reply.edns_options())]


async def test_an_unextended_client_is_told_nothing_extra() -> None:
    """Section 3.2's second sentence is a MUST NOT -- "an EDNS(0) aware server
    receiving a DNS query without an accompanying EDNS(0) record MUST NOT include EDE in
    a response" -- and its first sentence, "A server not sending EDE SHOULD include an
    EDNS0 record unless the client explicitly indicated that it does not support them",
    is satisfied by saying nothing at all to a client that sent no OPT. The SERVFAIL and
    its echoed question still arrive; only the explanation is withheld."""
    server, resolver, transport = make_server()

    async def no_answer(_packet):
        return None

    resolver.resolve = no_answer
    server.datagram_received(bytes(query_packet()), ADDR)
    await drain(server)

    reply = transport.replies[0]
    assert reply.RCODE == DnsResponseCode.SERVER_FAILURE
    assert reply.QDCOUNT == 1, "the echoed question is not part of what is withheld"
    assert reply.opt() is None, "section 7 forbids the record as firmly as 3.2 forbids the option"


async def test_a_rejection_that_already_explains_itself_gets_no_extended_error() -> None:
    """Sections 4.23 and 4.22 describe a resolver that could not reach anybody and a
    server that does not support an operation. FORMAT_ERROR for a second question and
    BADVERS for a version negotiation are statements about the datagram, not about
    anybody's ability to answer it, so bolting 22 onto them is the assumption section 3
    forbids. Section 4.3's code 2, "Unsupported DNS Response Code", is declined for
    BADVERS for the same reason: RFC 6891 section 6.2.2 already prescribes what a
    version reply carries -- the client's version and this server's bits -- and an
    option nobody asked for is not part of that. Both replies still carry an OPT, which
    is what section 6.1.1 requires of any answer to an extended request and is what the
    assertions below separate from the option."""
    server, _resolver, transport = make_server()
    two_questions = Query(
        ID=0xABCD,
        questions=[
            DnsQuestion(HOST, DnsQType.A, DnsQClass.IN),
            DnsQuestion(HOST, DnsQType.AAAA, DnsQClass.IN),
        ],
    ).add_edns(1232)

    await server.respond_to_packet(two_questions, ADDR)
    refused = transport.replies[0]
    assert refused.RCODE == DnsResponseCode.FORMAT_ERROR, "two questions is still a refusal"
    assert refused.opt() is not None, "an extended request still gets an OPT, section 6.1.1"
    assert () == refused.edns_options(), "but no explanation of a packet-shaped refusal"

    await server.respond_to_packet(query_packet().add_edns(1232, version=1), ADDR)
    negotiated = transport.replies[1]
    assert int(DnsResponseCode.BADVERS) == int(negotiated.extended_rcode), (
        "16 lives in the extension"
    )
    assert () == negotiated.edns_options(), "section 6.2.2 answers a version, not section 4.3"


def test_an_explanation_is_dropped_before_anything_the_client_asked_for() -> None:
    """Section 3: "If a message with EDE is too large for the transport being used,
    servers SHOULD truncate messages by dropping EDE options before dropping other data
    from packets." The boundary is measured rather than assumed -- the empty-OPT
    overhead and the answer's own size both come out of the built packet -- so the two
    requests below advertise the largest payload the explanation still fits inside, and
    one octet less. Past that line the answer survives and the explanation is what goes,
    which is the reverse of cutting an RRSet: an answer trimmed short is a server that
    answered a different question than it was asked. The OPT itself stays in both cases,
    because RFC 6891 section 6.1.1's MUST is not conditional on there being options. The
    padding records are what make the measurement mean anything: section 6.2.3 forces
    "values lower than 512 MUST be treated as equal to 512", so a reply of a hundred
    octets could never be shown to overflow even a miserly advertisement."""
    server, _resolver, _transport = make_server()
    request = query_packet()
    bare_opt = oversized_failure(request)
    bare_opt.add_edns(512)
    explanation = len(no_authority()[0].data) + 4
    fits = len(bytes(bare_opt)) + explanation

    kept = oversized_failure(query_packet())
    server._apply_edns(query_packet().add_edns(fits), kept, no_authority())
    assert [22] == [error.info_code for error in extended_errors_of(kept.edns_options())]
    assert len(bytes(kept)) <= fits, "it fits the advertised size, so it is kept"

    trimmed = oversized_failure(query_packet())
    server._apply_edns(query_packet().add_edns(fits - 1), trimmed, no_authority())
    assert () == trimmed.edns_options(), "the explanation is the first thing dropped"
    assert trimmed.opt() is not None, "the record the client is owed is not optional"
    assert len(bytes(trimmed)) <= fits - 1
    assert len(trimmed.answers) > 1, "the answer is not what gets truncated"
    assert trimmed.RCODE == DnsResponseCode.SERVER_FAILURE


async def test_an_extended_error_option_too_short_to_hold_a_code_is_malformed() -> None:
    """Section 2 makes the INFO-CODE the first two octets of the option, so one octet of
    RDATA cannot express even the code, let alone any text. RFC 6891 section 7 says what
    a responder does with that: "If a requestor includes an option value that is badly
    formatted or that includes out-of-range values, a FORMERR MUST be returned. If this
    occurs, the response MUST include an OPT record." The other half of the test is the
    case a lazy length check gets wrong -- an option with an unassigned INFO-CODE is
    well formed, and section 3's "Receivers MUST be able to accept EDE codes and
    EXTRA-TEXT in all messages" means refusing it would be inventing a rule that breaks
    the next RFC."""
    server, resolver, transport = make_server()
    await answer_with(resolver, stub_reply)

    server.datagram_received(bytes(extended_query([EdnsOption(15, b"\x00")])), ADDR)
    await drain(server)
    refused = transport.replies[0]
    assert refused.RCODE == DnsResponseCode.FORMAT_ERROR
    assert refused.opt() is not None, "the OPT the FORMERR rule asks for"
    assert () == refused.edns_options(), "and none of the client's option echoed"

    server.datagram_received(bytes(extended_query([EdnsOption(15, b"\xff\xfftext")])), ADDR)
    await drain(server)
    assert transport.replies[1].RCODE == DnsResponseCode.NO_ERROR, (
        "a code we have not met is not a defect"
    )


async def test_an_extended_error_in_a_query_is_neither_answered_nor_echoed() -> None:
    """Section 3.1: "A DNS server MAY ignore any EDE codes and EXTRA-TEXT in messages it
    receives in queries and MUST NOT attempt to resolve any based on such codes."
    Ignoring has to be proved in both directions: the server must not start resolving an
    error code, and it must not hand the client's own words back as though they were the
    server's reason -- the same discipline that stops a client's NSID payload from
    becoming the server's identity."""
    server, resolver, transport = make_server()
    await answer_with(resolver, stub_reply)

    server.datagram_received(bytes(extended_query([EdnsOption(15, b"\x00\x16please fail")])), ADDR)
    await drain(server)

    reply = transport.replies[0]
    assert reply.RCODE == DnsResponseCode.NO_ERROR, "a code in a query is not a query"
    assert () == reply.edns_options(), "an option defined for responses is not echoed"
    assert b"please fail" not in bytes(reply), "a client's text is not this server's reason"


# ------------------------------------------------------- amplification defence


async def test_second_lookup_waits_for_a_slot():
    """Egress must be provably bounded relative to ingress.

    Two datagrams with a cap of one: only one upstream lookup may be in flight.
    That inequality is what stops the server being usable as an amplifier, so it
    is asserted rather than assumed.
    """
    server, resolver, transport = make_server(max_concurrent_lookups=1)
    gate = asyncio.Event()
    inflight = []

    async def slow(packet):
        inflight.append(1)
        await gate.wait()
        return answered_response(packet)

    resolver.resolve = slow
    server.datagram_received(bytes(query_packet()), ADDR)
    server.datagram_received(bytes(query_packet(packet_id=0x999)), ADDR)
    await asyncio.sleep(0.05)

    assert len(inflight) == 1, "a cap of one must not admit two"

    gate.set()
    await drain(server)
    assert len(inflight) == 2
    assert len(transport.sent) == 2


async def test_connection_lost_cancels_and_forgets_outstanding_work():
    server, resolver, _transport = make_server()

    async def hang(_packet):
        await asyncio.sleep(30)

    resolver.resolve = hang
    server.datagram_received(bytes(query_packet()), ADDR)
    tasks = list(server._tasks)
    assert len(tasks) == 1

    server.connection_lost(None)

    assert server._tasks == set(), "references must be dropped, not merely cancelled"
    # cancel() only marks the task; it unwinds when the loop next resumes it, so
    # the settled state has to be awaited rather than inspected immediately.
    results = await asyncio.gather(*tasks, return_exceptions=True)
    assert isinstance(results[0], asyncio.CancelledError)
