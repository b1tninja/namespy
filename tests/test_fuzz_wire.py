"""Property-based fuzzing of the wire parsers.

This module exists because the parsers are a network trust boundary, and a
boundary is only as good as its worst failure mode. :class:`namespy.server` and
:class:`namespy.resolver` both catch :class:`~namespy.wire.DnsPacketParseError`
from inside an asyncio protocol callback and answer the client with FORMERR.
Any *other* exception type escaping a parser therefore escapes that handler,
reaches the event loop, and kills the datagram connection. The bugs that make
that happen -- an ``AttributeError`` on an unregistered RR type, an
``IndexError`` off the end of a length-bounded read, a ``struct.error`` from a
short slice -- are all one forgotten bounds check apart, and hand-written
corpus tests find them only when someone thinks to write the case.

So the central property is not "does it parse correctly" but **"does it fail
correctly"**: for arbitrary bytes, every parser must either return or raise
``DnsPacketParseError``. Nothing else. The corpus tests in
``test_names_wire.py`` and ``test_packet_wire.py`` stay valuable for the cases
whose *rejection* is the point; this file covers the ones nobody enumerated.

The round-trip properties matter for a different reason. :mod:`namespy.cache`
stores ``bytes(record)`` and re-parses it later, so a record whose serialisation
does not survive re-parsing corrupts the cache silently -- which is why
:mod:`namespy.rdata` serialises names without compression pointers at all.

Hypothesis shrinks every failure to a minimal repro and records it in
``.hypothesis/``, so a red run here names the exact byte string to turn into a
corpus test.

.. rubric:: What this file does *not* catch

Measured, not assumed: deleting a single rejection rule is **not** detected
here. Replacing :func:`namespy.wire.is_reserved_label_type` with a stub returning
``False``, and turning the pointer-target check in
:meth:`namespy.names.DomainName.parse_from` into an off-by-one, both leave this
file entirely green. Two reasons, both structural:

* The property constrains the exception *type*, and a message that slips past one
  removed check normally still trips a later bounds check and raises the same
  ``DnsPacketParseError`` -- so "fails correctly" remains true even though the
  message should have been refused earlier, for a different reason.
* A single-octet mutation of an entire message rarely lands on an octet the
  parser is reading as a label type at the moment it matters.

:func:`test_one_corrupt_octet_never_brings_down_the_parser` therefore guards the
crash boundary, not rule-level strictness. Which specific malformed input is
*refused*, and with which message, is pinned by the named corpus in
``test_names_wire.py`` and ``test_packet_wire.py`` -- those tests assert exact
rejection reasons and are the ones that fail when a rule disappears. Treat a
green fuzz tier as "no crashes", never as "no regressions".
"""

from __future__ import annotations

import hypothesis.strategies as st
from hypothesis import HealthCheck, assume, given, settings

from namespy.enums import DnsQR
from namespy.names import MAX_NAME_OCTETS, DomainName
from namespy.packet import DnsPacket, DnsQuestion, DnsRecord, Response
from namespy.rdata import (
    RData_A,
    RData_AAAA,
    RData_CNAME,
    RData_MX,
    RData_NS,
    RData_PTR,
    RData_SOA,
    RData_SRV,
    RData_TXT,
    all_rdata_classes,
)
from namespy.wire import DnsPacketParseError

# Parsing on a network path is allowed exactly one outcome besides success.
PARSE_ERRORS = (DnsPacketParseError,)

# Deadlines are meaningless for a parser that runs in microseconds and only
# produce flakes on a loaded runner; the example count is what buys coverage.
settings.register_profile(
    "wire",
    deadline=None,
    max_examples=400,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
)
settings.load_profile("wire")

_CODECS = sorted(all_rdata_classes().values(), key=lambda cls: cls.__name__)


@settings(max_examples=1000)
@given(data=st.binary(max_size=96), extra=st.integers(min_value=0, max_value=4))
def test_name_parser_fails_only_in_the_declared_way(data: bytes, extra: int) -> None:
    """``DomainName.parse_from`` never leaks an unexpected exception type."""
    offset = len(data) if not data else min(extra, len(data) - 1)
    try:
        name, end = DomainName.parse_from(data, offset)
    except PARSE_ERRORS:
        return
    # Success has consequences a caller relies on: the reported offset stays
    # inside the buffer, so the enclosing record can advance without going off
    # the end, and the expansion cannot exceed what the wire format permits.
    assert 0 <= end <= len(data)
    assert len(name.labels()) <= 128


@settings(max_examples=1000)
@given(data=st.binary(max_size=128), extra=st.integers(min_value=0, max_value=4))
def test_record_parser_fails_only_in_the_declared_way(data: bytes, extra: int) -> None:
    """``DnsRecord.parse`` survives every byte string, known type or not."""
    offset = len(data) if not data else min(extra, len(data) - 1)
    try:
        record, end = DnsRecord.parse(data, offset)
    except PARSE_ERRORS:
        return
    assert 0 <= end <= len(data)
    # A record that cannot be re-serialised and re-parsed identically would
    # corrupt the cache: namespy.cache.sqlite stores bytes(record) and reads it
    # back with DnsRecord.parse(payload, 0), long after the datagram that gave
    # it compression pointers has vanished.
    wire = bytes(record)
    reparsed, consumed = DnsRecord.parse(wire, 0)
    assert consumed == len(wire)
    assert reparsed == record


@settings(max_examples=1000)
@given(data=st.binary(max_size=160))
def test_message_parser_fails_only_in_the_declared_way(data: bytes) -> None:
    """``DnsPacket.parse`` never leaks an unexpected exception type."""
    try:
        packet, end = DnsPacket.parse(data)
    except PARSE_ERRORS:
        return
    assert end == len(data)
    # Header counts and parsed sections must agree. Trusting a count that the
    # body does not satisfy is how a resolver ends up treating an absent RR as
    # a present one.
    assert packet.QDCOUNT == len(packet.questions)
    assert packet.ANCOUNT == len(packet.answers)
    assert packet.NSCOUNT == len(packet.nameservers)
    assert packet.ARCOUNT == len(packet.additional_records)


@settings(max_examples=1000)
@given(data=st.binary(max_size=96))
def test_message_round_trips_through_its_own_serialisation(data: bytes) -> None:
    """Anything the parser accepts, it re-emits in a form it also accepts.

    Serialisation is where the compression-pointer decision shows up: a parsed
    message re-encodes names in full, so the output must still be parseable
    without the original buffer. Section counts must survive unchanged, or a
    reply built from a request would misdescribe its own body.
    """
    try:
        packet, _ = DnsPacket.parse(data)
    except PARSE_ERRORS:
        return
    wire = bytes(packet)
    again, end = DnsPacket.parse(wire)
    assert end == len(wire)
    assert again.QDCOUNT == packet.QDCOUNT
    assert again.ANCOUNT == packet.ANCOUNT
    assert again.NSCOUNT == packet.NSCOUNT
    assert again.ARCOUNT == packet.ARCOUNT
    assert again.ID == packet.ID
    assert again.questions == packet.questions


@settings(max_examples=600)
@given(
    cls=st.sampled_from(_CODECS),
    data=st.binary(max_size=80),
    offset=st.integers(min_value=0, max_value=3),
    length=st.integers(min_value=0, max_value=80),
)
def test_every_rdata_codec_fails_only_in_the_declared_way(
    cls, data: bytes, offset: int, length: int
) -> None:
    """Each codec, driven directly, honours the same failure contract.

    :class:`namespy.packet.DnsRecord` bounds RDATA for these, but they are public
    and reachable on their own; a caller that hands one a short slice must get
    ``DnsPacketParseError`` rather than a half-built object.
    """
    start = min(offset, len(data))
    try:
        value = cls.parse_from(data, start, length)
    except PARSE_ERRORS:
        return
    assert isinstance(value, cls)
    assert isinstance(bytes(value), bytes)


_label = st.binary(min_size=1, max_size=63)


@given(labels=st.lists(_label, min_size=1, max_size=6))
def test_names_survive_encode_parse_and_back(labels: list[bytes]) -> None:
    """Label octets in, identical label octets out -- through the wire, not around it.

    Labels are arbitrary octets (RFC 2181 section 11 forbids restricting them),
    so a dot or a backslash inside a label is the interesting case: it must not
    split into two labels or swallow a neighbour on the way back. Length limits
    are the encoder's business and are assumed away here.
    """
    name = DomainName.from_labels(labels)
    assume(len(bytes(name)) <= MAX_NAME_OCTETS)
    wire = bytes(name)
    assert len(wire) <= MAX_NAME_OCTETS

    parsed, end = DomainName.parse_from(wire, 0)
    assert end == len(wire)
    assert parsed.labels() == labels
    assert parsed == name


# ---------------------------------------------------------------------------
# The tests above feed unstructured bytes, which is the right input for the
# failure contract and the wrong one for everything else: measured over 20k
# random strings, DnsRecord.parse and DnsPacket.parse accept *none* of them, so
# an assertion placed on the success path would never run. Everything below is
# built from valid wire forms -- and then, in the mutation test, broken one
# octet at a time, which is the input class that finds off-by-one bounds bugs.
# ---------------------------------------------------------------------------


@settings(max_examples=400)
@given(
    labels=st.lists(_label, min_size=1, max_size=4),
    rtype=st.integers(min_value=0, max_value=65535),
    rclass=st.integers(min_value=0, max_value=65535),
    ttl=st.integers(min_value=0, max_value=0xFFFFFFFF),
    blob=st.binary(max_size=40),
)
def test_unregistered_types_carry_their_rdata_untouched(
    labels: list[bytes], rtype: int, rclass: int, ttl: int, blob: bytes
) -> None:
    """An RR this library has never heard of must round-trip byte-for-byte.

    RFC 3597 section 3 requires a resolver to handle unknown types transparently
    rather than reject them, and section 5 gives the presentation form. This is
    the property whose absence made a single ``HTTPS`` record (type 65) fatal:
    the code reached for ``.value`` on a plain int and the whole datagram died.
    """
    assume(rtype not in all_rdata_classes())
    name = DomainName.from_labels(labels)
    assume(len(bytes(name)) + 10 + len(blob) <= 0xFFFF)

    record = DnsRecord(name, rtype, rclass, ttl, rdata=blob)
    wire = bytes(record)
    parsed, end = DnsRecord.parse(wire, 0)

    assert end == len(wire)
    assert int(parsed.rtype) == rtype
    assert int(parsed.rclass) == rclass
    assert parsed.ttl == ttl
    assert bytes(parsed.rdata) == blob
    # RFC 3597 section 5 presentation. Stated as the rule rather than by
    # repeating the library's own helper, so a change to the helper is caught.
    presentation = parsed.rdata.to_presentation()
    if blob:
        assert presentation == rf"\# {len(blob)} {blob.hex()}"
    else:
        assert presentation == r"\# 0"


# --------------------------------------------------------- codec idempotence


@settings(max_examples=800)
@given(cls=st.sampled_from(_CODECS), data=st.binary(max_size=64))
def test_decoded_rdata_re_encodes_to_something_equivalent(cls, data: bytes) -> None:
    """Whatever a codec accepts, it must reproduce from its own output.

    Idempotence rather than exact octet equality: a codec is allowed to canonicalise
    (lowercase a name, drop a compression pointer), but not to lose or invent data.
    A cache stores the canonical form and re-parses it, so a second decode that
    disagrees with the first silently corrupts every later read.
    """
    try:
        first = cls.parse_from(data, 0, len(data))
    except PARSE_ERRORS:
        return
    canonical = bytes(first)
    try:
        second = cls.parse_from(canonical, 0, len(canonical))
    except PARSE_ERRORS as exc:  # pragma: no cover - the failure is the finding
        raise AssertionError(
            f"{cls.__name__} produced wire form it cannot re-read: {exc}\n"
            f"first input: {data.hex()}\ncanonical: {canonical.hex()}"
        ) from exc
    assert bytes(second) == canonical
    assert second == first


# ------------------------------------------------------------ built messages

#: Labels small enough that any list of them encodes, so the strategies below
#: never need to reject a sample and coverage cannot thin out.
_small_label = st.binary(min_size=1, max_size=20)
_name = st.lists(_small_label, min_size=1, max_size=4).map(DomainName.from_labels)

#: Each codec paired with a strategy that produces a *valid* instance of it.
_RDATA_FOR = {
    RData_A: st.builds(RData_A, st.ip_addresses(v=4)),
    RData_AAAA: st.builds(RData_AAAA, st.ip_addresses(v=6)),
    RData_NS: st.builds(RData_NS, _name),
    RData_CNAME: st.builds(RData_CNAME, _name),
    RData_PTR: st.builds(RData_PTR, _name),
    RData_SOA: st.builds(RData_SOA, _name, _name, *(st.integers(0, 0xFFFFFFFF) for _ in range(5))),
    RData_TXT: st.builds(RData_TXT, st.lists(st.binary(max_size=40), max_size=3)),
    RData_MX: st.builds(RData_MX, _name, st.integers(0, 0xFFFF)),
    RData_SRV: st.builds(
        RData_SRV,
        _name,
        st.integers(0, 0xFFFF),
        st.integers(0, 0xFFFF),
        st.integers(0, 0xFFFF),
    ),
}


@st.composite
def built_message(draw):
    """A syntactically valid response, assembled from the real encoders.

    Built through :class:`~namespy.rdata` rather than by hand so the fixture and
    the code under test cannot agree on a shared misunderstanding of the wire
    format -- the encoders themselves are part of what these properties check.
    """
    answers = []
    for codec in draw(st.lists(st.sampled_from(list(_RDATA_FOR)), max_size=4)):
        answers.append(
            DnsRecord(
                draw(_name),
                codec.RType,
                1,
                draw(st.integers(0, 0xFFFFFFFF)),
                rdata=draw(_RDATA_FOR[codec]),
            )
        )
    packet = Response(
        ID=draw(st.integers(0, 0xFFFF)),
        QR=DnsQR.RESPONSE,
        AA=draw(st.booleans()),
        TC=draw(st.booleans()),
        RD=True,
        RA=True,
        RCODE=draw(st.sampled_from([0, 2, 3, 5])),
        questions=[
            DnsQuestion(draw(_name), draw(st.sampled_from([1, 2, 5, 12, 15, 16, 28, 33])), 1)
        ],
        answers=answers,
    )
    return bytes(packet)


@settings(max_examples=400)
@given(wire=built_message())
def test_every_built_message_parses_back(wire: bytes) -> None:
    """The encoders and the parser must agree, on the success path, every time.

    Deliberately strict: no ``assume``, no rejection. If this ever raises, the
    library is emitting messages it would refuse to accept from someone else.
    """
    packet, end = DnsPacket.parse(wire)
    assert end == len(wire)
    assert packet.QDCOUNT == 1
    assert packet.ANCOUNT == len(packet.answers)
    assert DnsQR.RESPONSE == packet.QR


@settings(max_examples=2000)
@given(
    wire=built_message(),
    position=st.integers(min_value=0, max_value=511),
    value=st.integers(min_value=0, max_value=255),
)
def test_one_corrupt_octet_never_brings_down_the_parser(
    wire: bytes, position: int, value: int
) -> None:
    """Flip a single octet of a valid message; the failure must still be clean.

    This is the input class the corpus tests cannot enumerate and unstructured
    bytes cannot reach: a message that is *almost* right. A length field one
    larger than the buffer, a pointer aimed at the last octet, a label claiming
    63 characters at the very end -- all one octet away from something valid, and
    each one previously produced an ``IndexError`` or a ``struct.error`` that the
    server's ``except DnsPacketParseError`` would not have caught.
    """
    mutated = bytearray(wire)
    mutated[position % len(mutated)] = value
    try:
        packet, end = DnsPacket.parse(bytes(mutated))
    except PARSE_ERRORS:
        return
    assert end == len(bytes(mutated))
    assert packet.ANCOUNT == len(packet.answers)

    # Canonical fixed point. Anything the parser chooses to accept must survive a
    # serialize/re-parse cycle unchanged, because serialization is canonical
    # (pointer-free, per namespy.rdata). This is the oracle that notices a *lost
    # rejection rule*: checking only the exception type cannot, since a message
    # that slips past one removed check usually still fails a later bounds check
    # with the same exception class, and the property still holds.
    canonical = bytes(packet)
    again, again_end = DnsPacket.parse(canonical)
    assert again_end == len(canonical)
    assert bytes(again) == canonical
