r"""The SvcParams wire format: framing, ordering, and what makes an RR malformed.

``test_svcb_rdata.py`` works one level up, from whole RDATA octets through
:class:`namespy.rdata.RData_SVCB`, and pins the Appendix D vectors. This module goes
directly at :meth:`namespy.svcb.SvcParams.from_wire` and
:meth:`namespy.svcb.SvcbCandidate.from_wire`, because two things only show up at that
granularity: the framing failures *between* parameters, and the per-key value checks
that section 2.2 makes a condition of the whole RRset.

That second group is the one worth reading closely. A SvcParam whose value does not
match its key's definition is malformed (section 2.2), and a malformed RR means the
client "MUST reject the entire RRset and fall back to non-SVCB connection
establishment". An unknown key, by contrast, is skipped by length and kept for
re-export (sections 2.4.3, 4.3) -- so the two paths through the loop have to stay
separate, and every known key has to actually be recognized as known.
"""

import struct

import pytest

from namespy.names import DomainName
from namespy.svcb import SvcbCandidate, SvcParamError, SvcParams
from namespy.wire import DnsPacketParseError

# Octet-level helpers, spelled out rather than computed, so a change in the encoder
# cannot quietly move the expectation along with it.
PORT_53 = b"\x00\x03\x00\x02\x00\x35"
ALPN_H2 = b"\x00\x01\x00\x03\x02h2"
NO_DEFAULT_ALPN = b"\x00\x02\x00\x00"
IPV4HINT_192_0_2_1 = b"\x00\x04\x00\x04\xc0\x00\x02\x01"
ECH_OPAQUE = b"\x00\x05\x00\x02\x41\x42"
DOHPATH = b"\x00\x07\x00\x10/dns-query{?dns}"
KEYNNNNN_HELLO = b"\xff\x35\x00\x05hello"


def parse(blob: bytes) -> SvcParams:
    """Decode SvcParams from a buffer that holds nothing but SvcParams."""
    params, end = SvcParams.from_wire(blob)
    assert end == len(blob), "the parser must report having consumed everything"
    return params


# ------------------------------------------------------------------- framing


def test_parameters_are_read_until_the_end_of_the_buffer() -> None:
    """Section 2.2: the SvcParams consume "the remainder of the record"."""
    params = parse(ALPN_H2 + PORT_53)
    assert list(params) == [1, 3]
    assert params.port == 53
    assert params.alpn == [b"h2"]


def test_a_trailing_partial_parameter_header_is_refused() -> None:
    r"""Two octets left is not a SvcParam: there is no SvcParamValue length to read.

    The alternative -- stopping quietly -- would report a record as complete while
    dropping part of it, which is precisely what section 2.2's first malformed
    condition, "the end of the RDATA occurs within a SvcParam", rules out.
    """
    with pytest.raises(DnsPacketParseError, match="not enough for a SvcParamKey"):
        parse(b"\x00\x03\x00")
    with pytest.raises(DnsPacketParseError, match="not enough for a SvcParamKey"):
        parse(PORT_53 + b"\x00\x01")


def test_a_value_claiming_more_octets_than_remain_is_refused() -> None:
    """A SvcParamValue length that overruns the record cannot be trusted or skipped.

    The value length is the only thing that lets a parser find the next parameter, so
    an overlong claim means the rest of the record is unreadable rather than merely
    wrong. The message quotes both numbers, since that difference is what an operator
    needs in order to tell a truncated datagram from a corrupt record.
    """
    with pytest.raises(DnsPacketParseError, match="declares a 6-octet SvcParamValue but only 3"):
        parse(b"\x00\x01\x00\x06\x02h2")


def test_an_unknown_key_is_skipped_by_length_and_kept() -> None:
    r"""Section 2.4.3: "clients MUST ignore any SvcParam that they do not recognize".

    Ignored means *not acted on*, not discarded: section 4.3 requires a resolver to
    convey unrecognized keys onward, and the only way to reproduce octets it cannot
    interpret is to have never touched them. Hence byte-for-byte re-encoding, and hence
    a loop that keeps going rather than stopping at the first key it cannot read -- a
    record with two unrecognized keys loses the second one otherwise.
    """
    params = parse(KEYNNNNN_HELLO)
    assert params.unknown_keys == (65333,)
    assert params.has_unknown_keys
    assert params.to_wire() == KEYNNNNN_HELLO
    assert params[65333] == b"hello"

    two = parse(b"\x00\x08\x00\x01\x41" + KEYNNNNN_HELLO)
    assert two.unknown_keys == (8, 65333)
    assert two.to_wire() == b"\x00\x08\x00\x01\x41" + KEYNNNNN_HELLO


def test_a_key_with_no_value_definition_stays_opaque_and_the_loop_continues() -> None:
    """``ech`` is in Table 1 with a reference of "N/A", so there is nothing to check.

    Being registered buys it conveyance, not interpretation: the octets are stored
    unchecked and reported as unknown, which is the honest answer about a value whose
    format no specification defines. It is also the case that proves the loop resumes,
    because a key this module *can* read follows it -- RFC 9460 has no rule that
    uninterpretable keys form a suffix.
    """
    params = parse(ECH_OPAQUE + DOHPATH)
    assert params.unknown_keys == (5,)
    assert params.dohpath == "/dns-query{?dns}"
    assert params.to_wire() == ECH_OPAQUE + DOHPATH


@pytest.mark.parametrize(
    ("blob", "reason"),
    [
        (PORT_53 + PORT_53, "duplicate SvcParamKey port"),
        (ALPN_H2 + ALPN_H2, "duplicate SvcParamKey alpn"),
    ],
    ids=["port", "alpn"],
)
def test_a_repeated_key_is_refused(blob: bytes, reason: str) -> None:
    """Section 2.2 says keys are strictly increasing and notes that "implies that there
    are no duplicate SvcParamKeys" -- so the same key twice is refused by name rather
    than by the ordering rule, because "duplicate" is the more useful diagnosis."""
    with pytest.raises(DnsPacketParseError, match=reason):
        parse(blob)


def test_descending_key_order_is_refused() -> None:
    """Ascending order is what makes two records comparable and keys addressable once."""
    with pytest.raises(DnsPacketParseError, match="ascending numeric order"):
        parse(PORT_53 + ALPN_H2)


def test_the_reserved_invalid_key_is_refused_in_position() -> None:
    r"""Table 1 reserves 65535 as "Invalid key", "MUST NOT be used".

    Checked where the key is read rather than after its value, so the offset in the
    message points at the key rather than at the end of its value.
    """
    with pytest.raises(DnsPacketParseError, match='reserved "Invalid key"'):
        parse(b"\xff\xff\x00\x00")


def test_empty_params_decode_and_encode_as_nothing() -> None:
    """A record with no SvcParams is normal -- it is Figure 1 and Figure 2."""
    assert parse(b"").to_wire() == b""
    assert len(parse(b"")) == 0


# ------------------------------------------------ per-key value validation

# One bad SvcParamValue per key this module defines a format for. Each is a
# different way of disagreeing with the key's own section, and each must make the
# record malformed rather than merely unreadable to this implementation.
BAD_VALUES = [
    pytest.param(1, b"\x03h2", "protocol id at offset", id="alpn-framing"),
    pytest.param(3, b"\x35", "2-octet integer", id="port-one-octet"),
    pytest.param(3, b"\x00\x035", "2-octet integer", id="port-three-octets"),
    pytest.param(2, b"\x41", "key-only SvcParam", id="no-default-alpn-not-empty"),
    pytest.param(4, b"\xc0\x00\x02", "not a whole number of 4-octet", id="ipv4hint-truncated"),
    pytest.param(4, b"", "at least one address", id="ipv4hint-empty"),
    pytest.param(6, b"\xc0\x00\x02\x01", "not a whole number of 16-octet", id="ipv6hint-v4-sized"),
    pytest.param(0, b"\x00\x04\x00\x01", "strictly increasing", id="mandatory-descending"),
    pytest.param(0, b"\x00\x01\x00\x01", "strictly increasing", id="mandatory-duplicate"),
    pytest.param(0, b"\x00\x00", "its own value-list", id="mandatory-self-reference"),
    pytest.param(0, b"\xff\xff", "reserved key", id="mandatory-reserved-key"),
    pytest.param(0, b"\x00\x00\x00", "whole number of 2-octet", id="mandatory-odd-length"),
    pytest.param(7, b"", "URI Template", id="dohpath-empty"),
]


@pytest.mark.parametrize(("key", "value", "reason"), BAD_VALUES)
def test_a_value_that_disagrees_with_its_key_is_malformed(key, value, reason) -> None:
    r"""Section 2.2's third malformed condition, one key at a time.

    "the SvcParamValue for a SvcParamKey does not have the expected format" -- and
    the consequence is not local: "a client receiving an RR with a malformed
    SvcParamValue MUST treat the entire RRset as malformed", because the alternative
    is a client silently acting on half of a record it could not read.

    The check that fired has to be in the message, since that is the difference
    between "this sender is broken" and "this datagram was cut short".
    """
    with pytest.raises(DnsPacketParseError, match="malformed"):
        parse(struct.pack("!HH", key, len(value)) + value)
    with pytest.raises(DnsPacketParseError, match=reason):
        parse(struct.pack("!HH", key, len(value)) + value)


VALID_VALUES = [
    pytest.param(0, b"\x00\x01\x00\x04", id="mandatory"),
    pytest.param(1, b"\x02h2\x05h3-19", id="alpn"),
    pytest.param(2, b"", id="no-default-alpn"),
    pytest.param(3, b"\x00\x35", id="port"),
    pytest.param(4, b"\xc0\x00\x02\x01", id="ipv4hint"),
    pytest.param(6, bytes(16), id="ipv6hint"),
    pytest.param(7, b"/dns-query{?dns}", id="dohpath"),
]


@pytest.mark.parametrize(("key", "value"), VALID_VALUES)
def test_a_registered_key_is_not_reported_as_unknown(key, value) -> None:
    r"""The line between "malformed" and "ignore it" is drawn by knowing the key.

    A key with a defined value format has its value checked; a key without one is
    stored opaque. Both are correct behaviour for their own key, and they are not
    interchangeable -- so a registered key arriving on the opaque path would mean a
    record with a corrupt ``port`` silently becoming a record with no ``port``.
    """
    params = parse(struct.pack("!HH", key, len(value)) + value)
    assert params.unknown_keys == ()
    assert params.get(key) == value
    assert params.to_wire() == struct.pack("!HH", key, len(value)) + value


# ------------------------------------------------------ the container protocol


def test_absent_and_present_are_distinguishable() -> None:
    r"""``port=0`` is a statement; no ``port`` at all is a different one.

    Section 7.2: "If this key is not present, clients SHALL use the authority
    endpoint's port number". So a caller cannot treat None and 0 alike, which is why
    both the container protocol and the typed accessor report absence as None and the
    published zero as 0.
    """
    absent = parse(b"")
    zero = parse(b"\x00\x03\x00\x02\x00\x00")
    assert absent.port is None
    assert "port" not in absent
    assert zero.port == 0
    assert "port" in zero
    assert absent.get("port") is None
    assert absent.get("port", b"?") == b"?"
    assert zero.get("port") == b"\x00\x00"
    with pytest.raises(KeyError, match="port"):
        absent["port"]


def test_keys_are_addressable_by_name_as_well_as_by_number() -> None:
    """The two spellings of a key have to reach the same value, including ``keyNNNNN``."""
    params = parse(PORT_53 + KEYNNNNN_HELLO)
    assert params["key65333"] == params[65333] == b"hello"
    assert params["port"] == params[3] == b"\x00\x35"
    assert 3 in params
    assert "key3" in params
    assert "65333" not in params  # section 2.1 spells an unregistered key keyNNNNN
    assert 1 not in params
    assert "no-such-key" not in params


def test_iterating_and_len_cover_known_and_unknown_keys_alike() -> None:
    """Ignoring a key means not acting on it, not failing to see it: 4.3 forwards it."""
    params = parse(ALPN_H2 + PORT_53 + KEYNNNNN_HELLO)
    assert list(params) == [1, 3, 65333]
    assert len(params) == 3


def test_typed_accessors_read_the_wire_octets_of_a_received_record() -> None:
    """Everything a client needs after decoding, converted per key on access.

    Values are stored as octets and converted on access precisely so that a record
    carrying a key invented next year still gives up its ``alpn`` and its hints.
    """
    blob = (
        b"\x00\x00\x00\x04\x00\x01\x00\x04"  # mandatory=alpn,ipv4hint
        + b"\x00\x01\x00\x09\x02h2\x05h3-19"
        + NO_DEFAULT_ALPN
        + PORT_53
        + IPV4HINT_192_0_2_1
        + b"\x00\x06\x00\x20"
        + bytes.fromhex("20010db8000000000000000000000001") * 2
        + DOHPATH
    )
    params = parse(blob)
    assert params.mandatory == (1, 4)
    assert params.is_mandatory("alpn")
    assert params.is_mandatory(4)
    assert not params.is_mandatory("port")
    assert params.alpn == [b"h2", b"h3-19"]
    assert params.no_default_alpn
    assert params.port == 53
    assert params.ipv4hint == ["192.0.2.1"]
    assert params.ipv6hint == ["2001:db8::1", "2001:db8::1"]
    assert params.dohpath == "/dns-query{?dns}"
    assert params.to_presentation() == (
        "mandatory=alpn,ipv4hint alpn=h2,h3-19 no-default-alpn port=53 "
        "ipv4hint=192.0.2.1 ipv6hint=2001:db8::1,2001:db8::1 dohpath=/dns-query{?dns}"
    )


def test_a_mandatory_key_this_module_cannot_read_is_identifiable() -> None:
    """Section 8's compatibility test, as a lookup rather than as a decision.

    :meth:`SvcParams.unrecognized_mandatory_keys` is the half of it this layer can
    answer -- which listed keys have no value definition here. Whether that makes the
    record unusable depends on the client's own key set, which is
    :meth:`SvcbCandidate.compatibility_problems`'s business.
    """
    params = parse(b"\x00\x00\x00\x02\xff\x35" + ALPN_H2 + KEYNNNNN_HELLO)
    assert params.mandatory == (65333,)
    assert params.unrecognized_mandatory_keys() == (65333,)
    assert parse(b"\x00\x00\x00\x02\x00\x03" + PORT_53).unrecognized_mandatory_keys() == ()
    assert parse(b"").unrecognized_mandatory_keys() == ()


def test_params_compare_by_content_and_hash_alike() -> None:
    """Needed because :class:`SvcbCandidate` is a frozen dataclass holding these.

    Which keys happened to be unrecognized describes what a client could read, not
    what the record says, so it is outside both ``__eq__`` and ``__hash__`` -- the two
    have to agree or the objects misbehave as dict keys.
    """
    one = SvcParams([("port", b"\x00\x53")])
    assert one == SvcParams([(3, b"\x00\x53")])
    assert len({one, SvcParams([("port", b"\x00\x53")])}) == 1
    assert hash(one) == hash(SvcParams([("port", b"\x00\x53")]))
    assert one.__eq__("port=53") is NotImplemented


def test_building_params_validates_the_value_and_rejects_a_repeated_key() -> None:
    """The generator's path is held to the same rules as the parser's.

    A hand-built ``SvcParams`` becomes a wire record, so a 1-octet ``port`` here would
    leave this module as a malformed RR on someone else's network -- which is exactly
    what section 2.2 tells the receiving client to reject the whole RRset for.
    """
    with pytest.raises(SvcParamError, match='SvcParamKey "port"'):
        SvcParams([("port", b"\x35")])
    with pytest.raises(SvcParamError, match="duplicate SvcParamKey"):
        SvcParams([("port", b"\x00\x53"), (3, b"\x00\x35")])
    with pytest.raises(SvcParamError, match='reserved "Invalid key"'):
        SvcParams([(65535, b"")])
    with pytest.raises(SvcParamError, match="invalid SvcParamKey"):
        SvcParams([("Port", b"")])


# ------------------------------------------------------- a whole RDATA, decoded

RDATA = b"\x00\x10"  # SvcPriority 16
TARGET = b"\x03foo\x07example\x03com\x00"


def test_rdata_is_priority_then_target_then_params() -> None:
    """Section 2.2's layout, with no length of its own before the parameters."""
    record = SvcbCandidate.from_wire("svc.example.com.", RDATA + TARGET + PORT_53)
    assert record.priority == 16
    assert record.target == DomainName("foo.example.com.")
    assert record.owner == DomainName("svc.example.com.")
    assert record.effective_target == DomainName("foo.example.com.")
    assert record.to_wire() == RDATA + TARGET + PORT_53
    assert not record.target_is_root


def test_a_root_target_is_the_owner_name_only_in_servicemode() -> None:
    r"""Section 2.5: the same octets, two meanings, decided by SvcPriority.

    ``.`` in ServiceMode means "these parameters apply to the owner name", so
    :attr:`effective_target` synthesizes it; in AliasMode it is the section 2.5.1
    announcement that the service does not exist, which has to stay visible as a root
    rather than be quietly rewritten.
    """
    service = SvcbCandidate.from_wire("svc.example.com.", b"\x00\x10\x00" + PORT_53)
    assert service.target_is_root
    assert service.effective_target == DomainName("svc.example.com.")
    alias = SvcbCandidate.from_wire("svc.example.com.", b"\x00\x00\x00")
    assert alias.target_is_root
    assert alias.is_alias
    assert alias.effective_target == DomainName("")


def test_rdata_too_short_or_with_an_orphan_octet_is_refused() -> None:
    """The two framing failures that belong to the record rather than to a parameter.

    Under three octets there is no TargetName field to read. A stray octet after the
    last complete SvcParam is the section 2.2 condition "the end of the RDATA occurs
    within a SvcParam", and it has to be refused rather than shrugged off: the only
    ways to account for that octet are to pretend a parameter is shorter than it says
    or to invent one, and either way the record that gets reported is not the one that
    was sent.
    """
    with pytest.raises(DnsPacketParseError, match="too short"):
        SvcbCandidate.from_wire("example.com.", b"\x00\x10")
    with pytest.raises(DnsPacketParseError, match="too short"):
        SvcbCandidate.from_wire("example.com.", b"")
    with pytest.raises(DnsPacketParseError, match="not enough for a SvcParamKey"):
        SvcbCandidate.from_wire("example.com.", RDATA + TARGET + PORT_53 + b"\x00")
    with pytest.raises(DnsPacketParseError, match="declares a 2-octet SvcParamValue"):
        SvcbCandidate.from_wire("example.com.", RDATA + TARGET + b"\x00\x03\x00\x02\x00")


def test_a_record_is_renderable_as_master_file_rdata() -> None:
    """Section 2.1's RDATA order, so a decoded answer can go into a zone file."""
    record = SvcbCandidate.from_wire("svc.example.com.", RDATA + TARGET + PORT_53)
    assert str(record) == "16 foo.example.com. port=53"
    assert SvcbCandidate.from_presentation("svc.example.com.", str(record)) == record
    assert SvcbCandidate.from_presentation("svc.example.com.", "1 .").to_wire() == b"\x00\x01\x00"


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("", "at least a SvcPriority"),
        ("1", "needs a TargetName"),
        ("port=53 foo.example.com.", "not a decimal integer"),
        ("65536 foo.example.com.", "outside 0..65535"),
        ("-1 foo.example.com.", "outside 0..65535"),
    ],
    ids=["empty", "no-target", "priority-not-a-number", "priority-too-big", "priority-negative"],
)
def test_rejected_master_file_rdata(text: str, reason: str) -> None:
    """Each failure says which of the three RDATA fields it is complaining about."""
    with pytest.raises(ValueError, match=reason):
        SvcbCandidate.from_presentation("svc.example.com.", text)
