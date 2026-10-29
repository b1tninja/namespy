r"""Appendix A and A.1: the two decoding stages of a SvcParamValue, in order.

Section 2.1 decodes a SvcParamValue with the character-string algorithm of
Appendix A; Appendix A.1 then splits the *decoded* value on commas, where ``\,``
is a comma belonging to an item and ``\\`` a backslash belonging to one. The two
stages are easy to swap and the failure is silent -- split first and one protocol
id becomes two -- so what follows pins the RFC's own examples and every value
that has to survive a round trip.

The wire-side checks that section 2.2 makes malformed are in
``test_svcb_wire.py``; the RRset-level rules of sections 2.4 and 3 are in
``test_svcb_selection.py``.
"""

import pytest

from namespy.svcb import (
    SvcParamError,
    SvcParams,
    decode_charstring,
    encode_charstring,
    join_value_list,
    key_from_name,
    key_to_name,
    split_value_list,
    value_from_presentation,
    value_to_presentation,
)
from namespy.wire import DnsPacketParseError

# ------------------------------------------------- Appendix A: decoding


def test_three_digits_are_decimal_not_octal():
    r"""Appendix A's dec-octet is decimal: Figure 6's ``\210`` is octet 0xD2.

    Read as octal it is 0x88 -- a different octet, from a spelling that looks
    perfectly ordinary, which is the whole reason the production is written as
    three decimal digits.
    """
    assert decode_charstring(r"hello\210qoo") == b"hello\xd2qoo"


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        (r"\300", r"outside the 0-255 range"),
        ("abc" + chr(92), "dangling backslash"),
        ("\u20ac", "not a single octet"),
        (chr(92) + "\u20ac", "not a single octet"),
        ('"abc', "unterminated quoted string"),
    ],
    ids=["above-255", "dangling", "literal-non-octet", "escaped-non-octet", "unterminated-quote"],
)
def test_rejected_character_strings(text, reason):
    r"""``\300`` is not a spelling of anything: dec-octet stops at 255.

    The two non-octet cases are this module's own, because a master file is
    read into str: a character above U+00FF cannot become one octet, and
    silently truncating it would corrupt the record rather than reject it.
    """
    with pytest.raises(SvcParamError, match=reason):
        decode_charstring(text)


def test_the_two_documented_leniencies():
    r"""Accepted because RFC 1035 section 5.1 gives no way to report them.

    A backslash in front of fewer than three digits quotes the digit that
    follows and leaves the rest alone, and quoting an ordinary character is
    that character. Both are things a hand-edited zone file contains.
    """
    assert decode_charstring(r"\12") == b"12"
    assert decode_charstring(r"\a") == b"a"


def test_quoting_groups_octets_that_would_end_the_token():
    r"""A quoted char-string holds what an unquoted one could not: spaces."""
    assert decode_charstring('"a b"') == b"a b"
    assert decode_charstring('"h' + chr(92) + ',2"') == b"h,2"


# ------------------------------------------------- Appendix A: encoding


@pytest.mark.parametrize(
    ("octets", "spelling"),
    [
        (b"h2", "h2"),
        (b"a,b", "a,b"),
        (b"a=b", "a=b"),
        (b"a b", "a\\032b"),
        (b'a"b', "a\\034b"),
        (b"a;b", "a\\059b"),
        (b"a(b)c", "a\\040b\\041c"),
        (b"a\\b", "a\\\\b"),
        (b"\x00\xff", "\\000\\255"),
    ],
    ids=[
        "plain",
        "comma",
        "equals",
        "space",
        "double-quote",
        "semicolon",
        "parentheses",
        "backslash",
        "non-printable",
    ],
)
def test_encoding_escapes_in_decimal(octets, spelling):
    r"""Token-ending and non-printable octets become ``\DDD``, always decimal.

    Space is ``\032`` rather than ``\040``: the same decimal reading that
    :func:`decode_charstring` insists on, applied on the way out. A comma and an
    ``=`` stay bare deliberately, because Appendix A's ``non-special`` allows
    both and section 2.1 separates SvcParams with whitespace rather than commas.
    """
    assert encode_charstring(octets) == spelling


@pytest.mark.parametrize(
    "octets",
    [b"", b"h2", b"a,b", b"a\\b", b"a\\,b", b"\x00\xff ", b'";()', b"f\\oo,bar"],
    ids=[
        "empty",
        "plain",
        "comma",
        "backslash",
        "escaped-comma",
        "nul-and-space",
        "delimiters",
        "both-at-once",
    ],
)
def test_encoding_round_trips(octets):
    r"""The property that makes a zone file this module wrote safe to read back."""
    assert decode_charstring(encode_charstring(octets)) == octets


# ---------------------------------------------- Appendix A.1: value lists


def test_appendix_a1_worked_example():
    r"""Appendix A.1's example, in a third spelling of the same input.

    The RFC prints two equivalent zone-file spellings; ``\092`` escapes are a
    third that decodes to the same value, so the assertion does not depend on
    how either of them is quoted. Value-list decoding gives three items, the
    last of them ``part3,part4\``.
    """
    value = decode_charstring(r"part1,part2,part3\092,part4\092\092")
    assert value == rb"part1,part2,part3\,part4\\"
    assert split_value_list(value, what="example") == [b"part1", b"part2", b"part3,part4\x5c"]


@pytest.mark.parametrize(
    ("octets", "reason"),
    [
        (rb"a,,b", "empty item"),
        (b",", "empty item"),
        (rb"a,", "ends with a separator"),
        (rb"a" + b"\\", "dangling escape"),
    ],
    ids=["empty-in-middle", "only-a-comma", "trailing-comma", "dangling-escape"],
)
def test_rejected_value_lists(octets, reason):
    r"""A.1: "For simplicity, empty items are not allowed"."""
    with pytest.raises(SvcParamError, match=reason):
        split_value_list(octets, what="alpn value")


@pytest.mark.parametrize(
    "items",
    [[b"h2", b"h3-19"], [b"a,b"], [b"a\\b"], [b"f\\oo,bar"], [b"a\\b", b"c,d"]],
    ids=["plain", "data-comma", "data-backslash", "both", "mixed"],
)
def test_join_and_split_are_inverses(items):
    r"""What a generated ``alpn=`` or ``ipv4hint=`` list has to guarantee."""
    assert split_value_list(join_value_list(items), what="alpn value") == items


# ------------------------------------------------- section 2.1: key names


@pytest.mark.parametrize(
    ("number", "name"),
    [
        (0, "mandatory"),
        (1, "alpn"),
        (2, "no-default-alpn"),
        (3, "port"),
        (4, "ipv4hint"),
        (5, "ech"),
        (6, "ipv6hint"),
        (7, "dohpath"),
    ],
)
def test_registered_key_names_round_trip(number, name):
    """Section 14.3.2 Table 1's registrations, read in both directions."""
    assert key_to_name(number) == name
    assert key_from_name(name) == number


@pytest.mark.parametrize("number", [8, 100, 667, 65534])
def test_unregistered_keys_use_the_keynnnnn_form(number):
    r"""Section 2.1: "NNNNN is the numeric value of the key type without leading zeros"."""
    assert key_from_name(f"key{number}") == number
    assert key_to_name(number) == f"key{number}"


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("Port", "invalid SvcParamKey"),
        ("a" * 64, "1-63 characters"),
        ("no-such-key", "unknown SvcParamKey"),
        ("-", "unknown SvcParamKey"),
        ("key00003", "unknown SvcParamKey"),
        ("key65535", 'reserved "Invalid key"'),
        ("key70000", "outside 0-65535"),
    ],
    ids=[
        "uppercase",
        "too-long",
        "invented-name",
        "syntax-ok-unregistered",
        "leading-zeros",
        "reserved-key",
        "out-of-range",
    ],
)
def test_rejected_key_names(name, reason):
    r"""Uppercase is not a spelling of a key: section 2.1's ABNF is ``a-z`` only.

    ``-`` is the case worth naming: it is valid SvcParamKey *syntax*, so it is
    reported as unregistered rather than malformed. That distinction is what
    lets a key a future RFC registers read as a key rather than as an error.
    """
    with pytest.raises(SvcParamError, match=reason):
        key_from_name(name)


# ------------------------------------------- section 7: values, both ways


@pytest.mark.parametrize(
    ("key", "token", "wire"),
    [
        (3, "8443", b"\x20\xfb"),
        (3, "0", b"\x00\x00"),
        (1, "h2", b"\x02h2"),
        (1, "h2,h3-19", b"\x02h2\x05h3-19"),
        (2, "", b""),
        (4, "192.0.2.1,192.0.2.2", b"\xc0\x00\x02\x01\xc0\x00\x02\x02"),
        (6, "2001:db8::1", bytes.fromhex("20010db8000000000000000000000001")),
        (7, "/dns-query{?dns}", b"/dns-query{?dns}"),
        (0, "port,alpn", b"\x00\x01\x00\x03"),
        (65333, "hello", b"hello"),
        (65333, "a=b", b"a=b"),
        (5, "anything", b"anything"),
    ],
    ids=[
        "port",
        "port-zero",
        "alpn-one",
        "alpn-list",
        "no-default-alpn-empty",
        "ipv4hint-pair",
        "ipv6hint",
        "dohpath",
        "mandatory-sorted",
        "unknown-opaque",
        "unknown-with-equals",
        "ech-opaque",
    ],
)
def test_presentation_value_to_wire(key, token, wire):
    r"""The conversions section 2.1 asks for, one key at a time.

    Two cases are load-bearing rather than exhaustive. ``mandatory=port,alpn``
    comes out in ascending numeric order because section 2.2 requires the wire
    form to be ordered, whatever order the zone file used. And a ``keyNNNNN``
    value's decoded octets *are* its wire encoding -- "the decoded value SHALL be
    used as its wire-format encoding" -- which is what lets a resolver convey a
    key it has never heard of.
    """
    assert value_from_presentation(key, token) == wire


@pytest.mark.parametrize(
    ("key", "token", "reason"),
    [
        (3, "65536", "not a decimal integer"),
        (3, "http", "not a decimal integer"),
        (3, "80,443", "not a decimal integer"),
        (3, "8" + chr(92) * 2 + "4", "MUST NOT contain escape sequences"),
        (4, "192.0.2", "not a valid IPv4 address"),
        (6, "192.0.2.1", "not a valid IPv6 address"),
        (4, "", "at least one address"),
        (1, "h2,,h3", "empty item"),
        (1, "a" * 256, "over the 255"),
        (2, "x", "must be empty"),
        (0, "mandatory", "MUST NOT appear in its own value-list"),
        (0, "alpn,alpn", "more than once"),
        (7, "https://x.example/dns", "relative form"),
        (7, "", "empty"),
    ],
    ids=[
        "port-too-big",
        "port-not-a-number",
        "port-a-list",
        "port-with-escape",
        "hint-v4-truncated",
        "hint-v6-wrong-family",
        "hint-empty",
        "alpn-empty-item",
        "alpn-too-long",
        "no-default-alpn-with-value",
        "mandatory-self",
        "mandatory-duplicate",
        "dohpath-absolute",
        "dohpath-empty",
    ],
)
def test_rejected_presentation_values(key, token, reason):
    r"""Each of these is a section 7 or Appendix D failure spelled in a zone file.

    The port escape case is the one that reads oddly: section 7.2 bans escape
    sequences so that "to enable simpler parsing" holds, so a decoded backslash
    is refused even though the octets it denotes would have parsed fine.

    Both error types are accepted because a value this bad is a *syntax* problem
    on the way in: :exc:`~namespy.svcb.SvcParamError` for a value the key's
    definition rejects, :exc:`~namespy.wire.DnsPacketParseError` for the RFC 9461
    template rule that is stated as a format rather than a key definition.
    """
    with pytest.raises((SvcParamError, DnsPacketParseError), match=reason):
        value_from_presentation(key, token)


@pytest.mark.parametrize(
    ("key", "wire", "spelling"),
    [
        (3, b"\x20\xfb", "8443"),
        (1, b"\x02h2\x05h3-19", "h2,h3-19"),
        (2, b"", ""),
        (4, b"\xc0\x00\x02\x01", "192.0.2.1"),
        (6, bytes.fromhex("20010db80122034400000000c0000221"), "2001:db8:122:344::c000:221"),
        (7, b"/dns-query{?dns}", "/dns-query{?dns}"),
        (0, b"\x00\x01\x00\x03", "alpn,port"),
        (65333, b"hello\x00", "hello\\000"),
        (5, b"\x01\x02", "\\001\\002"),
    ],
    ids=[
        "port",
        "alpn-list",
        "no-default-alpn",
        "ipv4hint",
        "ipv6hint-canonical",
        "dohpath",
        "mandatory",
        "unknown-nul",
        "ech-opaque",
    ],
)
def test_wire_value_to_presentation(key, wire, spelling):
    r"""What a resolver has to emit when it prints an RR it merely received.

    The ipv6hint case is the one a hand-rolled formatter gets wrong: section 7.3
    makes the canonical text RFC 5952's, so Appendix D Figure 7's embedded-IPv4
    spelling ``2001:db8:122:344::192.0.2.33`` comes back as ``::c000:221`` --
    the same address written the way the standard text writes it, which is also
    what makes the round trip stable.
    """
    assert value_to_presentation(key, wire) == spelling


@pytest.mark.parametrize(
    ("key", "wire"),
    [
        (1, b"\x08f\\oo,bar"),
        (1, b"\x02h2\x05h3-19"),
        (4, b"\xc0\x00\x02\x01\xc0\x00\x02\x02"),
        (0, b"\x00\x01\x00\x04"),
        (65333, b"a,b\\c"),
        (5, b"\x00\x01\x02\xff"),
    ],
    ids=[
        "alpn-comma-and-backslash",
        "alpn-plain",
        "ipv4hint-pair",
        "mandatory",
        "unknown-comma-and-backslash",
        "unknown-nul-and-ff",
    ],
)
def test_generated_spelling_reparses_to_the_same_wire_value(key, wire):
    """Regeneration property, including the values that need escaping twice."""
    assert value_from_presentation(key, value_to_presentation(key, wire)) == wire


def test_a_protocol_id_containing_a_comma_and_a_backslash():
    r"""One alpn-id holding both characters that have to be escaped.

    Appendix D prints this value twice -- Figures 9 and 10, doubled characters
    and decimal escapes -- to demonstrate that they are one RDATA rather than
    two. This module writes the doubled form, which is a different spelling of
    the same octets rather than different octets, so what matters is that every
    spelling lands on the same wire value.
    """
    wire = b"\x08f\\oo,bar"
    doubled = value_to_presentation(1, wire)
    assert value_from_presentation(1, doubled) == wire
    assert value_from_presentation(1, r"f\\\092oo\092,bar") == wire
    assert SvcParams.from_presentation("alpn=" + doubled).alpn == [b"f\\oo,bar"]


# ------------------------------------------------ SvcParams as a whole


def test_presentation_round_trips_a_whole_parameter_list():
    r"""A zone file's ``key=value`` list, in and out.

    Ordering is the point as much as escaping: section 2.1 permits a zone file
    to write keys in any order, and :meth:`to_presentation` emits the numeric
    order the wire uses -- so reading a record and writing it back does not
    churn the file.
    """
    params = SvcParams.from_presentation("port=53 alpn=h2,h3")
    assert params.to_wire().hex() == "00010006026832026833000300020035"
    assert params.to_presentation() == "alpn=h2,h3 port=53"
    assert SvcParams.from_presentation(params.to_presentation()) == params


def test_quoting_reaches_a_value_through_the_parameter_list():
    r"""Appendix D Figure 5's lesson one level up: quotes group, they are not data."""
    assert SvcParams.from_presentation('key65333="a b"')[65333] == b"a b"


def test_a_key_without_an_equals_sign_is_the_empty_form():
    r"""Section 2.1: "When the optional '=' and SvcParamValue are omitted, the value is empty".

    This is how ``no-default-alpn`` is written, and why the form has to be
    accepted for a key-only parameter rather than rejected as a missing value.
    """
    assert (
        SvcParams.from_presentation("key65333 no-default-alpn").to_wire().hex()
        == "00020000ff350000"
    )
    assert SvcParams.from_presentation("").to_wire() == b""
    assert SvcParams.from_presentation("").to_presentation() == ""


def test_ech_is_conveyed_but_stays_opaque():
    r"""Table 1 registers key 5 with a reference of "N/A", so nothing reads its value.

    Section 4.3 still requires it to be forwarded, which is what
    :attr:`SvcParams.unknown_keys` exists for: it tells a caller that this RDATA
    carries something that could not be interpreted, without treating that as
    damage to the record.
    """
    params = SvcParams([("ech", b"\x01\x02")])
    assert params.has_unknown_keys
    assert params.unknown_keys == (5,)
    assert params.to_presentation() == "ech=\\001\\002"
    assert params.to_wire().hex() == "000500020102"


def test_repr_shows_raw_octets_and_marks_the_empty_ones():
    r"""A dash rather than nothing, so ``key=`` and ``key-`` are distinguishable here too."""
    assert repr(SvcParams([("port", b"\x00\x53")])) == "SvcParams(port=0053)"
    assert repr(SvcParams([("no-default-alpn", b"")])) == "SvcParams(no-default-alpn=-)"
    assert repr(SvcParams()) == "SvcParams()"
