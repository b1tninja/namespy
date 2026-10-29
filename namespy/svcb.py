"""Service parameters (SvcParams) for the SVCB and HTTPS RR types (RFC 9460).

Before this module existed, an ``HTTPS`` record (type 65) had no codec, so
:mod:`namespy.rdata` handed it to the caller as an RFC 3597 blob -- every
consumer that wanted the ALPN set or a port hint had to parse the record itself,
and the resolver could not see it at all. RFC 9460 is strict about that blob:
section 2.2 makes a record whose SvcParams do not parse *malformed*, and
"if any RRs are malformed, the client MUST reject the entire RRset". So this
module validates while it decodes, and reports every rule it enforces with a
section citation.

Two layers of text encoding are involved, and they compose -- which is the
subtlety that makes hand-rolled SVCB presentation parsers wrong:

1. **Character-string decoding** (RFC 1035 section 5.1, invoked by RFC 9460
   Appendix A) turns the master-file token into octets. Quoting is allowed,
   ``\\X`` means a literal *X*, and ``\\DDD`` means the octet whose value is the
   *decimal* number DDD -- not octal. Appendix D Figure 6 encodes
   ``hello\\210qoo`` as ``68 65 6c 6c 6f d2 71 6f 6f`` precisely because 210 is
   decimal, i.e. ``0xD2``; erratum 7871 was *rejected* over exactly this
   confusion.
2. **Value-list decoding** (Appendix A.1) then splits that octet string on
   commas, where ``\\,`` and ``\\\\`` are escapes: "Decoding of value-lists happens
   after character-string decoding". A.1's own worked example
   (``"part1,part2,part3\\,part4\\\\"`` -> ``part1``, ``part2``,
   ``part3,part4\\``) pins this down.

Encoding is the two inverses composed in the same order. A value containing both
a comma and a backslash therefore carries *doubled* backslashes on the wire --
which is why Appendix D Figure 10 prints ``alpn=f\\\\\\092oo\\092,bar,h2`` for the
protocol id ``f\\oo,bar``, and why this module round-trips that form.

.. rubric:: References

* RFC 9460 section 2.1 (presentation), section 2.2 (wire format and the
  malformed conditions), section 2.4 (AliasMode/ServiceMode), section 2.5
  (``.`` in TargetName), section 7 (initial SvcParamKeys), section 8 (mandatory
  keys and compatibility), section 14.3.2 Table 1 (key numbers), Appendix A/A.1
  (text decoding), Appendix D (test vectors)
* RFC 9461 sections 5 and 9 Table 1 (``dohpath``, number 7)
* Errata 7871 and 8168 (both rejected, both instructive): ``\\DDD`` is decimal,
  and every SvcParamValue -- even ``port`` -- is char-string encoded, so
  ``port="8004"`` is legal presentation for the value ``8004``.
"""

from __future__ import annotations

import ipaddress
import random
import re
import struct
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from enum import IntEnum
from typing import NamedTuple

from .names import DomainName
from .wire import DnsPacketParseError

#: Anything that names a SvcParamKey: its registered number, or its presentation
#: name (``"alpn"`` / ``"key667"``).
IntOrStr = int | str

__all__ = [
    "ALPN",
    "DOHPATH",
    "ECH",
    "HTTPS_AUTO_MANDATORY",
    "IPV4HINT",
    "IPV6HINT",
    "MANDATORY",
    "NO_DEFAULT_ALPN",
    "PORT",
    "SkippedRecord",
    "SvcParamError",
    "SvcParamKey",
    "SvcParams",
    "SvcbCandidate",
    "SvcbSelection",
    "UnknownKey",
    "key_from_name",
    "key_to_name",
    "select_records",
    "self_consistency_problems",
    "zone_file_warnings",
]


class SvcParamError(ValueError):
    """A SvcParam that cannot be built, decoded, or rendered.

    Wire decoding raises :class:`~namespy.wire.DnsPacketParseError` instead, so
    that a malformed record degrades to an opaque blob the way every other
    codec in :mod:`namespy.rdata` does rather than killing the caller.
    """


class SvcParamKey(IntEnum):
    """Registered SvcParamKey numbers (RFC 9460 section 14.3.2 Table 1).

    ``IPV6HINT`` is **6**, not 5: the registry holds number 5 for ``ech``
    (RESERVED for Encrypted ClientHello). Reading 5 as ``ipv6hint`` decodes
    every real-world ``alpn=..., ipv6hint=...`` record's hints as garbage.
    """

    MANDATORY = 0
    ALPN = 1
    NO_DEFAULT_ALPN = 2
    PORT = 3
    IPV4HINT = 4
    #: RESERVED in RFC 9460; no value format is defined, so it stays opaque.
    ECH = 5
    IPV6HINT = 6
    #: RFC 9461 section 9 Table 1.
    DOHPATH = 7


MANDATORY = SvcParamKey.MANDATORY
ALPN = SvcParamKey.ALPN
NO_DEFAULT_ALPN = SvcParamKey.NO_DEFAULT_ALPN
PORT = SvcParamKey.PORT
IPV4HINT = SvcParamKey.IPV4HINT
ECH = SvcParamKey.ECH
IPV6HINT = SvcParamKey.IPV6HINT
DOHPATH = SvcParamKey.DOHPATH

#: The largest number a SvcParamKey can carry on the wire.
MAX_KEY = 0xFFFF
#: 65280-65534 are "Reserved for Private Use" and 65535 is the reserved
#: "Invalid key" (section 14.3.2 Table 1), which MUST NOT appear on the wire.
PRIVATE_USE_FIRST = 0xFF00
PRIVATE_USE_LAST = 0xFFFE
RESERVED_INVALID_KEY = 0xFFFF

_KEY_NAMES: dict[int, str] = {
    int(key.value): key.name.lower().replace("_", "-") for key in SvcParamKey
}
_NAME_KEYS: dict[str, int] = {name: number for number, name in _KEY_NAMES.items()}

#: Keys whose value is a comma-separated list (Appendix A.1) rather than a
#: single value.
_LIST_KEYS = frozenset({int(ALPN), int(MANDATORY), int(IPV4HINT), int(IPV6HINT)})
#: Keys whose value MUST be empty -- section 7.1.1 for ``no-default-alpn``.
_EMPTY_VALUE_KEYS = frozenset({int(NO_DEFAULT_ALPN)})
#: Every key defined by RFC 9460/9461, i.e. what a client can be assumed to
#: "recognize" for section 8 compatibility purposes. ``ech`` is registered but
#: carries no defined value format, so it counts as recognized-but-opaque.
KNOWN_KEYS = frozenset(_KEY_NAMES)

#: The SvcParamKeys the HTTPS mapping makes mandatory without their being listed.
#: RFC 9460 section 9: "The 'automatically mandatory' keys (Section 8) are 'port'
#: and 'no-default-alpn'", repeated in Appendix B Table 3. Section 8 adds that a
#: client which does not recognize such a key "MUST ignore the RR containing that
#: SvcParamKey" -- so a client's key set must be tested against these even though
#: the record never says they are mandatory. Generic SVCB has no mapping and
#: therefore no automatically mandatory keys.
HTTPS_AUTO_MANDATORY = frozenset({int(PORT), int(NO_DEFAULT_ALPN)})

#: An alpn-id is 1-255 octets (section 7.1.1's ``alpn-id = 1*255OCTET``).
MAX_ALPN_ID_OCTETS = 255

_BACKSLASH = 0x5C
_COMMA = 0x2C

# ABNF section 2.1: SvcParamKey = 1*63(alpha-lc / DIGIT / "-")
_KEY_NAME_RE = re.compile(r"^[a-z0-9-]{1,63}$")
# section 2.1: "keyNNNNN where NNNNN is the numeric value ... without leading zeros"
_UNKNOWN_KEY_RE = re.compile(r"^key(0|[1-9][0-9]{0,4})$")


# ------------------------------------------------ stage 1: character-strings


def decode_charstring(text: str, *, what: str = "SvcParamValue") -> bytes:
    r"""Decode one master-file ``<character-string>`` to octets (Appendix A).

    RFC 1035 section 5.1 rules, as imported by RFC 9460 Appendix A: a ``"..."``
    segment is a quoted string (adjacent quoted and unquoted segments concatenate
    into one value), ``\X`` is a literal *X*, and ``\DDD`` is the octet given by
    the **decimal** digits DDD.

    The decimal reading is the one people get wrong, and it is not hypothetical:
    Appendix D Figure 6's ``hello\210qoo`` is ``68 65 6c 6c 6f d2 71 6f 6f``
    because 210 is decimal (``0xD2``). Reading it as octal gives ``0x88`` and a
    silently wrong value, which is why erratum 7871 was rejected rather than
    applied.

    Appendix A's grammar is ``escaped = '\' ( non-digit / dec-octet )``, where
    ``dec-octet`` tops out at ``255`` -- so ``\300`` is not a spelling of anything,
    and is rejected here rather than truncated to 44 the way a C-style parser
    would. Two leniencies are deliberate, because RFC 1035 section 5.1 itself has
    no way to report them: a backslash in front of one or two digits is taken as
    that many literal digits, and an escape that merely quotes an ordinary
    character (``\a``) is taken as that character.
    """
    out = bytearray()
    index = 0
    quoted = False
    length = len(text)
    while index < length:
        char = text[index]
        if char == '"':
            quoted = not quoted
            index += 1
            continue
        if char == "\\":
            digits = text[index + 1 : index + 4]
            if len(digits) == 3 and digits.isascii() and digits.isdigit():
                octet = int(digits)
                if octet > 255:
                    raise SvcParamError(
                        f"{what} contains \\{digits}, which is outside the 0-255 range "
                        "of Appendix A's dec-octet production"
                    )
                out.append(octet)
                index += 4
                continue
            if index + 1 >= length:
                raise SvcParamError(f"{what} ends with a dangling backslash escape")
            escaped = ord(text[index + 1])
            if escaped > 0xFF:
                raise SvcParamError(
                    f"{what} escapes U+{escaped:04X}, which is not a single octet; "
                    "write the UTF-8 bytes as \\DDD decimal escapes instead"
                )
            out.append(escaped)
            index += 2
            continue
        code = ord(char)
        if code > 0xFF:
            raise SvcParamError(
                f"{what} contains U+{code:04X}, which is not a single octet; "
                "write the UTF-8 bytes as \\DDD decimal escapes instead"
            )
        out.append(code)
        index += 1
    if quoted:
        raise SvcParamError(f"{what} has an unterminated quoted string")
    return bytes(out)


#: Octets that must not appear literally in an unquoted SvcParamValue, because
#: they would end the token in a master file. These are exactly Appendix A's
#: ``non-special`` exclusions -- ``"``, ``\``, ``;``, ``(``, ``)`` -- plus the
#: whitespace that terminates a token. A comma is deliberately absent, as is ``=``:
#: Appendix A allows both literally, and :func:`encode_charstring` explains why the
#: comma has to stay bare.
_TOKEN_DELIMITERS = frozenset(b'"\\;() ')


def encode_charstring(value: bytes) -> str:
    r"""Render octets as an unquoted master-file ``<character-string>``.

    The inverse of :func:`decode_charstring`: a backslash becomes ``\\``, octets
    that would break the token become ``\DDD``, and everything else printable is
    passed through. Non-printable and non-ASCII octets use ``\DDD`` for the same
    reason :func:`namespy.rdata.quote_charstring` does -- RFC 2181 section 11
    allows arbitrary octets, and this is the only lossless rendering.

    Commas are *not* escaped here, and that is load-bearing: for a list key,
    :func:`encode_charstring` runs *after* :func:`join_value_list`, so the
    separators must still be recognizable as bare commas to a decoder applying
    Appendix A.1's second stage. Data commas were already escaped by the join,
    and doubling their backslashes here is exactly what produces Appendix D
    Figure 10's ``alpn=f\\\092oo\092,bar,h2``.
    """
    out: list[str] = []
    for octet in value:
        if octet == _BACKSLASH:
            out.append("\\\\")
        elif octet in _TOKEN_DELIMITERS or not 0x20 <= octet < 0x7F:
            out.append(f"\\{octet:03d}")
        else:
            out.append(chr(octet))
    return "".join(out)


# ---------------------------------------------- stage 2: comma-separated lists


def split_value_list(value: bytes, *, what: str) -> list[bytes]:
    r"""Apply Appendix A.1's comma-separated list decoding to an octet string.

    This runs on the *output* of :func:`decode_charstring`, per A.1: "Decoding of
    value-lists happens after character-string decoding." A bare comma separates
    items; ``\,`` and ``\\`` are escapes. An empty item is rejected -- A.1 says
    "for simplicity, empty items are not allowed" -- as is a value that ends
    inside an escape.

    A.1's grammar (``escaped-item = 1*(item-allowed / "\," / "\\")``) only
    defines escapes for the two octets that need them, so a backslash in front of
    anything else has no defined meaning. Such a sequence cannot be produced by
    :func:`join_value_list`; it arrives only from a hand-written zone file, and
    this decoder takes it as a literal *X* the way RFC 1035 section 5.1 does
    rather than rejecting a record over a spelling variation.
    """
    if not value:
        return []
    items: list[bytes] = []
    current = bytearray()
    index = 0
    length = len(value)
    while index < length:
        octet = value[index]
        if octet == _BACKSLASH:
            if index + 1 >= length:
                raise SvcParamError(f"{what} ends with a dangling escape in a value list")
            current.append(value[index + 1])
            index += 2
            continue
        if octet == _COMMA:
            if not current:
                raise SvcParamError(f"{what} has an empty item in a comma-separated list")
            items.append(bytes(current))
            current = bytearray()
            index += 1
            continue
        current.append(octet)
        index += 1
    if not current:
        raise SvcParamError(f"{what} ends with a separator in a value list")
    items.append(bytes(current))
    return items


def join_value_list(items: Sequence[bytes]) -> bytes:
    r"""Apply the inverse of :func:`split_value_list`: escape and comma-join.

    The result is the octet string that a decoder's stage 1 would produce, so
    callers pass it to :func:`encode_charstring` to get the master-file token.
    """
    escaped: list[bytes] = []
    for item in items:
        if not item:
            raise SvcParamError("a comma-separated list item may not be empty (Appendix A.1)")
        escaped.append(item.replace(b"\\", b"\\\\").replace(b",", b"\\,"))
    return b",".join(escaped)


# --------------------------------------------------------------- key naming


def key_from_name(name: str) -> int:
    """Resolve a presentation key name -- registered or ``keyNNNNN`` -- to a number.

    Unknown keys use the ``keyNNNNN`` form of section 2.1, whose digits carry no
    leading zeros. An unresolvable name is an error rather than a silent zero:
    guessing a key number is how a zone file starts meaning something other than
    what it says.
    """
    if not _KEY_NAME_RE.match(name):
        raise SvcParamError(
            f"invalid SvcParamKey {name!r}: 1-63 characters from a-z, 0-9 and '-' "
            "(RFC 9460 section 2.1)"
        )
    number = _NAME_KEYS.get(name)
    if number is not None:
        return number
    match = _UNKNOWN_KEY_RE.match(name)
    if match is None:
        raise SvcParamError(
            f"unknown SvcParamKey {name!r}: registered names are "
            f"{', '.join(sorted(_NAME_KEYS))}, and any other key must use "
            "the keyNNNNN form of RFC 9460 section 2.1"
        )
    return _check_key_number(int(match.group(1)), source=f"key {name!r}")


def key_to_name(key: int) -> str:
    """Render a key number in its presentation form (name or ``keyNNNNN``)."""
    number = _check_key_number(key)
    return _KEY_NAMES.get(number) or f"key{number}"


def _check_key_number(key: int, *, source: str = "SvcParamKey") -> int:
    """Validate a key number's range, including the reserved "Invalid key"."""
    try:
        number = int(key)
    except (TypeError, ValueError) as exc:  # pragma: no cover - defensive
        raise SvcParamError(f"{source} {key!r} is not a number") from exc
    if not 0 <= number <= MAX_KEY:
        raise SvcParamError(f"{source} {number} is outside 0-{MAX_KEY} (RFC 9460 section 2.1)")
    if number == RESERVED_INVALID_KEY:
        raise SvcParamError(
            f'{source} {number} is the reserved "Invalid key" and MUST NOT be used '
            "(RFC 9460 section 14.3.2 Table 1)"
        )
    return number


# ------------------------------------------------ per-key value conversion


def _alpn_ids(value: bytes, *, where: str = "alpn") -> list[bytes]:
    """Split an ``alpn`` wire value into protocol ids, validating the framing.

    Section 7.1.1: the value is "at least one alpn-id prefixed by its length as a
    single octet", and "these pairs MUST exactly fill the SvcParamValue;
    otherwise, the SvcParamValue is malformed". A zero-length id is malformed too,
    because ``alpn-id = 1*255OCTET``.
    """
    if not value:
        raise DnsPacketParseError(
            f"{where} SvcParamValue is empty; it must carry at "
            "least one length-prefixed protocol id "
            "(RFC 9460 section 7.1.1)"
        )
    items: list[bytes] = []
    index = 0
    while index < len(value):
        length = value[index]
        index += 1
        if length == 0:
            raise DnsPacketParseError(
                f"{where} SvcParamValue contains a zero-length protocol id at offset "
                f"{index} (RFC 9460 section 7.1.1: alpn-id is 1-255 octets)"
            )
        if index + length > len(value):
            raise DnsPacketParseError(
                f"{where} SvcParamValue is malformed: the protocol id at offset {index} "
                f"claims {length} octet(s) but only {len(value) - index} remain, so the "
                "length-value pairs do not exactly fill the value (RFC 9460 section 7.1.1)"
            )
        items.append(value[index : index + length])
        index += length
    return items


def _hint_addresses(value: bytes, *, key: int) -> list[str]:
    """Validate a packed ``ipv4hint``/``ipv6hint`` value, returning canonical text.

    Section 7.3 makes each hint a list of addresses of exactly one family, and
    Appendix D's failure cases (Figure 12) make an empty value malformed. The
    canonical rendering is RFC 5952's, which :mod:`ipaddress` implements -- so
    Figure 8's embedded-IPv4 spelling ``2001:db8:122:344::192.0.2.33`` comes back
    as ``2001:db8:122:344::c000:221``: different text, identical 16 octets.
    """
    family, width, name = (
        (ipaddress.IPv4Address, 4, "ipv4hint")
        if key == int(IPV4HINT)
        else (ipaddress.IPv6Address, 16, "ipv6hint")
    )
    if not value:
        raise DnsPacketParseError(
            f"{name} SvcParamValue is empty; it must contain at least one address "
            "(RFC 9460 section 7.3, Appendix D Figure 12)"
        )
    if len(value) % width:
        raise DnsPacketParseError(
            f"{name} SvcParamValue is {len(value)} octet(s), which is not a whole number "
            f"of {width}-octet addresses (RFC 9460 section 7.3)"
        )
    out: list[str] = []
    for offset in range(0, len(value), width):
        try:
            out.append(str(family(value[offset : offset + width])))
        except ValueError as exc:  # pragma: no cover - widths make this unreachable
            raise DnsPacketParseError(f"{name} contains an invalid address: {exc}") from exc
    return out


def _mandatory_list(value: bytes) -> tuple[int, ...]:
    """Validate a ``mandatory`` wire value: increasing, unique, no self-reference.

    Section 8: the numbers appear "in strictly increasing numeric order", listed
    keys "MUST NOT appear more than once", and ``mandatory`` "is always
    automatically mandatory and MUST NOT appear in its own value-list" -- which
    Appendix D Figure 15 shows as a failure case.
    """
    if len(value) % 2:
        raise DnsPacketParseError(
            f"mandatory SvcParamValue is {len(value)} octet(s), not a whole number of "
            "2-octet key numbers (RFC 9460 section 8)"
        )
    keys = struct.unpack_from(f"!{len(value) // 2}H", value)
    previous = -1
    for key in keys:
        if key <= previous:
            raise DnsPacketParseError(
                f"mandatory SvcParamKey list is not in strictly increasing numeric order "
                f"({previous} then {key}); RFC 9460 section 8"
            )
        if key == int(MANDATORY):
            raise DnsPacketParseError(
                'the "mandatory" SvcParamKey MUST NOT appear in its own value-list '
                "(RFC 9460 section 8, Appendix D Figure 15)"
            )
        if key == RESERVED_INVALID_KEY:
            raise DnsPacketParseError(
                f"mandatory lists the reserved key {key} (RFC 9460 section 14.3.2 Table 1)"
            )
        previous = key
    return keys


#: RFC 3986 section 4.2: a path segment containing a colon before any slash makes
#: an absolute URI. RFC 9461 section 5 requires the *relative* form.
_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:")


def _port_number(value: bytes) -> int:
    """Validate a ``port`` wire value -- exactly two octets (section 7.2)."""
    if len(value) != 2:
        raise DnsPacketParseError(
            f"port SvcParamValue is {len(value)} octet(s), expected the 2-octet integer "
            "of RFC 9460 section 7.2"
        )
    (port,) = struct.unpack_from("!H", value)
    return port


def _doh_template(value: bytes) -> str:
    """Validate a ``dohpath`` wire value: UTF-8, non-empty, relative form.

    RFC 9461 section 5: the value "MUST be a URI Template in relative form
    ([RFC6570], Section 1.1) encoded in UTF-8". Those are format constraints, so
    violating them makes the RR malformed under section 2.2. The same section's
    requirement that the template "MUST contain a \"dns\" variable" is *not*
    checked here: it is a mapping-level rule rather than a value format, and RFC
    9460 section 4.3 tells implementations to "limit validation to specified
    constraints" for value types as open-ended as URIs. It surfaces from
    :meth:`SvcParams.self_consistency_problems` instead.
    """
    if not value:
        raise DnsPacketParseError(
            "dohpath SvcParamValue is empty; RFC 9461 section 5 requires a URI Template"
        )
    if b"\x00" in value:
        raise DnsPacketParseError("dohpath SvcParamValue contains a NUL octet")
    try:
        template = value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DnsPacketParseError(
            f"dohpath SvcParamValue is not valid UTF-8, which RFC 9461 section 5 requires: {exc}"
        ) from exc
    head = re.split(r"[/?#]", template, maxsplit=1)[0]
    if _SCHEME_RE.match(head):
        raise DnsPacketParseError(
            f'dohpath "{template}" is an absolute URI; RFC 9461 section 5 requires a URI '
            "Template in relative form"
        )
    return template


# ------------------------------------------------------- key-specific mapping


def value_from_presentation(key: int, token: str) -> bytes:
    r"""Convert one presentation SvcParamValue to its wire form.

    *token* is the raw master-file text after the ``=``, exactly as the zone-file
    tokenizer produced it -- quoting and escapes are this function's job, per
    section 2.1: "The SvcParamValue is parsed using the character-string decoding
    algorithm (Appendix A), producing a value. The value is then validated and
    converted into wire format in a manner specific to each key."
    """
    key = _check_key_number(key)
    name = key_to_name(key)
    raw = decode_charstring(token, what=f"{name} value")
    if key in _EMPTY_VALUE_KEYS:
        if raw:
            raise SvcParamError(
                f'the "{name}" SvcParamValue must be empty but is {raw!r} '
                "(RFC 9460 section 7.1.1, Appendix D Figure 13)"
            )
        return b""
    if key == int(ALPN):
        items = split_value_list(raw, what=f"{name} value")
        if not items:
            raise SvcParamError(
                f'"{name}" requires at least one protocol id (RFC 9460 section 7.1.1)'
            )
        framed = bytearray()
        for item in items:
            if len(item) > MAX_ALPN_ID_OCTETS:
                raise SvcParamError(
                    f"protocol id {item[:16]!r}... is {len(item)} octet(s), over the "
                    f"{MAX_ALPN_ID_OCTETS} of RFC 9460 section 7.1.1"
                )
            framed.append(len(item))
            framed.extend(item)
        return bytes(framed)
    if key == int(MANDATORY):
        # Section 8: "To enable simpler parsing, this SvcParamValue MUST NOT
        # contain escape sequences."
        if b"\\" in raw:
            raise SvcParamError(
                "the mandatory SvcParamValue MUST NOT contain escape sequences (RFC 9460 section 8)"
            )
        items = split_value_list(raw, what="mandatory value")
        if not items:
            raise SvcParamError(
                "mandatory requires a comma-separated list of at least one SvcParamKey "
                "(RFC 9460 section 8, Appendix D Figure 12)"
            )
        keys: list[int] = []
        for item in items:
            try:
                number = key_from_name(item.decode("ascii"))
            except UnicodeDecodeError as exc:
                raise SvcParamError(
                    f"mandatory lists a non-ASCII key name {item!r} (RFC 9460 section 8)"
                ) from exc
            if number == int(MANDATORY):
                raise SvcParamError(
                    'the "mandatory" SvcParamKey MUST NOT appear in its own value-list '
                    "(RFC 9460 section 8, Appendix D Figure 15)"
                )
            keys.append(number)
        if len(set(keys)) != len(keys):
            raise SvcParamError(
                "mandatory lists a SvcParamKey more than once (RFC 9460 section 8, "
                "Appendix D Figure 16)"
            )
        return struct.pack(f"!{len(keys)}H", *sorted(keys))

    if key == int(PORT):
        # Section 7.2: "The presentation value of the SvcParamValue is a single
        # decimal integer between 0 and 65535 in ASCII. Any other value (e.g., an
        # empty value) is a syntax error. To enable simpler parsing, this
        # SvcParamValue MUST NOT contain escape sequences."
        if b"\\" in raw:
            raise SvcParamError(
                "the port SvcParamValue MUST NOT contain escape sequences (RFC 9460 section 7.2)"
            )
        text = raw.decode("ascii", errors="replace")
        number = int(text) if text.isascii() and text.isdigit() else -1
        if not 0 <= number <= 65535:
            raise SvcParamError(
                f"port value {text!r} is not a decimal integer between 0 and 65535 "
                "(RFC 9460 section 7.2)"
            )
        return struct.pack("!H", number)
    if key in (int(IPV4HINT), int(IPV6HINT)):
        # Section 7.3 repeats section 7.2's ban on escapes, for the same reason.
        if b"\\" in raw:
            raise SvcParamError(
                f'the "{name}" SvcParamValue MUST NOT contain escape sequences '
                "(RFC 9460 section 7.3)"
            )
        items = split_value_list(raw, what=f"{name} value")
        if not items:
            raise SvcParamError(
                f"{name} requires at least one address (RFC 9460 section 7.3, Appendix D Figure 12)"
            )
        family = ipaddress.IPv4Address if key == int(IPV4HINT) else ipaddress.IPv6Address
        packed = bytearray()
        for item in items:
            try:
                packed.extend(family(item.decode("ascii")).packed)
            except (UnicodeDecodeError, ValueError) as exc:
                raise SvcParamError(
                    f"{name} lists {item!r}, which is not a valid "
                    f"{family.__name__[: -len('Address')]} address: {exc}"
                ) from exc
        return bytes(packed)
    if key == int(DOHPATH):
        return _doh_template(raw).encode("utf-8")
    # Section 2.1: for a key this implementation does not know, "Arbitrary keys can
    # be represented using the unknown-key presentation format ... and the decoded
    # value SHALL be used as its wire-format encoding" -- the presentation octets
    # ARE the wire octets, which is what lets a resolver convey a key it has never
    # heard of (section 4.3) without understanding it.
    return raw


def value_to_presentation(key: int, value: bytes) -> str:
    """Render a wire SvcParamValue as its master-file text, validating it.

    The rendering is what a reader of a *generated* zone file needs and is not
    always byte-identical to the text that produced it: Appendix D Figure 8's
    embedded-IPv4 spelling ``2001:db8:122:344::192.0.2.33`` comes back in RFC 5952's
    canonical ``2001:db8:122:344::c000:221``, because the two spellings are the same
    sixteen octets and section 7.3 names RFC 5952 as the format to write.
    """
    key = _check_key_number(key)
    if key == int(ALPN):
        return encode_charstring(join_value_list(_alpn_ids(value)))
    if key == int(PORT):
        return str(_port_number(value))
    if key in (int(IPV4HINT), int(IPV6HINT)):
        addresses = _hint_addresses(value, key=key)
        return encode_charstring(
            join_value_list([address.encode("ascii") for address in addresses])
        )
    if key == int(MANDATORY):
        names = [key_to_name(number).encode("ascii") for number in _mandatory_list(value)]
        return encode_charstring(join_value_list(names))
    if key == int(DOHPATH):
        return encode_charstring(_doh_template(value).encode("utf-8"))
    if key in _EMPTY_VALUE_KEYS:
        if value:
            raise DnsPacketParseError(
                f'{key_to_name(key)} SvcParamValue is {value!r}, but "{key_to_name(key)}" '
                "is defined as a key-only SvcParam with no value (RFC 9460 section 7.1.1, "
                "Appendix D Figure 13)"
            )
        return ""
    return encode_charstring(value)


#: One SvcParamKey plus its SvcParamValue length (section 2.2's "_svc-param-key =
#: 2OCTET / "_svc-param-value-length = 1OCTET" framing, read here as two octets
#: each because the value follows immediately).
_PARAM_HEADER_OCTETS = 4

#: Keys whose SvcParamValue format this module can interpret. "ech" is absent on
#: purpose: RFC 9460 section 14.3.2 Table 1 registers key number 5 as RESERVED with
#: a reference of "N/A", so there is no value format to validate against. It is
#: still *conveyed* -- section 4.3 requires exactly that -- it simply stays opaque.
#:
#: Key *numbers*, deliberately: every user asks "is this wire key interpretable?",
#: and a frozenset of the names would answer yes to nothing -- .values() is what
#: makes this the numbers, since _NAME_KEYS is the name-to-number direction.
_PARSABLE_KEYS = frozenset(_NAME_KEYS.values()) - {int(ECH)}


def _malformed(key: int, exc: Exception, *, source: bytes, offset: int) -> DnsPacketParseError:
    """Wrap a per-key failure in the section 2.2 error it constitutes.

    Only keys whose format is specified (section 7, plus RFC 9461 section 5) reach
    this. Unknown keys are skipped by length instead: section 2.2's malformed list
    does not mention them, and section 2.4.3 tells a client to "ignore any SvcParam
    that they do not recognize", so an unknown key costs a client its reading of
    that one parameter rather than the record.
    """
    return DnsPacketParseError(
        f'SvcParamKey "{key_to_name(key)}" at offset {offset} is malformed: {exc}. '
        "RFC 9460 section 2.2 makes a SvcParamValue that does not have the expected "
        "format malformed, and a malformed RR means the client MUST reject the entire "
        "RRset and fall back to non-SVCB connection establishment.",
        data=source,
        offset=offset,
    )


# ------------------------------------------------------------ the SvcParams


class UnknownKey(NamedTuple):
    """A SvcParamKey this module has no value definition for.

    Section 2.1's ``keyNNNNN`` form exists precisely so that such a key can still
    be written down, read, and re-sent: "the decoded value SHALL be used as its
    wire-format encoding". Section 2.4.3 then tells a client to "ignore any SvcParam
    that they do not recognize" rather than to reject the record for it.
    """

    key: int
    """Its number. The name is not known, so only the ``keyNNNNN`` form exists."""

    wire: bytes
    """Its raw SvcParamValue, preserved so a re-encode reproduces the octets."""


def _validate_wire(key: int, value: bytes) -> None:
    """Run the per-key wire checks; keys this module does not know are skipped."""
    if key == int(ALPN):
        _alpn_ids(value)
    elif key == int(PORT):
        _port_number(value)
    elif key in (int(IPV4HINT), int(IPV6HINT)):
        _hint_addresses(value, key=key)
    elif key == int(MANDATORY):
        _mandatory_list(value)
    elif key == int(DOHPATH):
        _doh_template(value)
    elif key in _EMPTY_VALUE_KEYS and value:
        raise DnsPacketParseError(
            f'{key_to_name(key)} SvcParamValue is {len(value)} octet(s); "{key_to_name(key)}" '
            "is a key-only SvcParam (RFC 9460 section 7.1.1, Appendix D Figure 13)"
        )


class SvcParams:
    """The SvcParams of one SVCB or HTTPS RDATA, as key numbers and wire octets.

    Values are held exactly as they appear on the wire and converted per key on
    access, because a record carrying a key invented next year still has to give up
    its ``alpn`` and its hints: section 2.4.3 says "clients MUST ignore any SvcParam
    that they do not recognize", and section 4.3 requires a resolver to "be able to
    convey SVCB records with unrecognized SvcParamKeys". An unrecognized key is
    therefore kept, named ``keyNNNNN``, and re-encoded byte for byte.

    Construction accepts keys in any order and stores them in ascending numeric
    order, which is what section 2.1 permits in a zone file ("SvcParams in
    presentation format MAY appear in any order") and section 2.2 demands on the
    wire ("SvcParamKeys SHALL appear in increasing numeric order"). Both sections
    forbid a key from appearing twice.

    >>> params = SvcParams.from_presentation("alpn=h2,h3 port=443")
    >>> params.port, params.alpn
    (443, [b'h2', b'h3'])
    >>> params.to_presentation()
    'alpn=h2,h3 port=443'
    """

    __slots__ = ("_unknown", "_values")

    def __init__(
        self,
        pairs: Iterable[tuple[IntOrStr, bytes]] = (),
        *,
        unknown: Iterable[UnknownKey] = (),
    ):
        """Build from ``(key, wire value)`` pairs; *key* may be a name or number.

        *unknown* carries the keys :meth:`from_wire` could not interpret, whose
        values are stored without validation because there is no specification to
        validate them against.

        :raises SvcParamError: for an invalid key, a duplicate key, or a value that
            the key's own definition rejects.
        """
        values: dict[int, bytes] = {}
        for skipped in unknown:
            values[skipped.key] = skipped.wire
        for key, value in pairs:
            number = key if isinstance(key, int) else key_from_name(key)
            number = _check_key_number(number)
            wire = bytes(value)
            try:
                _validate_wire(number, wire)
            except (SvcParamError, ValueError) as exc:
                raise SvcParamError(f'SvcParamKey "{key_to_name(number)}": {exc}') from exc
            if number in values:
                raise SvcParamError(
                    f"duplicate SvcParamKey {key_to_name(number)} in one RDATA "
                    "(RFC 9460 section 2.2)"
                )
            values[number] = wire
        self._values: dict[int, bytes] = {n: values[n] for n in sorted(values)}
        # Derived from what is stored, not from the *unknown* argument: a caller who
        # builds SvcParams([("ech", ...)]) by hand has supplied a key with no value
        # definition just as surely as the wire path did, and :attr:`unknown_keys`
        # documents ech as included either way.
        self._unknown = frozenset(n for n in self._values if n not in _PARSABLE_KEYS)

    # ---------------------------------------------------- container protocol

    def __len__(self) -> int:
        """How many SvcParamKeys are present, known or not."""
        return len(self._values)

    def __iter__(self) -> Iterator[int]:
        """Iterate the SvcParamKey numbers in ascending numeric order."""
        return iter(sorted(self._values))

    def __contains__(self, key: IntOrStr) -> bool:
        """Whether a SvcParamKey is present, given as a number or a name."""
        try:
            return self._number(key) in self._values
        except SvcParamError:
            return False

    def __getitem__(self, key: IntOrStr) -> bytes:
        """The raw wire SvcParamValue of *key*, or :exc:`KeyError`."""
        number = self._number(key)
        try:
            return self._values[number]
        except KeyError:
            raise KeyError(key_to_name(number)) from None

    def get(self, key: IntOrStr, default: bytes | None = None) -> bytes | None:
        """The raw wire SvcParamValue of *key*, or *default* when absent."""
        try:
            return self[self._number(key)]
        except KeyError:
            return default

    @staticmethod
    def _number(key: IntOrStr) -> int:
        return key if isinstance(key, int) else key_from_name(key)

    @property
    def unknown_keys(self) -> tuple[int, ...]:
        """Keys this module has no value definition for, in ascending order.

        Registered-but-undefined keys such as ``ech`` (section 14.3.2 Table 1 marks
        it RESERVED with no reference) are included, as is anything from a future
        registration.
        """
        return tuple(sorted(self._unknown))

    @property
    def has_unknown_keys(self) -> bool:
        """Whether this RDATA carried a parameter this module cannot interpret.

        That is a compatibility question, not a validity one -- section 2.4.3 makes
        an unrecognized SvcParam ignorable. What it does change is what a client may
        conclude: :meth:`is_compatible` can only vouch for keys it can read.
        """
        return bool(self._unknown)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SvcParams):
            return NotImplemented
        return self._values == other._values

    def __hash__(self) -> int:
        """Hash the key/value pairs, matching :meth:`__eq__`.

        Two things need this. A value object that defines ``__eq__`` loses its
        default hash and becomes unusable as a dict key or dataclass field -- and
        :class:`SvcbCandidate` is a frozen dataclass with an ``SvcParams`` field,
        which :mod:`dataclasses` refuses outright when the default's type is
        unhashable. Which keys happened to be unrecognized is deliberately not part
        of it, because ``__eq__`` ignores that too: it describes what a client could
        read, not what the record says.
        """
        return hash(tuple(self._values.items()))

    def __repr__(self) -> str:
        body = " ".join(
            f"{key_to_name(number)}={value.hex() or '-'}" for number, value in self._values.items()
        )
        return f"{type(self).__name__}({body or ''})"

    # ---------------------------------------------------------- typed access

    @property
    def alpn(self) -> list[bytes] | None:
        """The ``alpn`` protocol ids, in the order the zone published them, or None.

        The order is preserved rather than sorted or deduplicated because only the
        zone owner knows what it meant: section 7.1.1 defines the client's "SVCB ALPN
        set" as starting "with the list of alpn-ids from the 'alpn' SvcParamKey", and
        section 7.1.2 then has the client build a ProtocolNameList per transport from
        it. Interpreting that list is the protocol mapping's job, not this one's.
        """
        value = self._values.get(int(ALPN))
        return None if value is None else _alpn_ids(value)

    @property
    def port(self) -> int | None:
        """The ``port`` parameter, or None when absent.

        Section 7.2: "If this key is not present, clients SHALL use the authority
        endpoint's port number" -- the port the service is normally reached at. So
        absence is normal, and it is not the same statement as the explicit
        ``port=0`` that this property also reports faithfully.
        """
        value = self._values.get(int(PORT))
        return None if value is None else _port_number(value)

    def _hints(self, key: SvcParamKey) -> list[str] | None:
        value = self._values.get(int(key))
        return None if value is None else _hint_addresses(value, key=int(key))

    @property
    def ipv4hint(self) -> list[str] | None:
        """``ipv4hint`` addresses in RFC 5952 canonical text, or None when absent."""
        return self._hints(IPV4HINT)

    @property
    def ipv6hint(self) -> list[str] | None:
        """``ipv6hint`` addresses in RFC 5952 canonical text, or None when absent."""
        return self._hints(IPV6HINT)

    @property
    def dohpath(self) -> str | None:
        """The ``dohpath`` URI Template (RFC 9461 section 5), or None when absent."""
        value = self._values.get(int(DOHPATH))
        return None if value is None else _doh_template(value)

    @property
    def no_default_alpn(self) -> bool:
        """Whether ``no-default-alpn`` is present.

        Section 7.1.1: its "presentation and wire-format values MUST be empty", and
        "to determine the SVCB ALPN set, the client starts with the list of alpn-ids
        from the 'alpn' SvcParamKey, and it adds the default set unless the
        'no-default-alpn' SvcParamKey is present". Same section, one sentence later:
        "When no-default-alpn is specified in an RR, 'alpn' must also be specified in
        order for the RR to be self-consistent" -- so this key suppresses a default,
        it never removes ALPN support on its own. See :meth:`svc_alpn_set`.
        """
        return int(NO_DEFAULT_ALPN) in self._values

    def svc_alpn_set(self, default_set: Sequence[bytes] = ()) -> list[bytes] | None:
        """The "SVCB ALPN set" of section 7.1.1, or None if no ALPN is offered.

        *default_set* is the scheme's default -- Appendix B Table 3 gives HTTPS the
        set ``["http/1.1"]``. Empty by default because this module is scheme-agnostic:
        a caller using it for HTTPS should pass ``[b"http/1.1"]``, and one using it
        for a scheme with no default should pass nothing.

        Returns None when the RR offers no ALPN at all: no ``alpn`` parameter and
        ``no-default-alpn`` present, which is what a caller uses to conclude that
        section 7.1.2's "SVCB ALPN set" is empty.
        """
        offered = self.alpn or []
        if self.no_default_alpn:
            return list(offered) or None
        return [*offered, *(item for item in default_set if item not in offered)]

    @property
    def mandatory(self) -> tuple[int, ...] | None:
        """The ``mandatory`` key numbers, or None when absent (section 8)."""
        value = self._values.get(int(MANDATORY))
        return None if value is None else _mandatory_list(value)

    def is_mandatory(self, key: IntOrStr) -> bool:
        """Whether *key* is listed in this RR's own ``mandatory`` parameter."""
        listed = self.mandatory
        return listed is not None and self._number(key) in listed

    def unrecognized_mandatory_keys(self) -> tuple[int, ...]:
        """Mandatory keys this module cannot read -- the section 8 incompatibility.

        Section 8: "A ServiceMode RR is considered 'compatible' by a client if the
        client recognizes all the mandatory keys and their values indicate that
        successful connection establishment is possible. Incompatible RRs are
        ignored (see step 5 of the procedure defined in Section 3)." A key that is
        listed as mandatory but whose value this module cannot interpret therefore
        makes the whole RR unusable here, which is what
        :meth:`SvcbCandidate.compatibility_problems` reports.

        Note this says nothing about *automatically* mandatory keys, which section 8
        leaves to each protocol mapping -- Appendix B Table 3 lists ``port`` and
        ``no-default-alpn`` as automatically mandatory for HTTPS. A caller that wants
        that rule applies it with :meth:`is_mandatory` and its own key set.
        """
        listed = self.mandatory
        if listed is None:
            return ()
        return tuple(key for key in listed if key not in _PARSABLE_KEYS)

    # ------------------------------------------------------------ wire format

    @classmethod
    def from_wire(
        cls,
        buffer: bytes,
        offset: int = 0,
        *,
        size: int | None = None,
        data: bytes | None = None,
    ) -> tuple[SvcParams, int]:
        """Decode SvcParams up to the end of the RDATA, returning ``(params, offset)``.

        There is no overall length field: section 2.2 defines the SvcParams as
        "consuming the remainder of the record", so *size* comes from the RDLENGTH
        the caller already read.

        Everything this method rejects is one of section 2.2's three MUST conditions
        for considering an RR malformed: "the end of the RDATA occurs within a
        SvcParam" (a truncated key/value header, or a SvcParamValue that runs past
        the end of the RDATA); "SvcParamKeys are not in strictly increasing numeric
        order", which the section notes "implies that there are no duplicate
        SvcParamKeys"; and "the SvcParamValue for a SvcParamKey does not have the
        expected format". A key number that is out of range or the reserved 65535
        "Invalid key" (section 14.3.2 Table 1) cannot be a key at all.

        A malformed RR is not a per-record problem: "If any RRs are malformed, the
        client MUST reject the entire RRset and fall back to non-SVCB connection
        establishment." Every failure therefore carries the offset at which it
        happened, and callers must drop the whole RRset rather than keeping the
        records that did parse.
        """
        source = buffer if data is None else data
        end = len(buffer) if size is None else offset + size
        params: dict[int, bytes] = {}
        skipped: list[UnknownKey] = []
        previous = -1
        while offset < end:
            start = offset
            if offset + _PARAM_HEADER_OCTETS > end:
                raise DnsPacketParseError(
                    f"SvcParams: {end - offset} octet(s) remain before the end of the RDATA, "
                    "not enough for a SvcParamKey and a SvcParamValue length "
                    "(RFC 9460 section 2.2)",
                    data=source,
                    offset=start,
                )
            key, length = struct.unpack_from("!HH", buffer, offset)
            offset += _PARAM_HEADER_OCTETS
            try:
                key = _check_key_number(key, source=f"SvcParamKey at offset {start}")
            except SvcParamError as exc:
                raise DnsPacketParseError(str(exc), data=source, offset=start) from exc
            if length > end - offset:
                raise DnsPacketParseError(
                    f"SvcParams: {key_to_name(key)} declares a {length}-octet SvcParamValue "
                    f"but only {end - offset} remain in the RDATA (RFC 9460 section 2.2)",
                    data=source,
                    offset=start,
                )
            value = bytes(buffer[offset : offset + length])
            offset += length
            if key == previous:
                raise DnsPacketParseError(
                    f"SvcParams: duplicate SvcParamKey {key_to_name(key)} at offset {start}; "
                    "RFC 9460 section 2.2 requires strictly increasing keys and notes that "
                    "this 'implies that there are no duplicate SvcParamKeys'",
                    data=source,
                    offset=start,
                )
            if key < previous:
                raise DnsPacketParseError(
                    f"SvcParams: SvcParamKey {key_to_name(key)} at offset {start} follows "
                    f"{key_to_name(previous)}; keys MUST appear in ascending numeric order "
                    "(RFC 9460 section 2.2)",
                    data=source,
                    offset=start,
                )
            previous = key
            if key not in _PARSABLE_KEYS:
                # A key with no defined value format: section 2.1's keyNNNNN rule
                # makes its octets self-describing, section 4.3 requires that it be
                # conveyed onward, and section 2.4.3 makes it ignorable. It may be
                # followed by keys that ARE defined -- RFC 9460 has no "unknown keys
                # form a suffix" rule -- so the loop simply keeps going.
                skipped.append(UnknownKey(key, value))
                continue
            try:
                _validate_wire(key, value)
            except (SvcParamError, ValueError) as exc:
                raise _malformed(key, exc, source=source, offset=start) from exc
            params[key] = value
        return cls(params.items(), unknown=skipped), end

    def to_wire(self) -> bytes:
        """Encode in ascending key order (section 2.2), values verbatim."""
        out = bytearray()
        for key, value in self._values.items():
            out += struct.pack("!HH", key, len(value))
            out += value
        return bytes(out)

    # --------------------------------------------------------- presentation

    @classmethod
    def from_presentation(cls, text: str) -> SvcParams:
        r"""Parse an ``svc-value``: the parameters after the TargetName, space-separated.

        Section 2.1 gives the shape: "the SvcParams are a whitespace-separated list
        with each SvcParam consisting of a SvcParamKey=SvcParamValue pair or a
        standalone SvcParamKey". Two details make this more than ``text.split()``:

        * spaces must be split outside quotes and outside escapes, because a
          SvcParamValue is a ``char-string`` (Appendix A) and a quoted segment may
          contain a space -- ``dohpath="/a b{?dns}"`` is one parameter;
        * the key/value boundary is the *first* ``=``, which is unambiguous because
          section 2.1's ``SvcParamKey`` grammar admits only letters, digits and ``-``,
          so an ``=`` can never be part of a key.

        A key with no ``=`` at all is the empty form: "When the optional '=' and
        SvcParamValue are omitted, the value is interpreted as empty", which is how
        ``no-default-alpn`` is written (Appendix D Figure 12 lists the standalone keys
        whose values must NOT be empty, and so rejects this form for them).

        :raises SvcParamError: if a key or value is invalid. This is a zone-file
            error, not wire damage, so it is not a :exc:`DnsPacketParseError`.
        """
        params: list[tuple[int, bytes]] = []
        for token in _split_params(text):
            key_text, _, value_text = token.partition("=")
            key = key_from_name(key_text)
            params.append((key, value_from_presentation(key, value_text)))
        return cls(params)

    def to_presentation(self) -> str:
        """Render the ``svc-value``, keys in ascending numeric order (section 2.2).

        A parameter whose value is empty renders as a bare key name, per section
        2.1: "When the optional '=' and SvcParamValue are omitted, the value is
        interpreted as empty" -- which is the only way to write ``no-default-alpn``,
        since section 7.1.1 requires its value to be empty.

        Presentation order is not forced (§2.1: "SvcParams in presentation format MAY
        appear in any order"), but sorting costs nothing and means a record that was
        parsed and re-rendered prints the way a generated zone file should look.
        """
        parts: list[str] = []
        for key, value in self._values.items():
            name = key_to_name(key)
            rendered = value_to_presentation(key, value)
            parts.append(name if not rendered else f"{name}={rendered}")
        return " ".join(parts)


def _split_params(text: str) -> list[str]:
    r"""Split an ``svc-value`` on spaces that are not quoted or escaped.

    ``\20`` (a backslash before a space) and a space inside ``"..."`` both belong
    to a character-string rather than to the parameter separator, per Appendix A.
    Empty tokens are dropped, which is what makes a leading or doubled space
    harmless here -- and safe, because section 2.1's ``svc-value`` has no way to
    express an empty parameter anyway.
    """
    tokens: list[str] = []
    current: list[str] = []
    quoted = False
    index = 0
    while index < len(text):
        char = text[index]
        if char == '"':
            quoted = not quoted
            current.append(char)
            index += 1
            continue
        if char == "\\" and index + 1 < len(text):
            digits = text[index + 1 : index + 4]
            if len(digits) == 3 and digits.isascii() and digits.isdigit():
                current.append("\\")
                current.append(digits)
                index += 4
                continue
            current.append("\\")
            current.append(text[index + 1])
            index += 2
            continue
        if char.isspace() and not quoted:
            if current:
                tokens.append("".join(current))
                current = []
            index += 1
            continue
        current.append(char)
        index += 1
    if current:
        tokens.append("".join(current))
    return tokens


# ------------------------------------------------- record-level consistency


def self_consistency_problems(priority: int, params: SvcParams) -> tuple[str, ...]:
    """List the ways *params* fail to comply with each other's requirements.

    Section 2.4.3 defines the term and its consequence: "A ServiceMode RR is called
    'self-consistent' if its SvcParams all comply with each other's requirements.
    Clients MUST reject any RR whose recognized SvcParams are not self-consistent and
    MAY reject the entire RRset." This is the milder of RFC 9460's two kinds of bad
    record -- a *malformed* one (section 2.2) cannot be parsed at all and takes the
    whole RRset down, whereas an inconsistent one parsed cleanly and costs only
    itself. Nothing here raises, and a caller that drops the RRset over an
    inconsistency is allowed by that MAY but is throwing away records it was told to
    keep.

    The rules are applied only to ServiceMode, because section 2.4.2 says "In
    AliasMode, recipients MUST ignore any SvcParams that are present" -- parameters
    that are not read cannot be inconsistent. What a zone author should hear about
    instead is :func:`zone_file_warnings`, which the same section invites ("Zone-file
    parsers MAY emit a warning if an AliasMode record has SvcParams").

    >>> self_consistency_problems(1, SvcParams())
    ()
    >>> len(self_consistency_problems(
    ...     1, SvcParams.from_presentation("no-default-alpn")))
    1
    >>> self_consistency_problems(
    ...     1, SvcParams.from_presentation("alpn=h2 no-default-alpn"))
    ()
    >>> self_consistency_problems(
    ...     0, SvcParams.from_presentation("port=8443"))
    ()
    """
    problems: list[str] = []
    if priority == 0:
        return ()
    if params.no_default_alpn and params.alpn is None:
        problems.append(
            '"no-default-alpn" is present without "alpn"; RFC 9460 section 7.1.1: "When '
            "'no-default-alpn' is specified in an RR, 'alpn' must also be specified in "
            'order for the RR to be self-consistent"'
        )
    for key in params.mandatory or ():
        if key not in params:
            problems.append(
                f'mandatory SvcParamKey "{key_to_name(key)}" is not present in the RR; '
                "RFC 9460 section 8: 'For self-consistency (Section 2.4.3), listed keys "
                "MUST also appear in the SvcParams' -- Appendix D Figure 14 is this case"
            )
    dohpath = params.dohpath
    if dohpath is not None and not _DOD_DNS_VARIABLE_RE.search(dohpath):
        problems.append(
            f'dohpath "{dohpath}" references no "dns" variable; RFC 9461 section 5: "The '
            'URI Template MUST contain a "dns" variable", so a client has no way to put '
            "the wire-format DNS query into the request and this RR is unusable"
        )
    return tuple(problems)


#: A "dns" variable reference in a URI Template: ``{?dns}``, ``{&dns}``, ``{dns}``,
#: or one name in a longer expression list such as ``{?dns,foo}``.
_DOD_DNS_VARIABLE_RE = re.compile(r"\{[+#./;?&=,!@|]?[^}]*\bdns\b[^}]*\}")


def zone_file_warnings(
    priority: int,
    target: str,
    params: SvcParams,
    *,
    owner: str = "",
    auto_mandatory: Iterable[IntOrStr] = (),
) -> tuple[str, ...]:
    """What a zone author should be told about a record that is legal but odd.

    RFC 9460 keeps distinguishing "a client MUST do X" from "an operator SHOULD NOT
    publish Y", and it explicitly invites the second kind of feedback: section 2.4.2's
    "Zone-file parsers MAY emit a warning if an AliasMode record has SvcParams" and
    section 2.4.3's "To help zone operators avoid this condition, zone-file
    implementations SHOULD enforce self-consistency as well". A resolver that already
    received the record still obeys only the MUSTs -- :func:`self_consistency_problems`
    and :meth:`SvcbCandidate.compatibility_problems` govern that -- so these strings advise and
    change nothing, which is why they are a separate list rather than more problems.

    *owner* is the record's owner name, which the loop and hint checks need.
    *auto_mandatory* is the protocol mapping's automatically-mandatory key set:
    Appendix B Table 3 gives HTTPS ``port`` and ``no-default-alpn``.

    >>> zone_file_warnings(1, "svc.example.com.", SvcParams())
    ()
    >>> len(zone_file_warnings(
    ...     0, "svc.example.com.", SvcParams.from_presentation("port=8443")))
    1
    >>> len(zone_file_warnings(
    ...     1, ".", SvcParams.from_presentation("ipv4hint=192.0.2.1"),
    ...     owner="svc.example.com."))
    1
    """
    warnings: list[str] = []
    root = target in (".", "")
    if priority == 0:
        if len(params):
            warnings.append(
                f"AliasMode RR (priority 0) carries SvcParams ({params.to_presentation()}); "
                "RFC 9460 section 2.4.2: 'In AliasMode, recipients MUST ignore any SvcParams "
                "that are present', so these are dead weight in the zone"
            )
        if root:
            warnings.append(
                'AliasMode RR with TargetName "." announces that the service is not '
                "available (RFC 9460 section 2.5.1), an advisory indication that section 12 "
                "warns a hostile intermediary could forge"
            )
        elif owner and target == owner:
            warnings.append(
                f"AliasMode RR aliases {target} to itself; RFC 9460 section 2.4.2: 'The "
                "AliasMode TargetName SHOULD NOT be equal to the owner name, as this "
                "would result in a loop'"
            )
        return tuple(warnings)
    # ServiceMode. A root TargetName is NOT a warning here: section 2.5.2 makes it the
    # documented way to say "these parameters apply to the owner name itself".
    if (root or (owner and target == owner)) and (
        int(IPV4HINT) in params or int(IPV6HINT) in params
    ):
        warnings.append(
            f"ServiceMode RR carries address hints while its TargetName is the owner name "
            f"({owner or target}); RFC 9460 section 7.3: when TargetName is the service name "
            "or the owner name, 'server operators SHOULD NOT include these hints, because "
            "they are unlikely to convey any performance benefit'"
        )
    redundant = sorted(
        {key_to_name(params._number(key)) for key in auto_mandatory if params.is_mandatory(key)}
        - {key_to_name(MANDATORY)}
    )
    if redundant:
        warnings.append(
            f"mandatory lists automatically mandatory key(s) {', '.join(redundant)}; RFC 9460 "
            "section 8: 'Other automatically mandatory keys SHOULD NOT appear in the list "
            "either. (Including them wastes space and otherwise has no effect)'"
        )
    return tuple(warnings)


# ------------------------------------------------------ a decoded SVCB record


@dataclass(frozen=True)
class SvcbCandidate:
    """One decoded SVCB or HTTPS RR, ready to be classified and ordered.

    This is the shape :func:`select_records` consumes and the shape
    :class:`namespy.rdata.RData_SVCB` produces. The TargetName is kept exactly as the
    record carried it, because what that field *means* depends on the mode and on
    whether it is the root: :attr:`effective_target` is where section 2.5 folds those
    cases into the one name a client actually uses.
    """

    owner: DomainName
    """The RR owner name -- the name the query asked about."""

    priority: int
    """SvcPriority: 0 selects AliasMode, anything else ServiceMode (section 2.4.1)."""

    target: DomainName
    """The TargetName field as published -- see :attr:`effective_target`."""

    params: SvcParams = field(default_factory=SvcParams)
    """The decoded SvcParams, which AliasMode says to ignore (section 2.4.2)."""

    auto_mandatory: frozenset[int] = frozenset()
    """Keys the protocol mapping treats as mandatory without them being listed.

    Section 8's "automatically mandatory" set: empty for generic SVCB, which has no
    mapping, and :data:`HTTPS_AUTO_MANDATORY` for HTTPS (section 9, Appendix B
    Table 3). :class:`namespy.rdata.RData_HTTPS` fills it in, which is how
    :meth:`compatibility_problems` can apply a rule the record itself never states.
    A frozenset because this dataclass is frozen and hashable.
    """

    @property
    def is_alias(self) -> bool:
        """Whether this RR is AliasMode, i.e. its SvcPriority is 0 (section 2.4.1)."""
        return self.priority == 0

    @property
    def target_is_root(self) -> bool:
        """Whether the TargetName field is ``.`` -- a zero-length label (section 2.5)."""
        return not self.target.labels()

    @property
    def effective_target(self) -> DomainName:
        """The name this RR speaks about, after section 2.5.

        "For ServiceMode SVCB RRs, if TargetName has the value '.', then the owner
        name of this record MUST be used as the effective TargetName." A root in an
        AliasMode RR is different in kind -- an announcement rather than a synthesis
        -- so it stays the root here and is reported by :attr:`target_is_root`.
        """
        if self.target_is_root and not self.is_alias:
            return self.owner
        return self.target

    # ------------------------------------------------------------- wire format

    @classmethod
    def from_wire(cls, owner: DomainName | str, rdata: bytes) -> SvcbCandidate:
        """Decode a whole SVCB/HTTPS RDATA: SvcPriority, TargetName, SvcParams.

        Section 2.2's layout, and the reason the parameters carry no length of their
        own: they consume "the remainder of the record", so
        :meth:`SvcParams.from_wire` is told where the record ends and refuses a
        SvcParam that would run past it.

        Section 2.2 asks for "the *uncompressed*, fully qualified TargetName". A
        compression pointer in that field is therefore not what a sender should
        produce -- but it is not one of the three conditions that make an RR
        malformed either, so it is accepted here and normalised: :meth:`to_wire`
        always writes the expanded name, and a caller that needs the received octets
        for a hex dump keeps them the way :class:`namespy.rdata.RData` does, in a
        separate ``wire`` copy.
        """
        blob = bytes(rdata)
        if len(blob) < 3:
            raise DnsPacketParseError(
                f"SVCB RDATA is {len(blob)} octet(s), too short for SvcPriority and a TargetName",
                data=blob,
                offset=0,
            )
        (priority,) = struct.unpack_from("!H", blob, 0)
        target, cursor = DomainName.parse_from(blob, 2)
        params, cursor = SvcParams.from_wire(blob, cursor, size=len(blob) - cursor, data=blob)
        if cursor != len(blob):
            raise DnsPacketParseError(
                f"SVCB RDATA has {len(blob) - cursor} trailing octet(s) after the SvcParams",
                data=blob,
                offset=cursor,
            )
        return cls(
            owner=owner if isinstance(owner, DomainName) else DomainName(owner),
            priority=priority,
            target=target,
            params=params,
        )

    def to_wire(self) -> bytes:
        """Re-encode the RDATA, expanding the TargetName as section 2.2 requires."""
        return struct.pack("!H", self.priority) + bytes(self.target) + self.params.to_wire()

    @classmethod
    def from_presentation(cls, owner: DomainName | str, text: str) -> SvcbCandidate:
        """Decode master-file RDATA -- ``priority target [key=value ...]``.

        Section 2.1's RDATA order. The TargetName is read with the same tokenizer as
        the parameters, so a name containing an escaped space stays one token, and
        ``.`` passes through unchanged: section 2.5 makes it a value with meaning
        rather than a way of writing "no target".

        >>> str(SvcbCandidate.from_presentation("example.com.", "1 . port=8002"))
        '1 . port=8002'
        >>> SvcbCandidate.from_presentation("example.com.", "0 svc.example.net.").is_alias
        True
        """
        parts = _split_params(text.strip())
        if not parts:
            raise ValueError("SVCB RDATA needs at least a SvcPriority and a TargetName")
        try:
            priority = int(parts[0], 10)
        except ValueError:
            raise ValueError(f"SvcPriority {parts[0]!r} is not a decimal integer") from None
        if not 0 <= priority <= 65535:
            raise ValueError(f"SvcPriority {priority} is outside 0..65535")
        if len(parts) < 2:
            raise ValueError("SVCB RDATA needs a TargetName after the SvcPriority")
        return cls(
            owner=owner if isinstance(owner, DomainName) else DomainName(owner),
            priority=priority,
            target=DomainName(parts[1]),
            params=SvcParams.from_presentation(" ".join(parts[2:])),
        )

    # ----------------------------------------------------- self-consistency

    @property
    def problems(self) -> tuple[str, ...]:
        """Section 2.4.3's self-consistency complaints about this RR, if any.

        Computed on access rather than stored: it depends only on fields a frozen
        dataclass cannot change, and living on the record means the reason a record
        is unusable is always quoted from the check that fired.
        """
        return self_consistency_problems(self.priority, self.params)

    @property
    def self_consistent(self) -> bool:
        """Whether a client may act on this RR at all.

        Section 2.4.3: "Clients MUST reject any RR whose recognized SvcParams are not
        self-consistent and MAY reject the entire RRset." That MAY is exercised by
        :func:`select_records`, not here: this property is the per-record answer.
        Malformed RDATA is a different matter and never reaches this class --
        :meth:`SvcParams.from_wire` raises, because section 2.2 makes a malformed
        record the whole RRset's problem.
        """
        return not self.problems

    def warnings(self, *, auto_mandatory: Iterable[IntOrStr] | None = None) -> tuple[str, ...]:
        """Advisories for the operator of this record -- see :func:`zone_file_warnings`.

        *auto_mandatory* is the protocol mapping's automatically-mandatory key set;
        None means :attr:`auto_mandatory`, i.e. the set this record's mapping brings
        with it. Appendix B Table 3 gives HTTPS ``port`` and ``no-default-alpn``,
        which is what :class:`namespy.rdata.RData_HTTPS` fills in.
        """
        return zone_file_warnings(
            self.priority,
            str(self.target),
            self.params,
            owner=str(self.owner),
            auto_mandatory=self.auto_mandatory if auto_mandatory is None else auto_mandatory,
        )

    # --------------------------------------------------------- compatibility

    def compatibility_problems(
        self,
        client_keys: Iterable[IntOrStr] | None = None,
        *,
        client_alpn: Iterable[bytes] = (),
        default_alpn: Sequence[bytes] = (),
        auto_mandatory: Iterable[IntOrStr] | None = None,
    ) -> tuple[str, ...]:
        """Section 8's compatibility test, reported as the reasons this RR failed it.

        Section 8: "A ServiceMode RR is considered 'compatible' by a client if the
        client recognizes all the mandatory keys and their values indicate that
        successful connection establishment is possible. Incompatible RRs are ignored
        (see step 5 of the procedure defined in Section 3)." Both halves of that
        sentence are checked:

        * *client_keys* is what the client recognizes. It defaults to the keys this
          module can decode, so a record whose ``mandatory`` list names ``key65333``
          is unusable here: the client must convey such a key onward (section 4.3)
          but cannot act on what it means.
        * *client_alpn*, when non-empty, is the client's own protocol id set. Section
          7.1.2 step 1 intersects it with the SVCB ALPN set, and an empty intersection
          means no transport can be negotiated -- which is precisely "values [that do]
          not indicate that successful connection establishment is possible". Empty by
          default, meaning "this client does not use ALPN", which leaves the check
          inert rather than fatal. *default_alpn* is the scheme's default set, passed
          straight to :meth:`SvcParams.svc_alpn_set`.
        * *auto_mandatory* is the mapping's implicitly mandatory key set; None means
          use :attr:`auto_mandatory`, which is what makes an HTTPS record behave per
          section 9 without the caller repeating Appendix B Table 3 at every call.

        AliasMode is reported compatible without further tests: section 8 states the
        test for ServiceMode, and section 2.4.2 makes the parameters that would be
        tested irrelevant anyway.
        """
        if self.is_alias:
            return ()
        recognized = (
            frozenset(_PARSABLE_KEYS)
            if client_keys is None
            else frozenset(self.params._number(key) for key in client_keys)
        )
        problems: list[str] = []
        listed = self.params.mandatory or ()
        for key in listed:
            if key not in recognized:
                problems.append(
                    f'mandatory SvcParamKey "{key_to_name(key)}" is not recognized by this '
                    "client; RFC 9460 section 8 requires recognizing all mandatory keys and "
                    "says 'Incompatible RRs are ignored'"
                )
        implicit = (
            self.auto_mandatory
            if auto_mandatory is None
            else frozenset(self.params._number(key) for key in auto_mandatory)
        )
        for key in sorted(implicit - set(listed)):
            if key in recognized or key not in self.params:
                continue
            problems.append(
                f'SvcParamKey "{key_to_name(key)}" is automatically mandatory for this '
                "protocol mapping; RFC 9460 section 8: 'If a client encounters an "
                "automatically mandatory key that it does not recognize, it MUST ignore "
                "the RR containing that SvcParamKey'"
            )
        if client_alpn:
            offered = self.params.svc_alpn_set(default_alpn)
            if offered is not None and not set(offered) & set(client_alpn):
                problems.append(
                    "the SVCB ALPN set has no protocol this client supports; RFC 9460 "
                    "section 7.1.2 step 1 would leave SVCB-ALPN-Intersection empty, so "
                    "there is no transport to negotiate"
                )
        return tuple(problems)

    def is_compatible(
        self,
        client_keys: Iterable[IntOrStr] | None = None,
        *,
        client_alpn: Iterable[bytes] = (),
        default_alpn: Sequence[bytes] = (),
        auto_mandatory: Iterable[IntOrStr] | None = None,
    ) -> bool:
        """Whether section 8 calls this RR "compatible" -- see :meth:`compatibility_problems`."""
        return not self.compatibility_problems(
            client_keys,
            client_alpn=client_alpn,
            default_alpn=default_alpn,
            auto_mandatory=auto_mandatory,
        )

    # -------------------------------------------------------------- rendering

    def __str__(self) -> str:
        """The RDATA in master-file form: ``priority target [svc-value]``.

        Section 2.1's RDATA order, which is why the parameters follow the name and why
        :meth:`SvcParams.to_presentation` renders no leading space. An AliasMode
        record's TargetName is printed as published even when it is ``.``, because
        section 2.5.1 makes that a meaningful announcement rather than a typo.
        """
        params = self.params.to_presentation()
        head = f"{self.priority} {self.target}"
        return f"{head} {params}" if params else head


# ---------------------------------------------------------- RRset selection


class SkippedRecord(NamedTuple):
    """A record the client must ignore, and the reasons that took it out.

    Keeping the reasons beside the record rather than in a parallel list means a
    diagnostic can never drift out of step with the list it explains -- and both
    reasons are recomputable from the record, so this is a convenience, not a second
    source of truth.
    """

    record: SvcbCandidate
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class SvcbSelection:
    """What to do with one RRset of SVCB (or HTTPS) records, per RFC 9460 section 3.

    Produced by :func:`select_records`. The fields are mutually exclusive by mode:
    exactly one of :attr:`alias` and :attr:`service` is non-empty, and the mode
    property names which.
    """

    alias: tuple[SvcbCandidate, ...] = ()
    """Usable AliasMode RRs, best candidate first. Non-empty means ServiceMode was ignored."""

    service: tuple[SvcbCandidate, ...] = ()
    """Usable, compatible ServiceMode RRs, in the order section 3 step 4 asks for."""

    skipped: tuple[SkippedRecord, ...] = ()
    """Records the client must ignore, each with its :attr:`~SkippedRecord.reasons`."""

    notes: tuple[str, ...] = ()
    """Advisories about the RRset as a whole -- see :func:`zone_file_warnings`."""

    alias_processed: bool = False
    """Whether the RRset yielded an AliasMode record.

    Section 3: "if at least one AliasMode record was processed, SVCB-optional clients
    SHALL append to the list of endpoints an endpoint consisting of the final value of
    $QNAME, the authority endpoint's port number, and no SvcParams." A client that is
    SVCB-optional uses this flag to decide whether to add that fallback; it is true
    even when the alias announced that the service does not exist.
    """

    @property
    def mode(self) -> str:
        """``"alias"``, ``"service"``, or ``"none"`` -- which kind of record governs.

        Section 2.4.1: "Within a SVCB RRset, all RRs SHOULD have the same mode. If an
        RRset contains a record in AliasMode, the recipient MUST ignore any ServiceMode
        records in the set." ``"none"`` is section 3's step 5: SVCB resolution has
        failed and the endpoint list is empty, so a SVCB-optional client falls back to
        ordinary address records for the original name.
        """
        if self.alias:
            return "alias"
        if self.service:
            return "service"
        return "none"

    @property
    def alias_target(self) -> DomainName | None:
        """The name to re-query, or None when there is nothing to alias to.

        Section 3 step 3: "set $QNAME to its TargetName (without additional prefixes)
        and loop back to Step 2" -- which is why this returns the published TargetName
        rather than :attr:`~SvcbCandidate.effective_target`.
        """
        if not self.alias:
            return None
        return self.alias[0].target

    @property
    def absent(self) -> bool:
        """Whether the governing record announces that the service does not exist.

        Section 2.5.1: 'For AliasMode SVCB RRs, a TargetName of "." indicates that the
        service is not available or does not exist. This indication is advisory:
        clients encountering this indication MAY ignore it'. Advisory is the key word
        -- a client that ignores it gets the ordinary address records of the same
        name, which is what :attr:`mode` ``"none"`` also leads to.
        """
        return bool(self.alias) and self.alias[0].target_is_root

    @property
    def targets(self) -> tuple[DomainName, ...]:
        """The endpoints to try, in order, after section 2.5 has been applied.

        Empty for AliasMode, where the answer is one name to go query again rather
        than a set of endpoints, and for ``"none"``.
        """
        return tuple(record.effective_target for record in self.service)


def select_records(
    records: Iterable[SvcbCandidate],
    *,
    client_keys: Iterable[IntOrStr] | None = None,
    client_alpn: Iterable[bytes] = (),
    default_alpn: Sequence[bytes] = (),
    strict: bool = False,
    shuffle: Callable[[list[SvcbCandidate]], None] | None = random.shuffle,
) -> SvcbSelection:
    """Order one RRset the way section 3's SVCB resolution procedure does.

    Section 3 lists five steps, and this function is the three that need no network:
    step 3, "If an AliasMode SVCB record is returned for $QNAME..., set $QNAME to its
    TargetName (without additional prefixes) and loop back to Step 2" -- the loop
    itself belongs to the caller, so an AliasMode result is
    :attr:`SvcbSelection.alias_target` and the caller re-queries; step 4, "If one or
    more 'compatible' (Section 8) ServiceMode records are returned, these represent
    the alternative endpoints. Sort the records by ascending SvcPriority"; and step 5,
    "Otherwise, SVCB resolution has failed, and the list of available endpoints is
    empty", which is :attr:`SvcbSelection.mode` ``"none"``.

    Nothing in section 3 mentions SvcPriority when deciding between the two modes --
    that decision is section 2.4.1's, "If an RRset contains a record in AliasMode, the
    recipient MUST ignore any ServiceMode records in the set" -- so an AliasMode RR
    wins regardless of what else arrived, and the ServiceMode records that lost are
    reported in :attr:`SvcbSelection.skipped` rather than vanishing.

    Two independent tests decide which records are eligible at all. Section 2.4.3
    ("Clients MUST reject any RR whose recognized SvcParams are not self-consistent and
    MAY reject the entire RRset") is :attr:`SvcbCandidate.problems`, and the MAY is what
    *strict* exercises: with it True, one inconsistent record empties the RRset, which
    is allowed but throws away records the client was told to keep. Section 8
    ("Incompatible RRs are ignored") is :meth:`SvcbCandidate.compatibility_problems`, and
    it has no RRset-wide variant -- an incompatible record always costs only itself.
    *client_keys*, *client_alpn* and *default_alpn* say what this client understands and
    are passed straight through. A record's automatically-mandatory key set is not a
    client setting but a property of its mapping, so it arrives on the candidate
    (:attr:`SvcbCandidate.auto_mandatory`) and needs no argument here.

    Ties are section 2.4.1's: "When receiving an RRset containing multiple SVCB records
    with the same SvcPriority value, clients SHOULD apply a random shuffle within a
    priority level to the records before using them, to ensure uniform load balancing".
    The default :func:`random.shuffle` runs before a stable sort, so it reorders inside
    a priority level and nowhere else. Pass ``shuffle=None`` for the published order,
    which is what a test, a zone-file report, or a reproducible trace wants.

    One thing a caller has to keep straight: an RRset is per RR type, and section
    2.4.2 ends with "AliasMode records only apply to queries for the specific RR type.
    For example, a SVCB record cannot alias to an HTTPS record or vice versa". So
    *records* must be one RR type, and when following an alias the caller must query
    the same type again.

    >>> def rec(text, owner="example.com."):
    ...     return SvcbCandidate.from_presentation(owner, text)
    >>> selection = select_records(
    ...     [rec("2 svc2.example.com. port=8002"), rec("1 svc1.example.com.")],
    ...     shuffle=None)
    >>> selection.mode, [str(name) for name in selection.targets]
    ('service', ['svc1.example.com.', 'svc2.example.com.'])

    An AliasMode record in the same RRset takes precedence over both of those:

    >>> selection = select_records(
    ...     [rec("2 svc2.example.com."), rec("0 alias.example.net.")], shuffle=None)
    >>> selection.mode, str(selection.alias_target), selection.service
    ('alias', 'alias.example.net.', ())
    >>> len(selection.skipped)
    1

    And a record that fails a test costs only itself:

    >>> selection = select_records([rec("1 . alpn=h2"), rec("1 . no-default-alpn")])
    >>> len(selection.service), len(selection.skipped)
    (1, 1)
    >>> len(selection.skipped[0].reasons)
    1
    """
    candidates = list(records)
    inconsistent = [record for record in candidates if not record.self_consistent]
    if strict and inconsistent:
        detail = "; ".join(reason for record in inconsistent for reason in record.problems)
        return SvcbSelection(
            skipped=tuple(SkippedRecord(record, record.problems) for record in candidates),
            notes=(
                "RFC 9460 section 2.4.3 permits rejecting the entire RRset when a "
                "record is not self-consistent, and strict=True took that option: " + detail,
            ),
        )
    usable: list[SvcbCandidate] = []
    skipped: list[SkippedRecord] = []
    notes: list[str] = []
    for record in candidates:
        reasons = record.problems + record.compatibility_problems(
            client_keys, client_alpn=client_alpn, default_alpn=default_alpn
        )
        if reasons:
            skipped.append(SkippedRecord(record, reasons))
        else:
            usable.append(record)
    aliases = [record for record in usable if record.is_alias]
    services = [record for record in usable if not record.is_alias]
    if shuffle is not None:
        shuffle(aliases)
        shuffle(services)
    if aliases:
        if len(aliases) > 1:
            notes.append(
                f"{len(aliases)} AliasMode RRs in one RRset; RFC 9460 section 2.4.2: "
                "'SVCB RRsets SHOULD only have a single RR in AliasMode. If multiple "
                "AliasMode RRs are present, clients or recursive resolvers SHOULD pick "
                "one at random' -- alias[0] is the one this selection picked"
            )
        if services:
            notes.append(
                f"{len(services)} ServiceMode RR(s) set aside; RFC 9460 section 2.4.1: "
                "'If an RRset contains a record in AliasMode, the recipient MUST ignore "
                "any ServiceMode records in the set'"
            )
            skipped.extend(SkippedRecord(record, (notes[-1],)) for record in services)
            services = []
        return SvcbSelection(
            alias=tuple(aliases),
            skipped=tuple(skipped),
            notes=tuple(notes),
            alias_processed=True,
        )
    if services:
        # Stable sort: records that share a SvcPriority keep their shuffled order,
        # which is what section 2.4.1's "uniform load balancing" is for.
        services.sort(key=lambda record: record.priority)
        return SvcbSelection(service=tuple(services), skipped=tuple(skipped), notes=tuple(notes))
    if candidates:
        notes.append(
            "no usable record in the RRset; RFC 9460 section 3 step 5: 'SVCB resolution "
            "has failed, and the list of available endpoints is empty', so a "
            "SVCB-optional client falls back to the address records of the original name"
        )
    return SvcbSelection(skipped=tuple(skipped), notes=tuple(notes))
