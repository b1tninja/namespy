"""Wire-form name parsing: compression, arbitrary labels, and hostile input.

Every case here is anchored in a spec obligation rather than an implementation
detail:

* RFC 1035 section 3.1 -- 63-octet labels, 255-octet names, wire form
* RFC 1035 section 4.1.4 -- compression pointers, "a sequence of labels ending
  with a pointer", reserved ``01``/``10`` label types
* RFC 2181 section 11 -- no syntax restrictions on labels
* RFC 4592 section 4 / BCP 222 -- wildcards and underscored node names
* RFC 9267 sections 2 and 4 -- pointer loops, name-buffer limits

The corpus is deliberately built from raw octets rather than from this
library's own encoder, so a bug in :meth:`DomainName.__bytes__` cannot hide a
bug in :meth:`DomainName.parse_from`.
"""

import ast
import pathlib

import pytest

from aiodns.names import DomainName, escape_label, unescape_label
from aiodns.wire import MAX_NAME_OCTETS, DnsNameParseError

# A response-shaped message: 12-octet header, QNAME at 12, QTYPE/QCLASS at 25,
# then an answer whose NAME is a pointer back to 12 (the shape real servers
# emit for every RR in the answer section).
MESSAGE = (
    b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
    b"\x07example\x03com\x00"
    b"\x00\x01\x00\x01"
    b"\xc0\x0c"
    b"\x00\x01\x00\x01\x00\x00\x00\x40\x00\x04\x7f\x00\x00\x01"
)


def test_plain_name_consumes_exactly_its_octets() -> None:
    wire = b"\x07example\x03com\x00"
    name, offset = DomainName.parse_from(wire, 0)
    assert str(name) == "example.com."
    assert offset == len(wire)
    assert name.is_absolute


def test_root_label_is_zero_octet_and_absolute() -> None:
    name, offset = DomainName.parse_from(b"\x00\xff", 0)
    assert str(name) == "."
    assert offset == 1  # the pointer octet is not ours to consume
    assert name == DomainName.root_label()


def test_compression_pointer_expands_and_folds_equal() -> None:
    question, _ = DomainName.parse_from(MESSAGE, 12)
    answer, offset = DomainName.parse_from(MESSAGE, 29)
    assert str(answer) == "example.com."
    # RFC 1035 4.1.4: the pointer *is* the name's last element, so the
    # enclosing record resumes just past the pointer's two octets.
    assert offset == 31
    assert answer == question
    assert hash(answer) == hash(question)


def test_pointer_to_pointer_chain_is_followed() -> None:
    # labels @0..12, a pointer @13 -> 0, then "\x03www" + pointer @19 -> 13.
    # The final pointer lands on another pointer, which is legal wire form
    # ("a sequence of labels ending with a pointer") that single-hop parsers
    # reject.
    buffer = b"\x07example\x03com\x00\xc0\x00\x03www\xc0\x0d"
    name, offset = DomainName.parse_from(buffer, 15)
    assert str(name) == "www.example.com."
    assert offset == len(buffer)


@pytest.mark.parametrize(
    ("wire", "expected"),
    [
        # RFC 2181 11: the DNS itself imposes no label syntax. These are all
        # ordinary names in production traffic and must parse.
        (b"\x06_dmarc\x07example\x03com\x00", "_dmarc.example.com."),
        (b"\x04_svc\x06_https\x07example\x03com\x00", "_svc._https.example.com."),
        (b"\x01*\x07example\x03com\x00", "*.example.com."),
        (b"\x011\x010\x010\x017\x07example\x03com\x00", "1.0.0.7.example.com."),
        (b"\x03a_b\x03com\x00", "a_b.com."),
    ],
)
def test_underscored_wildcard_and_digit_labels_parse(wire: bytes, expected: str) -> None:
    name, offset = DomainName.parse_from(wire, 0)
    assert str(name) == expected
    assert offset == len(wire)


def test_arbitrary_label_octets_survive_roundtrip() -> None:
    # A label holding a dot, a NUL, and non-ASCII must not split into two
    # labels, and re-encoding must be byte-identical (RFC 2181 11).
    wire = bytes([3, 0x2E, 0x00, 0xE9]) + b"\x03com\x00"
    name, _ = DomainName.parse_from(wire, 0)
    assert name.labels() == [bytes([0x2E, 0x00, 0xE9]), b"com"]
    assert bytes(name) == wire
    assert str(name).count("\\") >= 3  # stored escaped, not raw


def test_escape_helpers_roundtrip_every_octet() -> None:
    for value in range(256):
        raw = bytes([value])
        assert unescape_label(escape_label(raw)) == raw


def test_dotted_label_cannot_fabricate_hierarchy() -> None:
    name, _ = DomainName.parse_from(bytes([2, 0x2E, 0x2E]) + b"\x03com\x00", 0)
    assert len(name.labels()) == 2


# --------------------------------------------------------------------------- hostile corpus

SELF_POINTER = b"\x07example\x03com\x00\xc0\x0d"
FORWARD_POINTER = b"\x00\xc0\x05\xff"
LOOP_PAIR = b"\x00\xc0\x03\xc0\x01"


@pytest.mark.parametrize(
    ("label", "wire", "offset"),
    [
        # RFC 9267 2: the reference "broken implementation" tested
        # ``octet & 0xC0`` truthily, so 0x41 (single tag bit set, and a 65-octet
        # label length) was silently reinterpreted as a pointer.
        ("single tag bit set (0x41)", b"\x41abc", 0),
        ("reserved label type 0b01", b"\x40\x00", 0),
        ("reserved label type 0b10", b"\x80\x00", 0),
        ("label length 64", b"\x40" + b"a" * 64 + b"\x00", 0),
        ("label truncated by message end", b"\x07exa", 0),
        ("name never terminated", b"\x03com", 0),
        ("name starts past end of message", b"\x03com", 40),
        ("negative offset", b"\x00", -1),
        ("pointer to itself", SELF_POINTER, 13),
        ("pointer to end of message", b"\x00\xc0\x01\xff", 1),
        ("forward pointer", FORWARD_POINTER, 1),
        ("pointer pair forming a loop", LOOP_PAIR, 3),
        ("pointer target past end", b"\x00\xdf\xff", 1),
        ("pointer to header then unterminated", b"\xff\xff" + b"\xc0\x00" * 8, 2),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_hostile_input_raises_structured_error(label, wire, offset) -> None:
    """Malformed names must fail *closed*, with type and context.

    :class:`DnsNameParseError` is a :class:`ValueError`, so callers that only
    know about ``ValueError`` still catch it; ``data``/``offset`` survive so a
    live capture can be debugged without re-running the parser.
    """
    with pytest.raises(DnsNameParseError) as excinfo:
        DomainName.parse_from(wire, offset)
    assert isinstance(excinfo.value, ValueError)
    assert excinfo.value.data == wire
    assert excinfo.value.wire_hex() == wire.hex()


def test_pointer_chain_work_is_bounded() -> None:
    """A long descending pointer chain stops rather than expanding forever.

    Each hop is 2 octets and must move backwards, so the walk is bounded by
    both the 255-octet name budget and the hop cap; either way the result is an
    error, not a hang and not a megabyte of expanded text (RFC 9267 2, 4).
    """
    buffer = bytearray(b"\x07example\x03com\x00")
    target = 0
    for _ in range(400):
        pointer_offset = len(buffer)
        buffer += bytes([0xC0 | (target >> 8), target & 0xFF])
        target = pointer_offset
    buffer = bytes(buffer)
    with pytest.raises(DnsNameParseError):
        DomainName.parse_from(buffer, len(buffer) - 2)


def test_name_budget_counts_length_octets_and_root() -> None:
    fitting = b"".join(b"\x14" + b"l" * 20 for _ in range(12)) + b"\x00"
    assert len(fitting) <= MAX_NAME_OCTETS
    name, _ = DomainName.parse_from(fitting, 0)
    assert len(name.labels()) == 12

    too_long = b"".join(b"\x14" + b"l" * 20 for _ in range(13)) + b"\x00"
    assert len(too_long) > MAX_NAME_OCTETS
    with pytest.raises(DnsNameParseError):
        DomainName.parse_from(too_long, 0)


def test_random_garbage_never_leaks_unexpected_exception() -> None:
    """Fuzz-lite: only the declared error types may escape the parser.

    Deterministic (fixed seed) so a failure is reproducible; a
    :class:`hypothesis` strategy is the natural next step once the dependency
    lands in the dev extra.
    """
    import random

    rng = random.Random(20261027)
    for _ in range(3000):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 40)))
        offset = rng.randrange(0, max(1, len(blob))) if blob else 0
        try:
            name, end = DomainName.parse_from(blob, offset)
        except (DnsNameParseError, ValueError):
            continue
        assert 0 <= end <= len(blob)
        assert len(name.labels()) <= 128


def test_parser_has_no_bare_assert() -> None:
    """The wire readers must not use :keyword:`assert` for validation.

    ``assert`` is erased by ``python -O`` / ``PYTHONOPTIMIZE``, which is exactly
    how a bounds check quietly stops existing in production. This test fails if
    anyone reintroduces one, in either the name parser or the shared primitives.
    """
    package = pathlib.Path(__file__).resolve().parent.parent / "aiodns"
    for filename in ("names.py", "wire.py"):
        tree = ast.parse((package / filename).read_text(encoding="utf-8"))
        offenders = [node.lineno for node in ast.walk(tree) if isinstance(node, ast.Assert)]
        assert offenders == [], f"{filename} asserts at {offenders}"


def test_encoder_rejects_what_the_wire_cannot_carry() -> None:
    with pytest.raises(ValueError):
        bytes(DomainName("a" * 64 + ".example.com."))
    with pytest.raises(ValueError):
        bytes(DomainName(".".join(["l" * 60] * 6) + "."))
    assert bytes(DomainName(".")) == b"\x00"
    assert bytes(DomainName("example.com.")) == b"\x07example\x03com\x00"
    # The presentation root terminator is not a label: no zero-length label
    # may appear ahead of the real terminator.
    assert not bytes(DomainName("example.com.")).startswith(b"\x00")


def test_host_name_check_is_opt_in() -> None:
    assert DomainName("www.example.com").is_hostname
    assert not DomainName("_dmarc.example.com").is_hostname  # BCP 222
    assert not DomainName("*.example.com").is_hostname  # RFC 4592
    assert not DomainName("-bad.example.com").is_hostname
    assert not DomainName("bad-.example.com").is_hostname
    assert DomainName(".").is_hostname  # vacuously
