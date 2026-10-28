"""Wire-format primitives shared by :mod:`namespy.names` and :mod:`namespy.packet`.

This module exists so that name parsing can raise structured errors without
importing :mod:`namespy.packet` (which imports :mod:`namespy.names`). Everything
here is deliberately dependency-free.

Two rules drive the design of the readers in this package:

1. **No :keyword:`assert` on network data.** ``assert`` disappears under
   ``python -O`` / ``PYTHONOPTIMIZE``, which silently removes every bounds and
   loop check. A malformed datagram must raise :class:`DnsPacketParseError`
   (or a subclass) unconditionally.
2. **Fail closed and early.** Per RFC 5625 §6.3 a receiver MAY drop messages
   with invalid compression pointers or section counts that cannot be
   satisfied; per RFC 9267 §2 blindly following compression pointers enables
   both denial of service (pointer loops) and memory corruption. Validation is
   therefore structural and bounded, never "parse and hope".

.. rubric:: References

* RFC 1035 §3.1 (label/full-name length limits), §4.1.4 (compression)
* RFC 2181 §11 (no syntax restrictions on labels)
* RFC 3597 §4 (compression only for well-known types)
* RFC 5625 §6.3 (dropping malformed packets)
* RFC 9267 §2, §4, §5 (pointer loops, name buffer, RDLENGTH validation)
"""

from __future__ import annotations

#: RFC 1035 §3.1: the length of any one label is limited to between 1 and 63 octets.
MAX_LABEL_OCTETS = 63

#: RFC 1035 §3.1 / RFC 2181 §11: a full domain name is limited to 255 octets,
#: counting the label length octets and the terminating root label.
MAX_NAME_OCTETS = 255

#: RFC 1035 §4.1.4 allows a name to be "a sequence of labels ending with a
#: pointer", and a pointer may itself land on another pointer. Each hop
#: consumes at least two octets of the 255-octet budget, so 128 hops is
#: generous; the cap exists to make termination obvious rather than argued.
MAX_POINTER_HOPS = 128

#: Fixed DNS header size in octets (RFC 1035 §4.1.1).
HEADER_OCTETS = 12

#: High-order bit patterns of a label-length / pointer octet (RFC 1035 §4.1.4).
_LABEL_MASK = 0xC0
_POINTER_TAG = 0xC0
_POINTER_OFFSET_MASK = 0x3F  # low 6 bits of the pointer's first octet
_RESERVED_LABEL_TYPES = (0x40, 0x80)  # 0b01 and 0b10: "reserved for future use"


class DnsPacketParseError(ValueError):
    """Raised when a DNS wire message cannot be parsed.

    Carries enough context to debug a live capture without re-running the
    parser: the offending datagram, the octet offset at which parsing failed,
    and a contiguous hex rendering of the whole message.

    Deliberately a :class:`ValueError` subclass so existing callers that
    already catch :class:`ValueError` keep working.
    """

    def __init__(
        self,
        message: str,
        *,
        data: bytes = b"",
        offset: int | None = None,
    ) -> None:
        super().__init__(message)
        self.data = data
        self.offset = offset

    def wire_hex(self) -> str:
        """Contiguous hex for the full datagram (same as :meth:`bytes.hex`)."""
        return self.data.hex()


class DnsNameParseError(DnsPacketParseError):
    """A domain name on the wire is malformed (bad label, pointer, or length).

    Subclasses :class:`DnsPacketParseError` so that a name failure inside an RR
    is caught by the same handler that catches whole-message failures.
    """


def is_compression_pointer(octet: int) -> bool:
    """Whether ``octet`` begins a compression pointer.

    RFC 1035 §4.1.4 assigns the two most-significant bits ``11`` to pointers,
    and RFC 9267 §2 shows the exact bug this guards against: testing
    ``octet & 0xC0`` (truthy) rather than ``octet & 0xC0 == 0xC0`` treats an
    octet with *either* bit set as a pointer, so an invalid label length such
    as ``0x41`` (65 > 63) is reinterpreted as a pointer and slips past
    validation.
    """
    return (octet & _LABEL_MASK) == _POINTER_TAG


def is_reserved_label_type(octet: int) -> bool:
    """Whether ``octet`` carries a label type RFC 1035 leaves unassigned.

    The ``01`` and ``10`` two-bit combinations are "reserved for future use";
    accepting them (or, worse, misreading them as something else) is how
    parsers get pulled into undefined behaviour.
    """
    return (octet & _LABEL_MASK) in _RESERVED_LABEL_TYPES


def pointer_target(octet: int, next_octet: int) -> int:
    """Decode the 14-bit message offset of a compression pointer.

    The 14-bit field spans *both* octets, so the tag bits must be cleared from
    the first octet before the shift: ``(octet & 0x3F) << 8 | next_octet``.
    Masking the already-shifted octet with ``0x3FFF`` instead leaves bit 6 set
    and yields a target inflated by 16384 -- which then sails past every
    bounds check as "out of range" rather than being read at all.
    """
    return ((octet & _POINTER_OFFSET_MASK) << 8) | next_octet


def read_octets(buffer: bytes, offset: int, count: int, *, what: str, data: bytes | None = None):
    """Return ``buffer[offset : offset + count]``, raising on truncation.

    Slicing past the end of a datagram is the single easiest way to turn a
    truncated message into a confusing downstream failure: a short slice is
    falsy rather than fatal, and an :class:`IndexError` from a later index is
    attributed to the wrong offset. Always bound the read.
    """
    if offset < 0 or offset + count > len(buffer):
        raise DnsPacketParseError(
            f"truncated {what}: need {count} octet(s) at offset {offset}, "
            f"have {max(0, len(buffer) - offset)} of {len(buffer)}",
            data=buffer if data is None else data,
            offset=offset,
        )
    return buffer[offset : offset + count]
