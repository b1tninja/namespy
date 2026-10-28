"""DNS message framing: header, question section, and the three RR sections.

Parsing here is a trust boundary. Everything that arrives is an untrusted
datagram, so the rules set out in :mod:`namespy.wire` apply throughout:

* **No :keyword:`assert` on anything that came off the wire.** An ``assert``
  compiled out by ``python -O`` or ``PYTHONOPTIMIZE`` is not a check, and the
  previous revision of this module used one for every bounds test.
* **Every failure is** :class:`~namespy.wire.DnsPacketParseError`, carrying the
  datagram and the offset at which parsing gave up.
* **Structure is validated before it is trusted** -- section counts must be
  satisfiable, and RDLENGTH must fit inside the message (RFC 9267 section 5).

The exception type lives in :mod:`namespy.wire` and is re-exported here for
existing import sites. Having it defined in two places once meant a failure
raised as one class and caught as the other, so malformed datagrams escaped the
``except DnsPacketParseError`` handlers in :mod:`namespy.server` and
:mod:`namespy.resolver` entirely.

.. rubric:: References

* RFC 1035 section 4.1 (message format), 4.1.1 (header), 4.1.4 (compression)
* RFC 2181 section 8 (TTLs are relative, and must be clamped when served)
* RFC 5625 section 6.3 (drop messages that are malformed)
* RFC 9267 sections 2, 4, 5 (pointer loops, name buffer, RDLENGTH)
"""

from __future__ import annotations

import logging
import secrets
import struct

from .enums import (
    DnsOpCode,
    DnsQClass,
    DnsQR,
    DnsQType,
    DnsRClass,
    DnsResponseCode,
    DnsRType,
)
from .names import DomainName
from .rdata import RData, rdata_class_for, type_name_of
from .wire import HEADER_OCTETS, DnsPacketParseError, read_octets

__all__ = [
    "OPT_RTYPE",
    "DnsPacket",
    "DnsPacketParseError",
    "DnsQuestion",
    "DnsRecord",
    "Query",
    "Response",
    "clamp_ttl",
]

LOGGER = logging.getLogger(__name__)

_HEADER_FMT = "!HBBHHHH"
_RECORD_FMT = "!HHIH"

#: RFC 2181 section 8: a served TTL must not exceed 2147483647 seconds (~68y).
MAX_SERVABLE_TTL = 0x7FFFFFFF


def clamp_ttl(ttl: int) -> int:
    """Clamp a wire TTL to what a resolver may actually serve (RFC 2181 section 8).

    The wire field is 32 bits unsigned, so a buggy or hostile server can offer
    ``0xFFFFFFFF``; caching that literally yields an RRset that never expires.
    RFC 2181 section 8 says a server "MUST NOT serve a TTL value that is larger
    than 2147483647", and that anything larger must be treated as exactly that.
    """
    value = int(ttl)
    if value < 0:
        return 0
    return min(value, MAX_SERVABLE_TTL)


class DnsQuestion:
    """One entry of the question section (RFC 1035 section 4.1.2).

    QTYPE and QCLASS are left as plain ``int`` when the registry has no member
    for them -- RFC 3597 section 3 requires unknown values to pass through
    rather than abort the parse.
    """

    _FMT = "!HH"
    _SIZE = struct.calcsize(_FMT)

    __slots__ = ("name", "qclass", "qtype")

    def __init__(self, qname, qtype=DnsQType.ANY, qclass=DnsRClass.IN):
        self.name = qname if isinstance(qname, DomainName) else DomainName(qname)
        self.qtype = qtype
        self.qclass = qclass

    @classmethod
    def parse(cls, data: bytes, offset: int) -> tuple[DnsQuestion, int]:
        name, offset = DomainName.parse_from(data, offset)
        if offset + cls._SIZE > len(data):
            raise DnsPacketParseError(
                f"truncated question at offset {offset}: missing QTYPE/QCLASS, "
                f"need {cls._SIZE} octet(s), {len(data) - offset} remain",
                data=data,
                offset=offset,
            )
        qtype, qclass = struct.unpack_from(cls._FMT, data, offset)
        offset += cls._SIZE
        return cls(name, DnsQType.parse(qtype), DnsQClass.parse(qclass)), offset

    def __repr__(self) -> str:
        return f"<DnsQuestion:{self.name},{type_name_of(self.qtype)},{self.qclass}>"

    def __bytes__(self) -> bytes:
        return bytes(self.name) + struct.pack(self._FMT, int(self.qtype), int(self.qclass))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DnsQuestion):
            return NotImplemented
        return (
            self.name == other.name
            and int(self.qtype) == int(other.qtype)
            and int(self.qclass) == int(other.qclass)
        )

    def __hash__(self) -> int:
        return hash((self.name, int(self.qtype), int(self.qclass)))


#: Octets in the fixed part of an RR, after the name: TYPE/CLASS/TTL/RDLENGTH.
RECORD_HEADER_OCTETS = struct.calcsize(_RECORD_FMT)


def _wrap_rdata(rtype, blob: bytes) -> RData:
    """Hold raw RDATA octets as an ``RData``, decoded if a codec agrees to.

    Used by :meth:`DnsRecord.__init__` when a caller supplies plain ``bytes``.
    The codec is *offered* the octets, not assumed: if they do not decode -- an
    ``A`` record built with two octets, an ``SOA`` built with ``b""`` as a
    placeholder by the cache tests -- the opaque form is returned instead of
    raising. That keeps the constructor as permissive as it has always been
    while still making ``record.rdata`` a single, spec-shaped kind of object.

    Decoding is safe to attempt because :mod:`namespy.rdata` codecs never read
    outside the length they are given, and every one of them re-encodes to the
    octets it was handed, so a successful decode cannot alter the wire form.
    """
    codec = rdata_class_for(rtype)
    if codec is None:
        return RData(blob)
    try:
        return codec.parse_from(blob, 0, len(blob))
    except DnsPacketParseError:
        LOGGER.debug("%s octets do not decode; keeping them opaque", type_name_of(rtype))
        return RData(blob)


class DnsRecord:
    """One resource record (RFC 1035 section 4.1.3).

    ``rtype`` and ``rclass`` stay plain :class:`int` when the registry has no
    member for them, which is what lets an unknown type travel through the
    resolver intact instead of exploding on an enum attribute -- the failure
    mode that made a single ``HTTPS`` record (RFC 9460) fatal, because the code
    reached for ``rtype.value`` on what was already an int.

    :param rdata: an :class:`~namespy.rdata.RData`, or raw ``bytes``, which are
        wrapped in the opaque :class:`~namespy.rdata.RData`. No codec is *run*
        here: tests and the root-hints loader build records with ``rdata=b""``
        or a bare :class:`~namespy.names.DomainName`, and parsing those as an
        SOA or an address would reject input the caller knowingly supplied.
        :meth:`parse` is the strict path.

    Wrapping rather than storing raw bytes is what keeps ``record.rdata`` one
    kind of thing. Hand-built records used to hold ``bytes`` while parsed ones
    held an ``RData``, which forced ``isinstance`` checks in the resolver and
    made ``print(record.rdata)`` show a Python bytes literal on one path and
    RFC 3597 section 5 form on the other.
    """

    __slots__ = ("name", "rclass", "rdata", "rdlength", "rtype", "ttl")

    def __init__(
        self, name, rtype=DnsRType.A, rclass=DnsRClass.IN, ttl=0, rdlength=None, rdata=b""
    ):
        self.name = name if isinstance(name, DomainName) else DomainName(name)
        self.rtype = DnsRType.parse(rtype)
        self.rclass = DnsRClass.parse(rclass)
        self.ttl = clamp_ttl(ttl)
        if isinstance(rdata, str):
            rdata = rdata.encode("ascii", "surrogateescape")
        if isinstance(rdata, (bytes, bytearray, memoryview)):
            rdata = _wrap_rdata(rtype, bytes(rdata))
        self.rdata = rdata
        self.rdlength = len(bytes(rdata)) if rdlength is None else int(rdlength)

    @classmethod
    def parse(cls, data: bytes, offset: int) -> tuple[DnsRecord, int]:
        """Decode one RR, refusing what the wire format cannot express.

        Two structural checks matter most. RDLENGTH must leave room *inside*
        this message: the previous implementation sliced ``data[offset:][:rdlength]``,
        which yields a short slice instead of failing, so a record claiming more
        RDATA than remained was accepted and only an ``assert`` -- invisible
        under ``python -O`` -- stood between that and the next record. And an
        RR whose type has no codec must still parse, as opaque RDATA, per
        RFC 3597 section 3.

        Returns the record and the offset at which the next RR begins, which is
        the end of this one's RDATA even when a compression pointer made the
        name occupy fewer octets than it expands to.
        """
        name, cursor = DomainName.parse_from(data, offset)
        header = read_octets(data, cursor, RECORD_HEADER_OCTETS, what="RR header")
        rtype_raw, rclass_raw, ttl, rdlength = struct.unpack_from(_RECORD_FMT, header, 0)
        cursor += RECORD_HEADER_OCTETS

        end = cursor + rdlength
        if end > len(data):
            raise DnsPacketParseError(
                f"RDLENGTH {rdlength} at offset {cursor} overruns the message: "
                f"{len(data) - cursor} of {len(data)} octet(s) remain",
                data=data,
                offset=cursor,
            )

        codec = rdata_class_for(rtype_raw)
        if codec is None:
            # RFC 3597 section 3: an unknown type is opaque data, not an error.
            # It still gets an RData wrapper so presentation and re-encoding
            # behave the same as for any known type.
            LOGGER.debug("no RDATA codec for %s; keeping it opaque", type_name_of(rtype_raw))
            rdata: RData = RData(data[cursor:end])
        else:
            rdata = codec.parse_from(data, cursor, rdlength)

        record = cls(
            name,
            DnsRType.parse(rtype_raw),
            DnsRClass.parse(rclass_raw),
            ttl,
            rdlength,
            rdata,
        )
        return record, end

    def __repr__(self) -> str:
        return (
            f"<Record:{self.name},{type_name_of(self.rtype)},{self.rclass},{self.ttl},{self.rdata}>"
        )

    def __bytes__(self) -> bytes:
        """Serialise with RDLENGTH derived from the payload, never stored blindly.

        A record built by hand and one read off the wire must both serialise to
        something a receiver can parse, so the length field is recomputed from
        the encoded RDATA -- which :mod:`namespy.rdata` guarantees is
        pointer-free. Keeping a stale ``rdlength`` alongside edited RDATA would
        emit a message whose sections no longer align.
        """
        payload = bytes(self.rdata)
        return (
            bytes(self.name)
            + struct.pack(_RECORD_FMT, int(self.rtype), int(self.rclass), self.ttl, len(payload))
            + payload
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, DnsRecord):
            return NotImplemented
        return bytes(self) == bytes(other)

    def __hash__(self) -> int:
        return hash(bytes(self))


#: RR type of the EDNS(0) pseudo-record (RFC 6891 section 6.1.2).
OPT_RTYPE = 41


class DnsPacket:
    """A DNS message: header plus a question section and three RR sections.

    Section counts are authoritative on output and validated on input. The
    header's 4-bit RCODE holds 0-15; larger codes need EDNS(0) and are reachable
    through :attr:`extended_rcode` (RFC 6891 section 6.1.3).

    :param suffix: octets that followed the last RR when this message was
        parsed. Kept so a re-serialised copy can be byte-identical to what
        arrived; :meth:`parse` rejects trailing octets rather than setting it.
    """

    def __init__(
        self,
        ID=None,
        QR=DnsQR.QUERY,
        OPCODE=DnsOpCode.QUERY,
        AA=False,
        TC=False,
        RD=True,
        RA=False,
        Z=0,
        RCODE=DnsResponseCode.NO_ERROR,
        QDCOUNT=None,
        ANCOUNT=None,
        NSCOUNT=None,
        ARCOUNT=None,
        questions=None,
        answers=None,
        nameservers=None,
        additional_records=None,
        suffix=b"",
    ):
        if ID is None:
            # RFC 5452 section 5 treats the transaction ID as the resolver's
            # principal defence against off-path forgery, and section 6.1 asks
            # for it to be hard to guess. secrets.randbits draws from the
            # operating system's source of randomness; random.getrandbits is a
            # Mersenne Twister, whose state an attacker who observes enough IDs
            # can recover, which is precisely the property a spoofing-resilient
            # identifier must not have.
            ID = secrets.randbits(16)
        questions = [] if questions is None else questions
        answers = [] if answers is None else answers
        nameservers = [] if nameservers is None else nameservers
        additional_records = [] if additional_records is None else additional_records

        for label, value in (
            ("questions", questions),
            ("answers", answers),
            ("nameservers", nameservers),
            ("additional_records", additional_records),
        ):
            if not isinstance(value, list):
                raise TypeError(f"{label} must be a list, got {type(value).__name__}")

        self.ID = int(ID) & 0xFFFF
        self.QR = QR if isinstance(QR, DnsQR) else DnsQR(int(QR))
        self.OPCODE = OPCODE if isinstance(OPCODE, DnsOpCode) else DnsOpCode.parse(int(OPCODE))
        self.AA = bool(AA)
        self.TC = bool(TC)
        self.RD = bool(RD)
        self.RA = bool(RA)
        self.Z = int(Z) & 0b111
        self.RCODE = (
            RCODE if isinstance(RCODE, DnsResponseCode) else DnsResponseCode.parse(int(RCODE))
        )
        self.QDCOUNT = len(questions) if QDCOUNT is None else int(QDCOUNT)
        self.ANCOUNT = len(answers) if ANCOUNT is None else int(ANCOUNT)
        self.NSCOUNT = len(nameservers) if NSCOUNT is None else int(NSCOUNT)
        self.ARCOUNT = len(additional_records) if ARCOUNT is None else int(ARCOUNT)

        self.questions = questions
        self.answers = answers
        self.nameservers = nameservers
        self.additional_records = additional_records
        if suffix is not None and not isinstance(suffix, bytes):
            raise TypeError(f"suffix must be bytes, got {type(suffix).__name__}")
        self.suffix = b"" if suffix is None else suffix

    # ------------------------------------------------------------- accessors

    @property
    def all_answers(self):
        """Answer, authority and additional RRs, in section order."""
        return [*self.answers, *self.nameservers, *self.additional_records]

    def opt(self):
        """The EDNS(0) OPT record, or ``None`` (RFC 6891 section 6.1.2).

        OPT is a pseudo-record: it is never stored, its NAME is always the root,
        and at most one may appear in a message.
        """
        for record in self.additional_records:
            if int(record.rtype) == OPT_RTYPE:
                return record
        return None

    @property
    def extended_rcode(self) -> int:
        """The effective RCODE, folding in EDNS(0)'s upper eight bits.

        RFC 6891 section 6.1.3 lays OPT's TTL field out as EXTENDED-RCODE (8
        bits) | FLAGS (16 bits) | reserved (8 bits), and defines the effective
        value as ``(EXTENDED-RCODE << 4) | RCODE``. The shift is 4 and not 8
        because the header field is four bits wide; treating it as an octet
        yields a code sixteen times too large.
        """
        record = self.opt()
        if record is None:
            return int(self.RCODE)
        extended = (int(record.ttl) >> 24) & 0xFF
        if (header := int(self.RCODE)) > 0xF:
            # An in-memory packet can hold the effective code directly in
            # RCODE -- __bytes__ splits it across header and OPT on the way
            # out. Folding would mask the upper nibble away and report the
            # wrong code for an object that was never serialized.
            return header
        return (extended << 4) | (header & 0xF)

    @property
    def ad(self) -> bool:
        """Authentic Data (DO) -- OPT FLAGS bit 15 (RFC 6891 sections 6.1.3-6.1.4).

        OPT's TTL reads as EXTENDED-RCODE (bits 24-31) | VERSION (bits 16-23)
        | FLAGS (bits 0-15); DO is the flags field's own bit 15. (The section
        6.1.3 drawing shows octet 2 as ``DO|Z`` -- octet 2 *begins* with DO
        and Z fills the rest, so DO lands on TTL bit 15, which is also what
        ``dig +dnssec`` puts in its QUERY MESSAGE OPT hdrlen field.)
        """
        record = self.opt()
        return record is not None and bool(int(record.ttl) & (1 << 15))

    @property
    def cd(self) -> bool:
        """Checking Disabled -- OPT FLAGS bit 14 (RFC 6891 section 6.1.3, RFC 6955 section 4).

        Same FLAGS-in-low-16-bits layout as :attr:`ad`; CD is the flags
        field's bit 14.
        """
        record = self.opt()
        return record is not None and bool(int(record.ttl) & (1 << 14))

    @property
    def requestor_payload_size(self) -> int | None:
        """OPT's CLASS field: the sender's UDP payload size in octets."""
        record = self.opt()
        return None if record is None else int(record.rclass)

    @property
    def edns_version(self) -> int | None:
        """OPT's VERSION octet (RFC 6891 section 6.1.3), or ``None``.

        "the VERSION of each response SHOULD be the highest implementation
        level of the responder" — so this teaches a requestor what the far
        end supports on every response, not only alongside ``BADVERS``.
        """
        record = self.opt()
        return None if record is None else (int(record.ttl) >> 16) & 0xFF

    #: RFC 6891 section 6.2.3: "Values lower than 512 MUST be treated as
    #: equal to 512."
    EDNS_MINIMUM_PAYLOAD = 512

    def add_edns(self, payload_size: int = 1232, *, version: int = 0, flags: int = 0):
        """Attach an EDNS(0) OPT record, replacing any previous one.

        The pseudo-record (RFC 6891 section 6.1.2) is deliberately minimal:
        NAME the root, TYPE 41, CLASS the requestor's UDP payload size, and a
        TTL laid out per section 6.1.3 as EXTENDED-RCODE (bits 24-31) |
        VERSION (bits 16-23) | FLAGS (bits 0-15, DO = bit 15, section 6.1.4)
        -- with empty RDATA
        because no EDNS option is signalled. That is eleven octets on the
        wire, the whole price of lifting the 512-octet answer ceiling of RFC
        1035 section 4.2.1.

        *payload_size* is clamped up to 512 per section 6.2.3; the caller —
        not this method — owns the opposite duty, not to advertise more than
        its stack can actually reassemble.

        Returns ``self`` so a caller can write ``Query(...)
        .add_edns(1232)``; mutating rather than copying because the message
        is already being built in place by ``Query``'s caller.
        """
        payload_size = max(self.EDNS_MINIMUM_PAYLOAD, int(payload_size))
        ttl = ((int(version) & 0xFF) << 16) | (int(flags) & 0xFFFF)
        # Rebuild rather than mutate the list in place: the constructor may
        # have been handed a list the caller still holds.
        self.additional_records = [
            record for record in self.additional_records if int(record.rtype) != OPT_RTYPE
        ]
        self.additional_records.append(DnsRecord(DomainName("."), OPT_RTYPE, payload_size, ttl))
        self.ARCOUNT = len(self.additional_records)
        return self

    def remove_edns(self) -> bool:
        """Drop any OPT record; ``True`` when one was present.

        This is the mechanical half of the RFC 6891 section 6.2.2 fallback:
        once a requestor "detects that the remote end does not support
        EDNS(0), it MAY issue queries without an OPT record". Section 7 makes
        the absence meaningful in the other direction too — a message with
        no OPT tells the responder "the requestor does not implement any
        part of this specification", which is exactly what a re-ask to a
        server that just rejected EDNS needs to say.
        """
        kept = [record for record in self.additional_records if int(record.rtype) != OPT_RTYPE]
        removed = len(kept) != len(self.additional_records)
        if removed:
            self.additional_records = kept
            self.ARCOUNT = len(kept)
        return removed

    # ---------------------------------------------------------------- output

    def __repr__(self) -> str:
        return "<DnsPacket:{:#06x} {} q={} a={} ns={} ar={}>".format(
            self.ID,
            "response" if DnsQR.RESPONSE == self.QR else "query",
            len(self.questions),
            len(self.answers),
            len(self.nameservers),
            len(self.additional_records),
        )

    def __hex__(self) -> str:
        """Wire-form octets as one lowercase hex string, without ``0x``.

        :func:`hex` only applies to :class:`int`; this is its counterpart for
        the serialized message, for logs and capture comparison.
        """
        return bytes(self).hex()

    def _header_bytes(self) -> bytes:
        rcode = int(self.RCODE)
        if rcode > 0xF and self.opt() is None:
            raise ValueError(
                f"RCODE {rcode} does not fit the 4-bit header field; add an "
                f"EDNS(0) OPT record so the upper bits have somewhere to go "
                f"(RFC 6891 section 6.1.3)"
            )
        flags1 = (
            (0x80 if DnsQR.RESPONSE == self.QR else 0)
            | (int(self.OPCODE) & 0xF) << 3
            | (0x04 if self.AA else 0)
            | (0x02 if self.TC else 0)
            | (0x01 if self.RD else 0)
        )
        flags2 = (0x80 if self.RA else 0) | (self.Z & 0b111) << 4 | (rcode & 0xF)
        return struct.pack(
            _HEADER_FMT,
            self.ID,
            flags1,
            flags2,
            self.QDCOUNT & 0xFFFF,
            self.ANCOUNT & 0xFFFF,
            self.NSCOUNT & 0xFFFF,
            self.ARCOUNT & 0xFFFF,
        )

    def __bytes__(self) -> bytes:
        out = bytearray(self._header_bytes())
        for question in self.questions:
            out += bytes(question)
        for section in (self.answers, self.nameservers, self.additional_records):
            for record in section:
                out += bytes(record)
        out += self.suffix
        return bytes(out)

    # ----------------------------------------------------------------- input

    @classmethod
    def parse(cls, data, offset: int = 0, *, strict: bool = True) -> tuple[DnsPacket, int]:
        """Decode a message; returns ``(packet, octets_consumed)``.

        :param strict: when true (the default) each section must hold exactly
            the count the header promises and the message must end there. Set it
            false to accept a response cut short by the ``TC`` bit or by a
            datagram lost in transit -- the only way to recover the header and
            question of an answer too large for one packet, which is the first
            step of the TCP retry RFC 7766 section 6 calls for.

        Raises :class:`~namespy.wire.DnsPacketParseError` for anything a receiver
        should drop rather than interpret (RFC 5625 section 6.3).
        """
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("DnsPacket.parse expects a bytes-like object")
        buf = bytes(data)
        if offset < 0 or offset > len(buf):
            raise DnsPacketParseError("offset out of range", data=buf, offset=offset)
        if len(buf) - offset < HEADER_OCTETS:
            raise DnsPacketParseError(
                f"truncated DNS message: need at least {HEADER_OCTETS} octet(s) "
                f"of header, got {len(buf) - offset} from offset {offset}",
                data=buf,
                offset=offset,
            )
        return cls._parse_impl(buf, offset, strict=strict)

    @classmethod
    def _parse_impl(cls, data: bytes, offset: int, *, strict: bool):
        ID, flags1, flags2, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT = struct.unpack_from(
            _HEADER_FMT, data, offset
        )
        offset += HEADER_OCTETS

        QR = DnsQR((flags1 & 0x80) >> 7)
        OPCODE = DnsOpCode.parse((flags1 & 0x78) >> 3)
        AA, TC, RD = bool(flags1 & 0x04), bool(flags1 & 0x02), bool(flags1 & 0x01)
        RA, Z = bool(flags2 & 0x80), (flags2 & 0x70) >> 4
        RCODE = DnsResponseCode.parse(flags2 & 0x0F)

        # Sections fill in order; on a TC=1 message the last one may legitimately
        # be cut off mid-record, so what did parse is kept rather than thrown
        # away (RFC 1035 section 4.1.1 makes truncation a normal condition, not
        # corruption).
        #
        # QDCOUNT is *not* capped at one here, even though multi-question messages
        # are what every current server refuses. Decoding is not accepting: this is
        # an inspection library, so it has to be able to read a message it would
        # reject, and a server that could not parse the FORMERR reply it sends for a
        # two-question query would be contradicting itself. The refusal belongs to
        # the policy layer and lives in namespy.server, per RFC 8906 section 5.2.
        # The loop below is bounded by the message itself -- each question consumes
        # at least three octets -- so a hostile count cannot spin.

        # A TC=1 message is a legitimately partial answer, not a corrupt one
        # (RFC 1035 section 4.1.1), so in lenient mode the last section may stop
        # mid-record and what did parse is kept -- the header and question are
        # enough to drive the TCP retry RFC 7766 section 6 calls for.
        tolerated = (not strict) and TC

        # Sections are read one after another, each to its own count. Once one
        # fails, the rest cannot be located, so they stay empty and the octets
        # land in `suffix`.
        sections: list[list] = []
        failure: DnsPacketParseError | None = None
        for parser, count in (
            (DnsQuestion, QDCOUNT),
            (DnsRecord, ANCOUNT),
            (DnsRecord, NSCOUNT),
            (DnsRecord, ARCOUNT),
        ):
            if failure is not None:
                sections.append([])
                continue
            items, offset, failure = cls._parse_section(parser, data, offset, count)
            if failure is not None and not tolerated:
                raise failure
            sections.append(items)

        questions, answers, nameservers, additional = sections

        if strict and offset != len(data):
            raise DnsPacketParseError(
                f"{len(data) - offset} unexpected octet(s) after the last RR "
                f"(RFC 1035 section 4.1)",
                data=data,
                offset=offset,
            )

        packet_cls = Query if DnsQR.QUERY == QR else Response
        return (
            packet_cls(
                ID,
                QR,
                OPCODE,
                AA,
                TC,
                RD,
                RA,
                Z,
                RCODE,
                len(questions),
                len(answers),
                len(nameservers),
                len(additional),
                questions,
                answers,
                nameservers,
                additional,
                suffix=data[offset:],
            ),
            offset,
        )

    @staticmethod
    def _parse_section(parser, data: bytes, offset: int, count: int):
        """Read up to *count* entries; returns ``(items, offset, failure)``.

        *failure* is the :class:`~namespy.wire.DnsPacketParseError` that stopped
        the section, or ``None``. Returning it instead of raising lets the caller
        distinguish "this message is corrupt, drop it" from "this answer is
        truncated, keep the part that parsed" without a try/except that would
        also swallow a failure it had already decided to accept.

        Filling sections from "whatever is left", as the original loop did, meant
        a message whose header promised fewer RRs than it carried was accepted
        silently, and one whose sections ran short left octets nobody owned. Each
        section is read to its own count.
        """
        items: list = []
        try:
            for _ in range(count):
                item, offset = parser.parse(data, offset)
                items.append(item)
        except DnsPacketParseError as exc:
            return items, offset, exc
        return items, offset, None


class Query(DnsPacket):
    """A query message -- ``QR`` clear (RFC 1035 section 4.1.1)."""


class Response(DnsPacket):
    """A response message -- ``QR`` set (RFC 1035 section 4.1.1)."""
