"""RDATA codecs: one class per wire format we understand, plus an opaque fallback.

Every class here obeys three rules, and each rule exists because the previous
revision of this module broke without it.

1. **Serialization is canonical (compression-free).** :meth:`RData.to_wire`
   always emits full labels, never a compression pointer, so the result is a
   self-contained octet string that is valid outside the datagram it came from.
   This matters concretely: :mod:`aiodns.cache.sqlite` stores ``bytes(record)``
   and reads it back with ``DnsRecord.parse(payload, 0)``, where the original
   name offsets no longer exist. Returning the pointer octets would silently
   resurrect a *different* name -- or none -- on the next load. The octets as
   received stay available as :attr:`RData.wire` for hex dumps.
2. **Reads are bounded by RDLENGTH.** A parser is handed the message, the start
   offset, and the declared RDATA length, and may not consume past it. RFC 9267
   section 5 names this exact class of bug: an RDATA field read that runs past
   its declared length walks into the next record.
3. **Malformed input raises; it never half-parses.** All failures are
   :class:`~aiodns.wire.DnsPacketParseError`, never an :keyword:`assert`.

Unknown types are *not* errors. RFC 3597 section 3 requires a server to handle
unknown RR types opaquely, and section 5 gives the master-file presentation
``\\# <rdlength> <hex>`` mirrored here by :func:`generic_presentation`. An RR
whose type is absent from :class:`~aiodns.enums.DnsRType` therefore lands in the
base :class:`RData` as a blob instead of raising -- the bug that previously made
a single ``HTTPS`` record (type 65, RFC 9460) fatal to the whole listener.

.. rubric:: References

* RFC 1035 section 3.3 (RDATA formats), 3.3.9 (MX), 3.3.13 (SOA), 3.3.14 (TXT)
* RFC 1982 / RFC 1035 section 3.3.13 (SOA serial number space arithmetic)
* RFC 2308 section 5 (SOA MINIMUM is the negative-cache TTL)
* RFC 2782 section 3 (SRV), RFC 7505 (null MX)
* RFC 3597 sections 3, 5 (opaque unknown types, ``\\#`` presentation)
* RFC 9267 section 5 (validate RDLENGTH; do not read past it)
"""

from __future__ import annotations

import ipaddress
import struct
from typing import ClassVar

from .enums import DnsRType
from .names import DomainName
from .wire import DnsPacketParseError, read_octets

__all__ = [
    "RData",
    "RData_A",
    "RData_AAAA",
    "RData_CNAME",
    "RData_DNAME",
    "RData_MX",
    "RData_NS",
    "RData_PTR",
    "RData_SOA",
    "RData_SRV",
    "RData_SingleName",
    "RData_TXT",
    "all_rdata_classes",
    "generic_presentation",
    "quote_charstring",
    "rdata_class_for",
    "split_charstrings",
    "type_name_of",
]

#: Registered by :meth:`RData.__init_subclass__`; keyed on wire type number.
_REGISTRY: dict[int, type[RData]] = {}

#: RFC 1035 section 3.3.14: a <character-string> is length-prefixed by one octet.
MAX_CHARSTRING_OCTETS = 255


def all_rdata_classes() -> dict[int, type[RData]]:
    """Every registered codec, keyed by RR type number (a copy)."""
    return dict(_REGISTRY)


def rdata_class_for(rtype: int) -> type[RData] | None:
    """The codec registered for ``rtype``, or ``None`` if it stays opaque."""
    return _REGISTRY.get(int(rtype))


def type_name_of(rtype: DnsRType | int | None) -> str:
    """Mnemonic for ``rtype``; RFC 3597 section 5 ``TYPE<n>`` when unknown.

    ``DnsRType`` deliberately does not guess at types it has never heard of, so
    an unregistered type still needs a stable, unambiguous label for logs.
    """
    if rtype is None:
        return "RDATA"
    try:
        return DnsRType(int(rtype)).name
    except ValueError:
        return f"TYPE{int(rtype)}"


def generic_presentation(blob: bytes) -> str:
    r"""RFC 3597 section 5 representation: ``\# <rdlength> <hex>``.

    The backslash is what tells a master file this is unknown-type data rather
    than text that happens to look like hex; callers that only want the payload
    can read :attr:`RData.blob`.

    An empty RDATA prints as ``\# 0`` with no trailing space -- RFC 3597's
    grammar allows the hex-string to be absent exactly when the length is zero,
    and a dangling space is what distinguishes considered output from a format
    string that never met an empty case.
    """
    if not blob:
        return r"\# 0"
    return rf"\# {len(blob)} {blob.hex()}"


class RData:
    """Opaque RDATA -- the fallback for every type without a dedicated codec.

    :param blob: the RDATA octets, either as received or synthesised.
    :param wire: the octets exactly as they appeared in the datagram, when they
        differ from *blob*. Only a parsed record has this, and only when the
        original used compression; it exists so a hex dump can still show what
        really went over the socket.
    """

    #: RR type this codec handles; ``None`` leaves the class unregistered.
    RType: DnsRType | None = None

    def __init_subclass__(cls, **kwargs) -> None:
        super().__init_subclass__(**kwargs)
        rtype = cls.__dict__.get("RType")
        if rtype is not None:
            _REGISTRY[int(rtype)] = cls

    def __init__(self, blob: bytes = b"", *, wire: bytes | None = None) -> None:
        self.blob = bytes(blob)
        self.wire = self.blob if wire is None else bytes(wire)

    # ------------------------------------------------------------------ parse

    @classmethod
    def parse_from(cls, buffer: bytes, offset: int = 0, length: int | None = None) -> RData:
        """Decode RDATA from ``buffer`` starting at ``offset``.

        *length* is the record's declared RDLENGTH. ``None`` means "the rest of
        the buffer", which is only sensible for a standalone slice; callers
        parsing a real message always pass it.
        """
        blob = cls.rdata_octets(buffer, offset, length)
        return cls(blob, wire=blob)

    @classmethod
    def rdata_octets(cls, buffer: bytes, offset: int, length: int | None) -> bytes:
        """The ``length`` octets of RDATA, refusing to read past the message.

        A short slice used to be forgiven by slicing twice
        (``data[offset:][:length]``), which produced a silently truncated RDATA
        that then tripped a length assertion two frames away.
        """
        count = len(buffer) - offset if length is None else int(length)
        try:
            return read_octets(buffer, offset, count, what=f"{cls._type_label()} RDATA")
        except DnsPacketParseError as exc:
            raise DnsPacketParseError(str(exc), data=buffer, offset=offset) from None

    @classmethod
    def _require_exact(cls, blob: bytes, expected: int) -> None:
        """Reject an RDATA blob whose length is not ``expected`` octets."""
        if len(blob) != expected:
            raise DnsPacketParseError(
                f"{cls._type_label()} RDATA is {len(blob)} octet(s), must be exactly {expected}",
                data=blob,
                offset=0,
            )

    @classmethod
    def _type_label(cls) -> str:
        """``"SOA"`` when registered, else RFC 3597 section 5 ``TYPE65``."""
        return type_name_of(cls.RType)

    # ----------------------------------------------------------------- output

    def to_wire(self) -> bytes:
        """Canonical RDATA, safe to store or re-parse anywhere."""
        return self.blob

    def to_presentation(self) -> str:
        """Master-file form; unknown types use the RFC 3597 section 5 escape."""
        return generic_presentation(self.blob)

    @property
    def type_name(self) -> str:
        """The RR type mnemonic for this codec, e.g. ``"A"`` or ``"TYPE65"``."""
        return type_name_of(self.RType)

    def __bytes__(self) -> bytes:
        return self.to_wire()

    def __repr__(self) -> str:
        return f"<{self.type_name} {self.to_presentation()}>"

    def __str__(self) -> str:
        return self.to_presentation()

    def __eq__(self, other: object) -> bool:
        if isinstance(other, RData):
            return self.to_wire() == other.to_wire()
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.to_wire())


# --------------------------------------------------------------- addresses


class RData_A(RData):
    """``A`` RDATA -- four octets of IPv4 address (RFC 1035 section 3.4.1)."""

    RType = DnsRType.A

    #: The :mod:`ipaddress` class used to validate and render the payload.
    #: Annotated explicitly because the subclass narrows it: left to inference,
    #: the base reads as ``type[IPv4Address]`` and :class:`RData_AAAA` assigning
    #: ``IPv6Address`` would be an incompatible redefinition.
    _ADDRESS_TYPE: ClassVar[type[ipaddress.IPv4Address] | type[ipaddress.IPv6Address]] = (
        ipaddress.IPv4Address
    )

    #: RFC 1035 section 3.4.1 / RFC 3596 section 3: a fixed RDLENGTH.
    _WIRE_OCTETS: ClassVar[int] = 4

    def __init__(self, ip, *, wire: bytes | None = None) -> None:
        if isinstance(ip, (bytes, bytearray, memoryview)):
            ip = self._parse_packed(bytes(ip))
        elif not isinstance(ip, self._ADDRESS_TYPE):
            ip = self._ADDRESS_TYPE(ip)
        self.ip = ip
        super().__init__(ip.packed, wire=wire)

    @classmethod
    def _parse_packed(cls, blob: bytes):
        """Build an address from exactly the right number of octets.

        The length check is not pedantry: RDLENGTH for ``A`` is 4 and for
        ``AAAA`` is 16, so a datagram claiming otherwise is malformed. Feeding
        a short slice straight to :class:`ipaddress.IPv4Address` raised a bare
        ``ValueError`` from deep inside the standard library instead.
        """
        cls._require_exact(blob, cls._WIRE_OCTETS)
        try:
            return cls._ADDRESS_TYPE(blob)
        except ValueError as exc:
            raise DnsPacketParseError(
                f"{cls._type_label()} RDATA is not a valid address: {exc}",
                data=blob,
                offset=0,
            ) from None

    @classmethod
    def parse_from(cls, buffer: bytes, offset: int = 0, length: int | None = None):
        blob = cls.rdata_octets(buffer, offset, length)
        return cls(cls._parse_packed(blob), wire=blob)

    def to_presentation(self) -> str:
        return self.ip.compressed

    def __eq__(self, other: object) -> bool:
        if isinstance(other, RData_A):
            return self.ip == other.ip
        if isinstance(other, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            return self.ip == other
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self.type_name, self.ip))


class RData_AAAA(RData_A):
    """``AAAA`` RDATA -- sixteen octets of IPv6 address (RFC 3596 section 3)."""

    RType = DnsRType.AAAA
    _ADDRESS_TYPE: ClassVar[type[ipaddress.IPv6Address]] = ipaddress.IPv6Address
    _WIRE_OCTETS: ClassVar[int] = 16


# ------------------------------------------------- names inside bounded RDATA


def _read_name(buffer: bytes, offset: int, rdata_end: int, *, where: str) -> tuple[DomainName, int]:
    """Read one ``<domain-name>`` that must fit inside the RDATA window.

    Compression pointers may target earlier octets *anywhere* in the message --
    that is their purpose -- but the name's own storage must end before the
    record's RDATA does. A name that overruns its RDLENGTH has walked into the
    next record, which is exactly what RFC 9267 section 5 tells a receiver to
    reject rather than tolerate.

    Returns the name and the offset at which the enclosing record continues.
    """
    if offset > rdata_end:
        raise DnsPacketParseError(
            f"{where} starts past the end of its RDATA at offset {offset}",
            data=buffer,
            offset=offset,
        )
    name, end = DomainName.parse_from(buffer, offset)
    if end > rdata_end:
        raise DnsPacketParseError(
            f"{where} spans {end - offset} octet(s) but only "
            f"{rdata_end - offset} remain in its RDATA (RFC 9267 section 5)",
            data=buffer,
            offset=offset,
        )
    return name, end


# ------------------------------------------------------- single <domain-name>


class RData_SingleName(DomainName):
    """RDATA that is exactly one ``<domain-name>`` -- the NS/CNAME/PTR/DNAME shape.

    Subclasses :class:`~aiodns.names.DomainName` rather than :class:`RData`, so an
    ``RData_NS`` *is* a domain name and compares and hashes as one; the concrete
    codecs below mix this in with :class:`RData`. That is what lets resolver code
    write ``ns_targets.append(r.rdata)`` and treat the result as a name, and what
    keeps ``DomainName("ns1.example.com") == RData_NS("ns1.example.com")`` true.

    :meth:`to_wire` re-encodes from the expanded name, so a name that arrived via
    a compression pointer serialises as full labels. Returning the pointer octets
    would make stored RDATA depend on offsets from a datagram that no longer
    exists.
    """

    RType: DnsRType | None = None

    def __init__(
        self,
        name,
        buffer: bytes | None = None,
        offset: int | None = None,
        *,
        wire: bytes | None = None,
    ) -> None:
        DomainName.__init__(self, name, buffer, offset)
        self.blob = self.to_wire()
        self.wire = self.blob if wire is None else bytes(wire)

    @property
    def type_name(self) -> str:
        return type_name_of(self.RType)

    @classmethod
    def _type_label(cls) -> str:
        return type_name_of(cls.RType)

    @classmethod
    def rdata_octets(cls, buffer: bytes, offset: int, length: int | None) -> bytes:
        """RData-compatible bounded read, so DnsRecord can treat codecs alike."""
        count = len(buffer) - offset if length is None else int(length)
        try:
            return read_octets(buffer, offset, count, what=f"{cls._type_label()} RDATA")
        except DnsPacketParseError as exc:
            raise DnsPacketParseError(str(exc), data=buffer, offset=offset) from None

    def to_wire(self) -> bytes:
        """The name in uncompressed wire form -- which *is* the whole RDATA."""
        return bytes(DomainName(self.name))

    def to_presentation(self) -> str:
        return str(self.name)

    @classmethod
    def parse_from(cls, buffer: bytes, offset: int = 0, length: int | None = None):
        """Decode one name, keeping the octets it occupied for provenance.

        ``DomainName.parse_from`` reports the offset at which the *enclosing*
        record continues, which after a compression pointer is just past the
        pointer rather than past the expanded labels. The field's own extent is
        therefore from ``offset`` to that returned value -- using the parsed
        name's ``offset`` attribute here would point at the pointer's target.
        """
        name, end = DomainName.parse_from(buffer, offset)
        original = buffer[offset:end]
        if length is not None and len(original) > int(length):
            raise DnsPacketParseError(
                f"{cls._type_label()} name spans {len(original)} octet(s), "
                f"beyond the {length}-octet RDATA (RFC 9267 section 5)",
                data=buffer,
                offset=offset,
            )
        return cls(name.name, buffer, offset, wire=original)

    def __bytes__(self) -> bytes:
        return self.to_wire()

    def __repr__(self) -> str:
        return f"<{self.type_name} {self.name}>"


class RData_NS(RData_SingleName, RData):
    """``NS`` RDATA -- one name server (RFC 1035 section 3.3.11)."""

    RType = DnsRType.NS


class RData_CNAME(RData_SingleName, RData):
    """``CNAME`` RDATA -- the canonical name of an alias (RFC 1035 section 3.3.1)."""

    RType = DnsRType.CNAME


class RData_PTR(RData_SingleName, RData):
    """``PTR`` RDATA -- the domain name a pointer refers to (RFC 1035 section 3.3.12)."""

    RType = DnsRType.PTR


class RData_DNAME(RData_SingleName, RData):
    """``DNAME`` RDATA -- a subtree redirection target (RFC 6672 section 4)."""

    RType = DnsRType.DNAME


# ------------------------------------------------------------------- SOA


class RData_SOA(RData):
    """``SOA`` RDATA (RFC 1035 section 3.3.13, as extended by RFC 2308 section 5).

    ``minimum`` is the seventh field. RFC 2308 repurposed it from "minimum TTL"
    to the negative-caching TTL, and section 5.1 requires the authoritative
    server to set a negative response's TTL to ``min(SOA.MINIMUM, SOA.TTL)`` --
    which cannot be computed without reading it. It was absent before, so
    :meth:`aiodns.resolver.Resolver._negative_ttl_seconds` could only fall back
    to the RR's own TTL and therefore over-cached negative answers.

    Serial comparison is RFC 1982 unsigned 32-bit wrap-around arithmetic, per
    RFC 1035 section 3.3.13 ("comparison is done using serial number space
    arithmetic"); use :meth:`serial_ahead` rather than ``<``.
    """

    RType = DnsRType.SOA

    #: The five 32-bit timers following MNAME and RNAME.
    _TIMERS_FMT = "!IIIII"

    def __init__(
        self,
        mname,
        rname,
        serial: int = 0,
        refresh: int = 0,
        retry: int = 0,
        expire: int = 0,
        minimum: int = 0,
        *,
        wire: bytes | None = None,
    ) -> None:
        self.mname = mname if isinstance(mname, DomainName) else DomainName(mname)
        self.rname = rname if isinstance(rname, DomainName) else DomainName(rname)
        self.serial = int(serial) & 0xFFFFFFFF
        self.refresh = int(refresh) & 0xFFFFFFFF
        self.retry = int(retry) & 0xFFFFFFFF
        self.expire = int(expire) & 0xFFFFFFFF
        self.minimum = int(minimum) & 0xFFFFFFFF
        super().__init__(self.to_wire(), wire=wire)

    @classmethod
    def parse_from(cls, buffer: bytes, offset: int = 0, length: int | None = None):
        blob = cls.rdata_octets(buffer, offset, length)
        end = offset + len(blob)

        mname, cursor = _read_name(buffer, offset, end, where="SOA MNAME")
        rname, cursor = _read_name(buffer, cursor, end, where="SOA RNAME")

        remaining = end - cursor
        if remaining != struct.calcsize(cls._TIMERS_FMT):
            raise DnsPacketParseError(
                f"SOA RDATA has {remaining} octet(s) after RNAME, expected "
                f"{struct.calcsize(cls._TIMERS_FMT)} for SERIAL/REFRESH/RETRY/"
                f"EXPIRE/MINIMUM",
                data=buffer,
                offset=cursor,
            )
        serial, refresh, retry, expire, minimum = struct.unpack_from(
            cls._TIMERS_FMT, buffer, cursor
        )
        return cls(mname, rname, serial, refresh, retry, expire, minimum, wire=blob)

    def to_wire(self) -> bytes:
        """Fully-expanded RDATA -- a stored SOA never carries a pointer."""
        return (
            bytes(self.mname)
            + bytes(self.rname)
            + struct.pack(
                self._TIMERS_FMT,
                self.serial,
                self.refresh,
                self.retry,
                self.expire,
                self.minimum,
            )
        )

    @staticmethod
    def serial_ahead(a: int, b: int) -> bool:
        """Whether serial ``a`` is *after* ``b`` in RFC 1982 serial number space.

        A naive ``a > b`` breaks the moment a zone crosses 2**31: a zone whose
        serial rolled to ``0x80000001`` would compare behind a stale
        ``0x7FFFFFFF``, and a secondary would refuse the update forever. RFC 1035
        section 3.3.13 mandates this arithmetic for SOA serials.
        """
        diff = (int(a) - int(b)) & 0xFFFFFFFF
        return 0 < diff < 0x80000000

    def to_presentation(self) -> str:
        return " ".join(
            str(value)
            for value in (
                self.mname,
                self.rname,
                self.serial,
                self.refresh,
                self.retry,
                self.expire,
                self.minimum,
            )
        )


# --------------------------------------------------- character-string records


class RData_TXT(RData):
    """``TXT`` RDATA -- one or more ``<character-string>``s (RFC 1035 section 3.3.14).

    Each string is a length octet plus up to 255 octets, so a longer value *must*
    be split across several strings: RFC 1035 section 3.3.14 says a string over
    255 characters "may be represented by multiple <character-string>s".
    :func:`split_charstrings` does that and :attr:`text` re-joins them, which is
    what a reader of SPF/DKIM/DMARC values wants. The split stays visible because
    re-joining and then re-splitting at a different boundary is not a no-op on the
    wire.
    """

    RType = DnsRType.TXT

    def __init__(self, strings=(), *, wire: bytes | None = None) -> None:
        if isinstance(strings, (bytes, str)):
            strings = [strings]
        self.strings: list[bytes] = [
            value if isinstance(value, bytes) else str(value).encode() for value in strings
        ]
        for value in self.strings:
            if len(value) > MAX_CHARSTRING_OCTETS:
                raise ValueError(
                    f"TXT character-string of {len(value)} octets exceeds "
                    f"{MAX_CHARSTRING_OCTETS} (RFC 1035 section 3.3.14)"
                )
        super().__init__(self.to_wire(), wire=wire)

    @property
    def text(self) -> str:
        """All character-strings concatenated, decoded as UTF-8 where possible."""
        joined = b"".join(self.strings)
        try:
            return joined.decode()
        except UnicodeDecodeError:
            return joined.decode("latin-1")

    @classmethod
    def from_text(cls, text: str, *, encoding: str = "utf-8") -> RData_TXT:
        """Build a TXT record from one logical string, chunking at 255 octets."""
        return cls(split_charstrings(text.encode(encoding)))

    @classmethod
    def parse_from(cls, buffer: bytes, offset: int = 0, length: int | None = None):
        blob = cls.rdata_octets(buffer, offset, length)
        strings: list[bytes] = []
        cursor = 0
        while cursor < len(blob):
            size = blob[cursor]
            cursor += 1
            if cursor + size > len(blob):
                raise DnsPacketParseError(
                    f"TXT character-string claims {size} octet(s) at offset "
                    f"{cursor} but only {len(blob) - cursor} remain inside "
                    f"RDLENGTH {len(blob)} (RFC 9267 section 5)",
                    data=blob,
                    offset=offset + cursor,
                )
            strings.append(blob[cursor : cursor + size])
            cursor += size
        return cls(strings, wire=blob)

    def to_wire(self) -> bytes:
        out = bytearray()
        for value in self.strings:
            out.append(len(value))
            out.extend(value)
        return bytes(out)

    def to_presentation(self) -> str:
        return " ".join(f'"{quote_charstring(value)}"' for value in self.strings)


def split_charstrings(payload: bytes, limit: int = MAX_CHARSTRING_OCTETS) -> list[bytes]:
    """Split *payload* into character-strings of at most *limit* octets."""
    if not payload:
        return [b""]
    return [payload[i : i + limit] for i in range(0, len(payload), limit)]


def quote_charstring(value: bytes) -> str:
    r"""Render one character-string as a quoted, escaped master-file string.

    Non-printable octets become ``\DDD``: RFC 1035 section 5.1 permits the
    escape, and it is the only lossless option once RFC 2181 section 11 allows
    arbitrary octets.
    """
    out: list[str] = []
    for octet in value:
        char = chr(octet)
        if char in {'"', "\\"}:
            out.append(f"\\{char}")
        elif 0x20 <= octet < 0x7F:
            out.append(char)
        else:
            out.append(f"\\{octet:03d}")
    return "".join(out)


# ---------------------------------------------------- preference + name types


class RData_MX(RData_SingleName, RData):
    """``MX`` RDATA -- a 16-bit preference then a mail exchanger (RFC 1035 section 3.3.9).

    Preference 0 pointing at the root is the RFC 7505 "null MX" assertion that
    the domain neither sends nor accepts mail; :attr:`is_null_mx` recognises it so
    a caller does not try to route to the root zone. RFC 7505 section 4 also
    requires such a record to be the only MX in its RRset, which is a property of
    the RRset rather than of this record.
    """

    RType = DnsRType.MX
    _FMT = "!H"

    def __init__(self, name, preference: int = 10, *, wire: bytes | None = None) -> None:
        self.preference = int(preference) & 0xFFFF
        super().__init__(name, wire=wire)

    def to_wire(self) -> bytes:
        return struct.pack(self._FMT, self.preference) + bytes(DomainName(self.name))

    @classmethod
    def parse_from(cls, buffer: bytes, offset: int = 0, length: int | None = None):
        blob = cls.rdata_octets(buffer, offset, length)
        end = offset + len(blob)
        if len(blob) < struct.calcsize(cls._FMT):
            raise DnsPacketParseError(
                f"MX RDATA is {len(blob)} octet(s), too short for a 16-bit preference",
                data=blob,
                offset=offset,
            )
        (preference,) = struct.unpack_from(cls._FMT, buffer, offset)
        exchange, cursor = _read_name(buffer, offset + 2, end, where="MX EXCHANGE")
        if cursor != end:
            raise DnsPacketParseError(
                f"MX RDATA has {end - cursor} trailing octet(s) after EXCHANGE",
                data=blob,
                offset=cursor,
            )
        return cls(exchange, preference, wire=blob)

    @property
    def is_null_mx(self) -> bool:
        """RFC 7505: preference 0 pointing at the root means "no mail here"."""
        return self.preference == 0 and not self.labels()

    def to_presentation(self) -> str:
        return f"{self.preference} {self.name}"


class RData_SRV(RData):
    """``SRV`` RDATA -- priority, weight, port, target (RFC 2782 section 3).

    A port of 0 means the service is explicitly *not* offered (RFC 2782 section
    3), which is not the same as the record being absent: it is how an operator
    says "and do not fall back to any lower-priority target either".
    """

    RType = DnsRType.SRV
    _FMT = "!HHH"

    def __init__(
        self,
        target,
        priority: int = 0,
        weight: int = 0,
        port: int = 0,
        *,
        wire: bytes | None = None,
    ) -> None:
        self.target = target if isinstance(target, DomainName) else DomainName(target)
        self.priority = int(priority) & 0xFFFF
        self.weight = int(weight) & 0xFFFF
        self.port = int(port) & 0xFFFF
        super().__init__(self.to_wire(), wire=wire)

    @classmethod
    def parse_from(cls, buffer: bytes, offset: int = 0, length: int | None = None):
        blob = cls.rdata_octets(buffer, offset, length)
        end = offset + len(blob)
        header = struct.calcsize(cls._FMT)
        if len(blob) < header:
            raise DnsPacketParseError(
                f"SRV RDATA is {len(blob)} octet(s), too short for priority/weight/port",
                data=blob,
                offset=offset,
            )
        priority, weight, port = struct.unpack_from(cls._FMT, buffer, offset)
        target, cursor = _read_name(buffer, offset + header, end, where="SRV target")
        if cursor != end:
            raise DnsPacketParseError(
                f"SRV RDATA has {end - cursor} trailing octet(s) after the target",
                data=blob,
                offset=cursor,
            )
        return cls(target, priority, weight, port, wire=blob)

    def to_wire(self) -> bytes:
        return struct.pack(self._FMT, self.priority, self.weight, self.port) + bytes(self.target)

    def to_presentation(self) -> str:
        return f"{self.priority} {self.weight} {self.port} {self.target}"
