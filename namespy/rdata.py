"""RDATA codecs: one class per wire format we understand, plus an opaque fallback.

Every class here obeys three rules, and each rule exists because the previous
revision of this module broke without it.

1. **Serialization is canonical (compression-free).** :meth:`RData.to_wire`
   always emits full labels, never a compression pointer, so the result is a
   self-contained octet string that is valid outside the datagram it came from.
   This matters concretely: :mod:`namespy.cache.sqlite` stores ``bytes(record)``
   and reads it back with ``DnsRecord.parse(payload, 0)``, where the original
   name offsets no longer exist. Returning the pointer octets would silently
   resurrect a *different* name -- or none -- on the next load. The octets as
   received stay available as :attr:`RData.wire` for hex dumps.
2. **Reads are bounded by RDLENGTH.** A parser is handed the message, the start
   offset, and the declared RDATA length, and may not consume past it. RFC 9267
   section 5 names this exact class of bug: an RDATA field read that runs past
   its declared length walks into the next record.
3. **Malformed input raises; it never half-parses.** All failures are
   :class:`~namespy.wire.DnsPacketParseError`, never an :keyword:`assert`.

Unknown types are *not* errors. RFC 3597 section 3 requires a server to handle
unknown RR types opaquely, and section 5 gives the master-file presentation
``\\# <rdlength> <hex>`` mirrored here by :func:`generic_presentation`. An RR
whose type is absent from :class:`~namespy.enums.DnsRType` therefore lands in the
base :class:`RData` as a blob instead of raising -- the bug that previously made
a single ``HTTPS`` record (type 65, RFC 9460) fatal to the whole listener.

.. rubric:: References

* RFC 1035 section 3.3 (RDATA formats), 3.3.9 (MX), 3.3.13 (SOA), 3.3.14 (TXT)
* RFC 1982 / RFC 1035 section 3.3.13 (SOA serial number space arithmetic)
* RFC 2308 section 5 (SOA MINIMUM is the negative-cache TTL)
* RFC 2782 section 3 (SRV), RFC 7505 (null MX)
* RFC 3597 sections 3, 5 (opaque unknown types, ``\\#`` presentation)
* RFC 9267 section 5 (validate RDLENGTH; do not read past it)
* RFC 9460 sections 2.1, 2.2, 2.4, 2.5, 9 (SVCB/HTTPS presentation, wire format,
  AliasMode/ServiceMode, the root TargetName, the HTTP mapping); the SvcParamKeys
  themselves are :mod:`namespy.svcb`
"""

from __future__ import annotations

import datetime
import ipaddress
import struct
from collections.abc import Iterable
from typing import ClassVar

from .crypto import (
    ECDSA_ALGORITHMS,
    ECDSA_FIELD_OCTETS,
    EDDSA_ALGORITHMS,
    EDDSA_KEY_OCTETS,
    MAX_RSA_KEY_BITS,
    RSA_ALGORITHMS,
    minimum_rsa_key_bits,
)
from .dnssec import (
    DNSKEY_FLAG_REVOKED,
    DNSKEY_FLAG_SEP,
    DNSKEY_FLAG_ZONE_KEY,
    DNSKEY_HEAD_OCTETS,
    DNSKEY_PROTOCOL_VALUE,
    NSEC3_OPT_OUT_FLAG,
    DigestType,
    EcdsaPublicKey,
    MalformedRsaKeyError,
    RsaPublicKey,
    decode_base32hex,
    decode_base64_field,
    decode_hex_field,
    decode_type_bitmap,
    digest_material,
    ds_digest,
    eddsa_public_key_octets,
    encode_base32hex,
    encode_base64_field,
    encode_hex_field,
    encode_type_bitmap,
    key_material,
    known_digest_octets,
    nsec3_hash,
    unpack_ec_public_key,
    unpack_rsa_public_key,
    unsigned_field,
)
from .dnssec import (
    key_tag as key_tag_of,
)
from .enums import DnsRType
from .names import DomainName
from .svcb import HTTPS_AUTO_MANDATORY, IntOrStr, SvcbCandidate, SvcParams
from .wire import DnsPacketParseError, read_octets

__all__ = [
    "RData",
    "RData_A",
    "RData_AAAA",
    "RData_CNAME",
    "RData_DNAME",
    "RData_DNSKEY",
    "RData_DS",
    "RData_HTTPS",
    "RData_MX",
    "RData_NS",
    "RData_NSEC",
    "RData_NSEC3",
    "RData_NSEC3PARAM",
    "RData_PTR",
    "RData_RRSIG",
    "RData_SOA",
    "RData_SRV",
    "RData_SVCB",
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

    def canonical_wire(self) -> bytes:
        """RDATA as a signature covers it (RFC 4034 §6.2, RFC 3597 §7).

        For most types that is simply the wire form: no embedded domain name means nothing to
        downcase, and the codecs already re-encode names expanded rather than copying pointers.
        The name-bearing codecs override this; anything that reaches the base implementation and
        *is* in RFC 4034 §6.2 item 3's list would be silently under-canonicalised, which is why
        :func:`namespy.dnssec.canonical_rdata_octets` only asks types in that list to prove they
        have an override by way of the codec existing.
        """
        return self.to_wire()

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

    Subclasses :class:`~namespy.names.DomainName` rather than :class:`RData`, so an
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

    def canonical_wire(self) -> bytes:
        """The name downcased, which for this shape means lowering the whole RDATA.

        §6.2 item 2/3 downcase domain names, and here the entire RDATA is one name. Lowering every
        octet is safe for exactly the reason given in
        :func:`namespy.dnssec.canonical_owner_octets`: a length octet is at most 63 and the root is
        0, so the only bytes that can land in A-Z are label contents. MX and SRV cannot use this --
        they have numeric fields ahead of their name, and a preference of 0x41 is not a letter.
        """
        return self.to_wire().lower()

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
        if length is not None and len(original) < int(length):
            # Fail closed on the other side too: RDATA that does not end with
            # the name carries octets no field accounts for. MX, SRV and SOA
            # already refuse this; NS/CNAME/PTR/DNAME must not accept it.
            raise DnsPacketParseError(
                f"{cls._type_label()} RDATA has {int(length) - len(original)} "
                f"trailing octet(s) after the name (RFC 9267 section 5)",
                data=buffer,
                offset=end,
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
    :meth:`namespy.resolver.Resolver._negative_ttl_seconds` could only fall back
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

    def canonical_wire(self) -> bytes:
        """Both names downcased, the five timers untouched (§6.2 item 3).

        Lowering the whole record would corrupt a serial or a refresh whose octet happens to land
        in A-Z, which is why this rebuilds rather than transforms. MNAME and RNAME arrive here
        expanded already -- :meth:`parse_from` reads them through :func:`_read_name`, which refuses
        a name that overruns its RDATA -- so item 1 is satisfied by construction.
        """
        return (
            bytes(self.mname).lower()
            + bytes(self.rname).lower()
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
        if not strings:
            # RFC 1035 section 3.3.14: TXT RDATA is one or more
            # <character-string>; an empty RDLENGTH is malformed, not an
            # empty string.
            raise DnsPacketParseError(
                "TXT RDATA contains no character-string (RFC 1035 section 3.3.14)",
                data=blob,
                offset=offset,
            )
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

    def canonical_wire(self) -> bytes:
        """Preference untouched, exchange downcased (RFC 4034 §6.2 item 3)."""
        return struct.pack(self._FMT, self.preference) + bytes(DomainName(self.name)).lower()

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

    def canonical_wire(self) -> bytes:
        """Priority, weight and port untouched; target downcased (§6.2 item 3)."""
        return (
            struct.pack(self._FMT, self.priority, self.weight, self.port)
            + bytes(self.target).lower()
        )

    def to_presentation(self) -> str:
        return f"{self.priority} {self.weight} {self.port} {self.target}"


# ---------------------------------------------------------- service binding


class RData_SVCB(RData):
    """``SVCB`` RDATA -- SvcPriority, TargetName, SvcParams (RFC 9460 section 2.2).

    One layout serves two modes and the first field selects: SvcPriority 0 is
    AliasMode, which renames the service, and anything else is ServiceMode, which
    binds parameters to a target (section 2.4). The SvcParams have no length field
    of their own -- section 2.2 says they consume "the remainder of the record" --
    so the only thing that can tell a parser where they stop is the RDLENGTH, and a
    SvcParam that would run past it is malformed rather than merely suspicious.

    The target comes first in the constructor's order, as in :class:`RData_MX` and
    :class:`RData_SRV`, and has no default: ``.`` is a real value in both modes --
    "service not available" in AliasMode, "the owner name itself" in ServiceMode
    (section 2.5) -- so defaulting it would make the constructor state something.

    What to do about a record that will not decode is not this class's decision.
    :class:`RData` keeps the received octets intact either way, and
    :func:`namespy.svcb.select_records` is where section 2.2's "MUST reject the
    entire RRset" verdict belongs.
    """

    RType = DnsRType.SVCB

    #: SvcParamKeys the protocol mapping makes mandatory without their being listed.
    #: Section 8: generic SVCB defines no mapping, so it has none. HTTPS overrides
    #: this with :data:`namespy.svcb.HTTPS_AUTO_MANDATORY`.
    _AUTO_MANDATORY: ClassVar[frozenset[int]] = frozenset()

    def __init__(
        self,
        target: DomainName | str,
        priority: int = 0,
        params: SvcParams | Iterable[tuple[IntOrStr, bytes]] = (),
        *,
        wire: bytes | None = None,
    ) -> None:
        self.priority = int(priority)
        if not 0 <= self.priority <= 0xFFFF:
            raise ValueError(f"SvcPriority {priority} is outside 0..65535")
        self.target = target if isinstance(target, DomainName) else DomainName(target)
        self.params = params if isinstance(params, SvcParams) else SvcParams(params)
        super().__init__(self.to_wire(), wire=wire)

    @property
    def is_alias(self) -> bool:
        """SvcPriority 0: the record renames the service instead of describing it."""
        return self.priority == 0

    @classmethod
    def parse_from(cls, buffer: bytes, offset: int = 0, length: int | None = None):
        blob = cls.rdata_octets(buffer, offset, length)
        end = offset + len(blob)
        if len(blob) < 3:
            raise DnsPacketParseError(
                f"{cls._type_label()} RDATA is {len(blob)} octet(s), too short for a "
                "SvcPriority and a TargetName",
                data=blob,
                offset=offset,
            )
        (priority,) = struct.unpack_from("!H", buffer, offset)
        target, cursor = _read_name(
            buffer, offset + 2, end, where=f"{cls._type_label()} TargetName"
        )
        # The parameters run to the end of the RDLENGTH: from_wire is handed that
        # window and refuses a SvcParam that would cross it (RFC 9460 section 2.2).
        params, _ = SvcParams.from_wire(buffer, cursor, size=end - cursor, data=blob)
        return cls(target, priority, params, wire=blob)

    def to_wire(self) -> bytes:
        """Priority, then the TargetName written out in full -- section 2.2's rule."""
        return struct.pack("!H", self.priority) + bytes(self.target) + self.params.to_wire()

    def to_presentation(self) -> str:
        """``SvcPriority TargetName [SvcParams]`` -- section 2.1's order."""
        params = self.params.to_presentation()
        return f"{self.priority} {self.target} {params}".rstrip()

    def candidate(self, owner: DomainName | str) -> SvcbCandidate:
        """This RDATA and an owner name, in the shape :func:`namespy.svcb.select_records` reads.

        RDATA has no owner name, yet two of the decisions a client makes need one:
        RFC 9460 section 2.4.3 checks 11-13 compare the owner with the TargetName,
        and section 2.5 turns a root TargetName into the owner name. The mapping's
        automatically-mandatory keys come along from :attr:`_AUTO_MANDATORY` for the
        same reason -- section 8 judges those by protocol, and the RDATA class is
        what knows which protocol this is.
        """
        return SvcbCandidate(
            owner=owner if isinstance(owner, DomainName) else DomainName(owner),
            priority=self.priority,
            target=self.target,
            params=self.params,
            auto_mandatory=self._AUTO_MANDATORY,
        )


class RData_HTTPS(RData_SVCB):
    """``HTTPS`` RDATA -- the SVCB format plus the HTTP mapping (RFC 9460 sections 9, 14.2).

    Nothing about the wire format changes; what changes is what the fields mean. Two
    of those differences are attached to the class so a caller cannot lose them:
    section 9 and Appendix B Table 3 make ``port`` and ``no-default-alpn``
    automatically mandatory, so a client that cannot act on one must ignore an RR
    that carries it; and section 9 gives ``http/1.1`` alone as the default ALPN set,
    which :attr:`default_alpn` carries so that an HTTPS call site of
    :meth:`namespy.svcb.SvcParams.svc_alpn_set` needs no arguments.
    """

    RType = DnsRType.HTTPS
    _AUTO_MANDATORY: ClassVar[frozenset[int]] = HTTPS_AUTO_MANDATORY

    #: RFC 9460 section 9: "The default set of ALPN IDs is the single value
    #: 'http/1.1'"; Appendix B Table 3 repeats it as the mapping's SvcParam default.
    _DEFAULT_ALPN: ClassVar[tuple[bytes, ...]] = (b"http/1.1",)

    @property
    def default_alpn(self) -> tuple[bytes, ...]:
        """The ALPN set an RR with neither ``alpn`` nor ``no-default-alpn`` offers."""
        return self._DEFAULT_ALPN


# ------------------------------------------------------------ DNSSEC (RFC 4034)


class RData_DNSKEY(RData):
    """``DNSKEY`` RDATA -- Flags, Protocol, Algorithm, Public Key (RFC 4034 §2.1).

    The public key is stored as opaque octets, and nothing on the parse path interprets it:
    §2.1.4 says only that "The format depends on the algorithm of the key being stored and is
    described in separate documents". Those documents have now been read -- RFC 3110 §2 is
    integer packing, RFC 6605 §4 is two fixed-width coordinates, RFC 8080 §3 is a bare
    bit string -- and :meth:`rsa_public_key`, :meth:`ec_public_key` and
    :meth:`eddsa_public_key` decode them here on request, with no dependency for any of it:
    every format turned out to be layout rather than arithmetic. Everything that never needs
    a format at all -- the flags, the key tag, the DS a key turns into -- is still computed
    on the raw octets.

    Nothing in this class rejects a key it finds unusable, because the RFCs put those
    judgements at verification time: §2.1.2 says a Protocol other than 3 makes the RR
    "treated as invalid *during signature verification*", and §2.1.1¶3 says the
    reserved flag bits "MUST be ignored upon receipt". A resolver that dropped such a
    record while parsing could not tell an operator which rule the zone broke, so it
    is kept, and :attr:`may_verify_rrsets` states the consequence instead.
    """

    RType = DnsRType.DNSKEY

    def __init__(
        self,
        flags: int,
        protocol: int,
        algorithm: int,
        public_key,
        *,
        wire: bytes | None = None,
    ) -> None:
        self.flags = unsigned_field(flags, bits=16, name="DNSKEY flags")
        self.protocol = unsigned_field(protocol, bits=8, name="DNSKEY protocol")
        self.algorithm = unsigned_field(algorithm, bits=8, name="DNSKEY algorithm")
        key = key_material(public_key)
        if not key:
            raise ValueError("DNSKEY public key is empty")
        self.public_key = key
        super().__init__(self.to_wire(), wire=wire)

    @classmethod
    def parse_from(cls, buffer: bytes, offset: int = 0, length: int | None = None):
        blob = cls.rdata_octets(buffer, offset, length)
        if len(blob) <= DNSKEY_HEAD_OCTETS:
            raise DnsPacketParseError(
                f"DNSKEY RDATA is {len(blob)} octet(s), must exceed the "
                f"{DNSKEY_HEAD_OCTETS}-octet Flags/Protocol/Algorithm header",
                data=buffer,
                offset=offset,
            )
        flags, protocol, algorithm = struct.unpack_from("!HBB", blob, 0)
        return cls(flags, protocol, algorithm, blob[DNSKEY_HEAD_OCTETS:], wire=blob)

    def to_wire(self) -> bytes:
        return struct.pack("!HBB", self.flags, self.protocol, self.algorithm) + self.public_key

    @property
    def key_algorithm_is_rsa(self) -> bool:
        """Whether :attr:`algorithm` packs its public key per RFC 3110 §2.

        Derived from `namespy.crypto`'s algorithm table rather than a local list, so this cannot
        drift from it. Algorithm 1 (RSA/MD5) is deliberately False: RFC 3110 §2's notes moved
        RSA/SHA-1 onto number 5 to separate it from RFC 2537's RSA/MD5 keys, whose RDATA begins
        with a key-length header that would be read here as an exponent length.
        """
        return self.algorithm in RSA_ALGORITHMS

    def rsa_public_key(self) -> RsaPublicKey | None:
        """The RSA key this record carries, or None if its algorithm is not RSA-packed.

        Parsing still never interprets the key material -- see the class docstring -- so this is
        where interpretation happens, on request, and a zone holding a malformed RSA key still
        yields a record that can be counted, key-tagged and reported.
        :class:`namespy.dnssec.MalformedRsaKeyError` here means the octets cannot be read as a
        key at all, which is a different report from a key that is readable but too small.
        """
        if not self.key_algorithm_is_rsa:
            return None
        return unpack_rsa_public_key(self.public_key)

    def require_rsa_key(self) -> RsaPublicKey:
        """The RSA key, checked against the size window this algorithm's RFC sets.

        The upper bound is RFC 3110 §2¶3's 4096 bits; the lower one is per-algorithm because
        RFC 5702 §2.2¶2 demands 1024 bits for RSA/SHA-512 while §3¶9 and §2.1¶2 leave 512 for
        numbers 5, 7 and 8. Enforcing one constant across all four would accept a 512-bit
        RSA/SHA-512 key, and since a zone may hold keys of several algorithms, the weakest one is
        what an attacker would aim at.

        Raises for a non-RSA algorithm as well as for unreadable key material: callers use this
        precisely when they are about to verify an RSA signature, so a GOST or ECDSA key reaching
        it is a programming error rather than a hostile record.
        """
        key = self.rsa_public_key()
        if key is None:
            raise ValueError(
                f"DNSKEY algorithm {self.algorithm} does not use the RFC 3110 RSA key format"
            )
        minimum = minimum_rsa_key_bits(self.algorithm)
        if key.key_bits < minimum:
            raise MalformedRsaKeyError(
                f"DNSKEY algorithm {self.algorithm} requires at least {minimum} bits, "
                f"this modulus has {key.key_bits}"
            )
        if key.key_bits > MAX_RSA_KEY_BITS:
            raise MalformedRsaKeyError(
                f"DNSKEY modulus is {key.key_bits} bits, over the {MAX_RSA_KEY_BITS}-bit "
                f"interoperability limit of RFC 3110 §2¶3"
            )
        return key

    @property
    def key_algorithm_is_ecdsa(self) -> bool:
        """Whether :attr:`algorithm` packs its public key as two field elements (RFC 6605 §4¶1)."""
        return self.algorithm in ECDSA_ALGORITHMS

    @property
    def key_algorithm_is_eddsa(self) -> bool:
        """Whether :attr:`algorithm` carries its public key as a bare bit string (RFC 8080 §3)."""
        return self.algorithm in EDDSA_ALGORITHMS

    def ec_public_key(self) -> EcdsaPublicKey | None:
        """The ECDSA curve point this record carries, or None if its algorithm is not ECDSA.

        The width is the curve's and is therefore not a judgement: RFC 6605 §4¶2 says the
        coordinates MUST be 32 octets each on P-256 and 48 on P-384, so there is no size
        window to consult the way RSA keys have one -- wrong width is malformed, not weak.
        Whether the point is *on* the curve is arithmetic, and arrives with the backend.
        """
        if not self.key_algorithm_is_ecdsa:
            return None
        return unpack_ec_public_key(
            self.public_key, field_octets=ECDSA_FIELD_OCTETS[self.algorithm]
        )

    def require_ec_key(self) -> EcdsaPublicKey:
        """The ECDSA point, refusing a record whose algorithm is not ECDSA.

        Mirrors :meth:`require_rsa_key`: callers reach for this about to verify an ECDSA
        signature, so a key of another algorithm arriving here is a programming error.
        """
        key = self.ec_public_key()
        if key is None:
            raise ValueError(
                f"DNSKEY algorithm {self.algorithm} does not use the RFC 6605 §4 "
                f"two-coordinate key format"
            )
        return key

    def eddsa_public_key(self) -> bytes | None:
        """The EdDSA key octets at their fixed width, or None if the algorithm is not EdDSA.

        RFC 8080 §3 gives the key as one value of one width -- 32 octets for Ed25519, 57
        for Ed448 -- so this reads nothing and checks only the length, the sole fact about
        the blob that needs no arithmetic.
        """
        if not self.key_algorithm_is_eddsa:
            return None
        return eddsa_public_key_octets(self.public_key, key_octets=EDDSA_KEY_OCTETS[self.algorithm])

    def require_eddsa_key(self) -> bytes:
        """The EdDSA key octets, refusing a record whose algorithm is not EdDSA."""
        key = self.eddsa_public_key()
        if key is None:
            raise ValueError(
                f"DNSKEY algorithm {self.algorithm} does not use the RFC 8080 §3 key format"
            )
        return key

    def to_presentation(self) -> str:
        """``256 3 5 AQPSKmyn...`` (RFC 4034 §2.2).

        Decimals for the three numeric fields, one Base64 token for the key. §2.3's
        own example wraps that token across five lines; this does not, because a
        single run survives being pasted into a shell and stays legal either way.
        """
        return (
            f"{self.flags} {self.protocol} {self.algorithm} {encode_base64_field(self.public_key)}"
        )

    @property
    def key_tag(self) -> int:
        """This key's DNSSEC key tag (RFC 4034 Appendix B), for RRSIG and DS matching.

        Computed from the RDATA rather than from ``self.algorithm`` on its own,
        because that is how §B defines the function -- and it means an RR whose flags
        or key were edited after construction cannot report a tag for bytes it no
        longer carries.
        """
        return key_tag_of(self.to_wire())

    @property
    def is_zone_key(self) -> bool:
        """Bit 7 (§2.1.1): a zone key, as opposed to some other kind of DNSKEY."""
        return bool(self.flags & DNSKEY_FLAG_ZONE_KEY)

    @property
    def is_secure_entry_point(self) -> bool:
        """Bit 15 (§2.1.1): the RFC 3757 hint that this key anchors a zone.

        A hint, and §2.1.1 is emphatic that it stays one -- "validators MUST NOT
        alter their behavior during the signature validation process in any way based
        on the setting of this bit". It matters when publishing a KSK, not when
        checking a signature made by one.
        """
        return bool(self.flags & DNSKEY_FLAG_SEP)

    @property
    def is_revoked(self) -> bool:
        """Bit 8 (RFC 5011 §3): the owner has said this key should be withdrawn.

        Trust-anchor bookkeeping rather than signature arithmetic. RFC 5011 §2.1
        makes the bit decisive for a key the resolver added as an anchor of its own
        accord, and §2.1's note that such a key "has a different fingerprint" is a
        reminder that revoking changes the DS pointing at the key instead of making
        the old DS wrong.
        """
        return bool(self.flags & DNSKEY_FLAG_REVOKED)

    @property
    def may_verify_rrsets(self) -> bool:
        """Whether RFC 4034 permits this key to verify an RRSIG over an RRset.

        Three instructions add up to this predicate: a key with the Zone Flag clear
        "MUST NOT be used to verify RRSIGs that cover RRsets" (§2.1.1¶1), one with SEP
        set and the Zone Flag clear is refused in the same words (§2.1.1¶2), and a
        Protocol other than 3 makes the record "treated as invalid during signature
        verification" (§2.1.2).

        The REVOKE bit is not in here, and that is a decision rather than an
        omission. RFC 5011 uses it to retire a trust anchor across a hold-down period
        during which the key still signs its own RRset perfectly well; treating the
        bit as "not a key" would have a resolver call a zone broken at the exact
        moment its operator is doing the right thing about key rotation.
        """
        return self.is_zone_key and self.protocol == DNSKEY_PROTOCOL_VALUE and bool(self.public_key)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, RData_DNSKEY):
            return self.to_wire() == other.to_wire()
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self.type_name, self.to_wire()))


class RData_DS(RData):
    """``DS`` RDATA -- Key Tag, Algorithm, Digest Type, Digest (RFC 4034 §5.1).

    The record that lets the chain of trust cross a zone cut: the parent holds a hash
    of the child's key rather than the key itself, so the child signs below the cut
    with material the parent never sees. §5.1 makes the first three fields a copy of
    the DNSKEY being pointed at and the fourth a hash of the owner name and RDATA
    together (§5.1.4).

    The digest is opaque here for the same reason a public key is opaque in
    :class:`RData_DNSKEY`: this package can *produce* one and compare one, but has
    nothing to authenticate it against until validation exists.
    """

    RType = DnsRType.DS

    #: Key Tag (2) + Algorithm (1) + Digest Type (1), ahead of the digest.
    _HEAD_OCTETS = 4

    def __init__(
        self,
        key_tag: int,
        algorithm: int,
        digest_type: int,
        digest,
        *,
        wire: bytes | None = None,
    ) -> None:
        self.key_tag = unsigned_field(key_tag, bits=16, name="DS key tag")
        self.algorithm = unsigned_field(algorithm, bits=8, name="DS algorithm")
        self.digest_type = unsigned_field(digest_type, bits=8, name="DS digest type")
        value = digest_material(digest)
        if not value:
            raise ValueError("DS digest is empty")
        self.digest = value
        super().__init__(self.to_wire(), wire=wire)

    @classmethod
    def for_dnskey(cls, owner, dnskey: RData_DNSKEY, digest_type=DigestType.SHA256):
        """The DS a parent publishes to introduce *dnskey* (RFC 4034 §5.1.4, §5.4).

        The three identifying fields are copied from the key rather than derived
        separately: §5.1.1 and §5.1.2 say the DS "lists the key tag / the algorithm
        number of the DNSKEY RR referred to", so a DS that disagrees with the key it
        names is a mistake, never a legitimate record.

        SHA-256 is the default because it is what a parent is expected to publish
        today; the mandatory-to-implement digest in RFC 4034's own Appendix A.2 was
        SHA-1, and the parameter exists because that has already changed once.
        """
        return cls(
            dnskey.key_tag,
            dnskey.algorithm,
            int(digest_type),
            ds_digest(owner, dnskey.to_wire(), digest_type),
        )

    @classmethod
    def parse_from(cls, buffer: bytes, offset: int = 0, length: int | None = None):
        blob = cls.rdata_octets(buffer, offset, length)
        if len(blob) <= cls._HEAD_OCTETS:
            raise DnsPacketParseError(
                f"DS RDATA is {len(blob)} octet(s), must exceed the "
                f"{cls._HEAD_OCTETS}-octet Key Tag/Algorithm/Digest Type header",
                data=buffer,
                offset=offset,
            )
        tag, algorithm, digest_type = struct.unpack_from("!HBB", blob, 0)
        digest = blob[cls._HEAD_OCTETS :]
        expected = known_digest_octets(digest_type)
        if expected is not None and len(digest) != expected:
            raise DnsPacketParseError(
                f"DS digest of type {digest_type} is {len(digest)} octet(s), must be {expected}",
                data=buffer,
                offset=offset + cls._HEAD_OCTETS,
            )
        return cls(tag, algorithm, digest_type, digest, wire=blob)

    def to_wire(self) -> bytes:
        return struct.pack("!HBB", self.key_tag, self.algorithm, self.digest_type) + self.digest

    def to_presentation(self) -> str:
        """``60485 5 1 2BB183AF...`` (RFC 4034 §5.3, matching §5.4's example).

        §5.3 allows the algorithm as a mnemonic; decimals are what it also permits
        and what survives a diff.
        """
        return f"{self.key_tag} {self.algorithm} {self.digest_type} {encode_hex_field(self.digest)}"

    def refers_to(self, dnskey: RData_DNSKEY, owner) -> bool:
        """Whether this DS names *dnskey* -- the claim RFC 4034 §5.3.1 asks a
        validator to check before it treats a key as introduced.

        The cheap fields are compared first because that is how a validator prunes
        candidates, but a tag match proves nothing on its own: Appendix B¶2 says
        "Implementations MUST NOT assume that the key tag uniquely identifies a
        DNSKEY RR". So the tag and algorithm only decide whether to hash; the hash
        decides the answer. An unsupported digest type is ``False`` rather than an
        error, because "I cannot confirm this" and "this is broken" are different
        statements and only the first one is ours to make.
        """
        if dnskey.key_tag != self.key_tag or dnskey.algorithm != self.algorithm:
            return False
        if known_digest_octets(self.digest_type) is None:
            return False
        return ds_digest(owner, dnskey.to_wire(), self.digest_type) == self.digest

    def __eq__(self, other: object) -> bool:
        if isinstance(other, RData_DS):
            return self.to_wire() == other.to_wire()
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self.type_name, self.to_wire()))


# --------------------------------------------------- proof records (RFC 4034 §3, §4)


#: RFC 4034 §3.1's fixed header, in field order: Type Covered (H), Algorithm (B),
#: Labels (B), Original TTL (I), Expiration (I), Inception (I), Key Tag (H) -- 18 octets
#: ahead of the Signer's Name. The three 32-bit fields have to be three I's: spelling
#: this "!HBBIIHI" keeps the size at 18 and silently reads the Key Tag into Inception,
#: which is the kind of bug a sweep payload catches and a hand-written one does not.
_RRSIG_HEAD_FMT = "!HBBIIIH"

#: §3.2¶6: the 14-digit form is exactly one character longer than the widest decimal a
#: 32-bit field can take, which is how a reader tells the two renderings apart.
_RRSIG_DATE_FMT = "%Y%m%d%H%M%S"


def _rrsig_time(value: int) -> str:
    """One RRSIG time field as YYYYMMDDHHmmSS in UTC (RFC 4034 §3.2¶6).

    The decimal form is equally legal, but the date form is what signed zones and zone
    diffs carry, and a resolver printing raw seconds is harder to read against either.
    The field is 32 bits, so the latest representable instant is 2106-02-07 and
    :mod:`datetime` cannot overflow on it.
    """
    moment = datetime.datetime.fromtimestamp(int(value), datetime.UTC)
    return moment.strftime(_RRSIG_DATE_FMT)


class RData_RRSIG(RData):
    """``RRSIG`` RDATA -- the signature over one RRset (RFC 4034 §3.1).

    Nine fields, and only two of them are the signature. The rest exist so a validator
    can find the key and rebuild the exact octets it signed: Type Covered and the Signer's
    Name say which RRset, Key Tag narrows the DNSKEYs to try (§3.1.6), Original TTL and
    Labels say what the TTL and owner name looked like before the wire changed them
    (§3.1.3, §3.1.4), and the two time fields bound how long the answer stays good.

    **Nothing here verifies a signature.** That needs each algorithm's arithmetic, and for
    RSA and DSA a dependency this package does not carry; the codec is useful without it,
    because these fields are what a resolver caches, prints, and hands to a validator
    later. The one rule this class does enforce is the validity window, since that is
    field comparison rather than cryptography (§3.1.5, :meth:`within_validity`).

    The Signer's Name is read as an uncompressed name: RFC 4034 §3.1.7 requires that it
    "must not be compressed", which is one reason these codecs go through
    :func:`_read_name` rather than a compression-aware reader.
    """

    RType = DnsRType.RRSIG

    def __init__(
        self,
        type_covered: int,
        algorithm: int,
        labels: int,
        original_ttl: int,
        expiration: int,
        inception: int,
        key_tag: int,
        signer_name,
        signature,
        *,
        wire: bytes | None = None,
    ) -> None:
        self.type_covered = unsigned_field(type_covered, bits=16, name="RRSIG type covered")
        self.algorithm = unsigned_field(algorithm, bits=8, name="RRSIG algorithm")
        self.labels = unsigned_field(labels, bits=8, name="RRSIG labels")
        self.original_ttl = unsigned_field(original_ttl, bits=32, name="RRSIG original TTL")
        self.expiration = unsigned_field(expiration, bits=32, name="RRSIG expiration")
        self.inception = unsigned_field(inception, bits=32, name="RRSIG inception")
        self.key_tag = unsigned_field(key_tag, bits=16, name="RRSIG key tag")
        self.signer_name = (
            signer_name if isinstance(signer_name, DomainName) else DomainName(signer_name)
        )
        # §2.2 lets whitespace appear anywhere inside the Base64, which is what
        # decode_base64_field exists to absorb; digest_material would be the wrong
        # helper here, since a DS digest is written in hex and a signature is not.
        blob = signature
        if not isinstance(blob, (bytes, bytearray)):
            blob = decode_base64_field(blob, what="RRSIG signature")
        if not blob:
            raise ValueError("RRSIG signature is empty")
        self.signature = bytes(blob)
        super().__init__(self.to_wire(), wire=wire)

    @classmethod
    def parse_from(cls, buffer: bytes, offset: int = 0, length: int | None = None):
        blob = cls.rdata_octets(buffer, offset, length)
        head = struct.calcsize(_RRSIG_HEAD_FMT)
        if len(blob) < head:
            raise DnsPacketParseError(
                f"RRSIG RDATA is {len(blob)} octet(s), must be at least {head}",
                data=buffer,
                offset=offset,
            )
        (
            type_covered,
            algorithm,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag,
        ) = struct.unpack_from(_RRSIG_HEAD_FMT, blob, 0)
        end = offset + len(blob)
        signer_name, cursor = _read_name(buffer, offset + head, end, where="RRSIG Signer's Name")
        return cls(
            type_covered,
            algorithm,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer_name,
            blob[cursor - offset :],
            wire=blob,
        )

    def to_wire(self) -> bytes:
        return (
            struct.pack(
                _RRSIG_HEAD_FMT,
                self.type_covered,
                self.algorithm,
                self.labels,
                self.original_ttl,
                self.expiration,
                self.inception,
                self.key_tag,
            )
            + bytes(self.signer_name)
            + self.signature
        )

    def signed_data_prefix(self) -> bytes:
        """RRSIG_RDATA with the Signature excluded and the signer downcased (§3.1.8.1¶4).

        That is literally what a signature covers ahead of the RRset: every field of this record
        except the signature itself, with the Signer's Name in canonical form -- downcased,
        because RRSIG is the other type RFC 4034 adds to RFC 3597's list. Excluding the signature
        is not an optimisation: including it would make the signed text depend on the signature.
        """
        return (
            struct.pack(
                _RRSIG_HEAD_FMT,
                self.type_covered,
                self.algorithm,
                self.labels,
                self.original_ttl,
                self.expiration,
                self.inception,
                self.key_tag,
            )
            + bytes(self.signer_name).lower()
        )

    def canonical_wire(self) -> bytes:
        """The whole record less the signature, plus it -- i.e. signer lowered only."""
        return self.signed_data_prefix() + self.signature

    @property
    def covered_type(self) -> str:
        """The RR type this signature covers: mnemonic, else ``TYPE`` form (§3.2¶2)."""
        return type_name_of(self.type_covered)

    def to_presentation(self) -> str:
        """``NSEC3 7 2 3600 20150420235959 20051021000000 40430 example. OsGOkm26...``

        Field order and rendering are RFC 4034 §3.2: the covered type as a mnemonic with
        the RFC 3597 ``TYPE`` form when unknown, the times in the 14-digit UTC form, the
        signature in Base64. The algorithm prints as a decimal -- §3.2¶3 also allows a
        mnemonic, but a number survives a signer using an algorithm this code has no name
        for.
        """
        return " ".join(
            (
                self.covered_type,
                str(self.algorithm),
                str(self.labels),
                str(self.original_ttl),
                _rrsig_time(self.expiration),
                _rrsig_time(self.inception),
                str(self.key_tag),
                str(self.signer_name),
                encode_base64_field(self.signature),
            )
        )

    def within_validity(self, moment: float | None = None) -> bool:
        """Whether *moment* falls inside this signature's stated lifetime.

        RFC 4034 §3.1.5¶1 is strict about the consequence -- the RRSIG "MUST NOT be used
        for authentication" outside the window -- but ¶2 is the trap: an RRSIG may carry an
        Expiration numerically *below* its Inception near the 32-bit wrap or for a
        long-lived signature, so "all comparisons involving these fields MUST use Serial
        number arithmetic" (RFC 1982). Comparing them as integers would reject a valid
        signature for roughly half of 2105-2106, which is far enough away to be forgotten
        and close enough to be someone's problem. :meth:`RData_SOA.serial_ahead` already
        implements that arithmetic for SOA serials, so it is reused rather than rewritten.

        As with any RFC 1982 comparison this is meaningful only within 2**31 seconds of the
        fields, a limit §3.1.5¶2 states itself: these fields "cannot refer to dates more
        than 68 years in either the past or the future".
        """
        if moment is None:
            moment = datetime.datetime.now(datetime.UTC).timestamp()
        now = int(moment) & 0xFFFFFFFF

        def at_or_after(candidate: int, boundary: int) -> bool:
            return candidate == boundary or RData_SOA.serial_ahead(candidate, boundary)

        return at_or_after(now, self.inception) and at_or_after(self.expiration, now)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, RData_RRSIG):
            return self.to_wire() == other.to_wire()
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self.type_name, self.to_wire()))


class RData_NSEC(RData):
    """``NSEC`` RDATA -- Next Domain Name and Type Bit Maps (RFC 4034 §4.1).

    The older denial-of-existence record: it names the next owner name in canonical order
    and lists every type that exists at this one, so a canonical walk from the query name
    proves absence. That same property is what makes a zone enumerable, which is why
    RFC 5155 hashed the names into NSEC3; NSEC is still widely served, and RFC 8020's
    ancestor-SOA rule has to be able to read it either way.

    Types are held as numbers, ascending and deduplicated, and re-encoded through
    :func:`encode_type_bitmap`. §4.1.2's ordering and trailing-zero MUSTs leave exactly one
    legal encoding for a given set, so comparing the rebuilt bytes is sound.
    """

    RType = DnsRType.NSEC

    def __init__(self, next_domain, types, *, wire: bytes | None = None) -> None:
        self.next_domain = (
            next_domain if isinstance(next_domain, DomainName) else DomainName(next_domain)
        )
        self.types = tuple(sorted({int(value) for value in types}))
        super().__init__(self.to_wire(), wire=wire)

    @classmethod
    def parse_from(cls, buffer: bytes, offset: int = 0, length: int | None = None):
        blob = cls.rdata_octets(buffer, offset, length)
        end = offset + len(blob)
        next_domain, cursor = _read_name(buffer, offset, end, where="NSEC Next Domain Name")
        try:
            types = decode_type_bitmap(blob[cursor - offset :])
        except ValueError as exc:
            raise DnsPacketParseError(str(exc), data=buffer, offset=cursor) from None
        return cls(next_domain, types, wire=blob)

    @property
    def type_bitmap(self) -> bytes:
        """The Type Bit Maps field as it will go on the wire (§4.1.2)."""
        return encode_type_bitmap(self.types)

    def has_type(self, rtype: int) -> bool:
        """Whether this record claims *rtype* exists at the owner name."""
        return int(rtype) in self.types

    def to_wire(self) -> bytes:
        return bytes(self.next_domain) + self.type_bitmap

    def canonical_wire(self) -> bytes:
        """Next Domain Name downcased, bitmap unchanged (§6.2 item 3 lists NSEC).

        NSEC is one of the two types RFC 4034 adds to RFC 3597 §7¶4's list -- the pairing that
        verified errata 1062 and 1063 exist to reconcile -- and the type its proofs turn on: a
        canonical walk that compared case-sensitively sorted RRs would order a zone differently
        from the signer and reject real NSEC records. The bitmap is a bitmap, so nothing in it is
        a name and nothing in it gets lowered.
        """
        return bytes(self.next_domain).lower() + self.type_bitmap

    def to_presentation(self) -> str:
        """``next.name. A MX RRSIG NSEC`` -- name then type mnemonics (RFC 4034 §4.2)."""
        listed = " ".join(type_name_of(value) for value in self.types)
        return str(self.next_domain) if not listed else f"{self.next_domain} {listed}"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, RData_NSEC):
            return self.to_wire() == other.to_wire()
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self.type_name, self.to_wire()))


class RData_NSEC3(RData):
    """``NSEC3`` RDATA -- hash parameters, hashed successor, Type Bit Maps (RFC 5155 §3.2).

    The same job as NSEC with the names hashed, so a passer-by cannot read the zone out of
    the chain. The four leading fields are not decoration: they are *this record's* hash
    parameters, because the NSEC3 RRs of a zone must agree on them and because a validator
    re-derives a name's hash from the very record it is using to prove absence (§5).

    Reading stays forgiving about what it does not understand -- an unknown hash algorithm
    parses, since the rest of the record is worth caching and printing -- while
    :meth:`hash_owner` refuses rather than inventing a hash function (§11 names SHA-1 and
    nothing else today).

    Lengths are checked against what the *algorithm* produces, not merely against §3.1.6's
    1..255 field bound: a 7-octet SHA-1 fits that field perfectly well and is a truncated
    proof, which is not something to carry quietly into a cache.
    """

    RType = DnsRType.NSEC3

    #: Octets a known hash algorithm produces (RFC 5155 §11: SHA-1, so far).
    _HASH_OCTETS: ClassVar[dict[int, int]] = {1: 20}

    #: Hash Alg + Flags + Iterations + Salt Length, ahead of the variable part.
    _HEAD_OCTETS = 5

    def __init__(
        self,
        hash_algorithm: int,
        flags: int,
        iterations: int,
        salt,
        next_hashed_owner,
        types,
        *,
        wire: bytes | None = None,
    ) -> None:
        self.hash_algorithm = unsigned_field(hash_algorithm, bits=8, name="NSEC3 hash algorithm")
        self.flags = unsigned_field(flags, bits=8, name="NSEC3 flags")
        self.iterations = unsigned_field(iterations, bits=16, name="NSEC3 iterations")
        if isinstance(salt, (bytes, bytearray)):
            self.salt = bytes(salt)
        else:
            self.salt = b"" if salt in ("", "-") else decode_hex_field(salt, what="NSEC3 salt")
        if isinstance(next_hashed_owner, (bytes, bytearray)):
            self.next_hashed_owner = bytes(next_hashed_owner)
        else:
            self.next_hashed_owner = decode_base32hex(next_hashed_owner)
        expected = self._HASH_OCTETS.get(self.hash_algorithm)
        if expected is not None and len(self.next_hashed_owner) != expected:
            raise ValueError(
                f"NSEC3 next hashed owner name is {len(self.next_hashed_owner)} octet(s); "
                f"hash algorithm {self.hash_algorithm} produces {expected}"
            )
        self.types = tuple(sorted({int(value) for value in types}))
        super().__init__(self.to_wire(), wire=wire)

    @classmethod
    def parse_from(cls, buffer: bytes, offset: int = 0, length: int | None = None):
        blob = cls.rdata_octets(buffer, offset, length)
        if len(blob) < cls._HEAD_OCTETS:
            raise DnsPacketParseError(
                f"NSEC3 RDATA is {len(blob)} octet(s), must be at least {cls._HEAD_OCTETS}",
                data=buffer,
                offset=offset,
            )
        hash_algorithm, flags, iterations, salt_length = struct.unpack_from("!BBHB", blob, 0)
        cursor = cls._HEAD_OCTETS
        salt = blob[cursor : cursor + salt_length]
        if len(salt) < salt_length:
            raise DnsPacketParseError(
                f"NSEC3 salt of {salt_length} octet(s) runs past the end of its RDATA",
                data=buffer,
                offset=offset + cursor,
            )
        cursor += salt_length
        if cursor >= len(blob):
            raise DnsPacketParseError(
                "NSEC3 RDATA ends before its Hash Length field",
                data=buffer,
                offset=offset + cursor,
            )
        hash_length = blob[cursor]
        cursor += 1
        if hash_length < 1:
            raise DnsPacketParseError(
                "NSEC3 Hash Length is 0; §3.1.6 bounds it at 1..255 octets",
                data=buffer,
                offset=offset + cursor - 1,
            )
        hashed = blob[cursor : cursor + hash_length]
        if len(hashed) < hash_length:
            raise DnsPacketParseError(
                f"NSEC3 hashed owner name of {hash_length} octet(s) runs past its RDATA",
                data=buffer,
                offset=offset + cursor,
            )
        cursor += hash_length
        try:
            types = decode_type_bitmap(blob[cursor:])
        except ValueError as exc:
            raise DnsPacketParseError(str(exc), data=buffer, offset=offset + cursor) from None
        return cls(hash_algorithm, flags, iterations, salt, hashed, types, wire=blob)

    @property
    def opt_out(self) -> bool:
        """Whether the Opt-Out flag is set (RFC 5155 §3.1.2.1).

        A set flag means this span may cover unsigned delegations, so a proof landing
        inside it establishes "insecure" rather than "does not exist" -- a difference that
        changes the answer a resolver gives. §3.1.2 adds that undefined flags "must be
        zero"; as with the DNSKEY reserved bits that is a rule about senders, so unknown
        bits are preserved on :attr:`flags` for a validator to object to rather than
        silently cleared or rejected here.
        """
        return bool(self.flags & NSEC3_OPT_OUT_FLAG)

    @property
    def type_bitmap(self) -> bytes:
        """The Type Bit Maps field as it will go on the wire (RFC 5155 §3.1.8)."""
        return encode_type_bitmap(self.types)

    def has_type(self, rtype: int) -> bool:
        """Whether this record claims *rtype* exists at the original owner name."""
        return int(rtype) in self.types

    def hash_owner(self, owner) -> bytes:
        """The hash *owner* would need in order to sit at this record's owner name.

        Computed with this record's own algorithm, iterations and salt -- which is what
        those fields are for (§5). Matching it against the first label of the record's
        owner name is how a validator finds the NSEC3 RR for a name; deciding whether a
        name falls *between* this record and :attr:`next_hashed_owner` is the proof step,
        and is not claimed here.
        """
        return nsec3_hash(
            owner,
            iterations=self.iterations,
            salt=self.salt,
            hash_algorithm=self.hash_algorithm,
        )

    def to_wire(self) -> bytes:
        return (
            struct.pack("!BBHB", self.hash_algorithm, self.flags, self.iterations, len(self.salt))
            + self.salt
            + bytes([len(self.next_hashed_owner)])
            + self.next_hashed_owner
            + self.type_bitmap
        )

    def to_presentation(self) -> str:
        """``1 1 12 aabbccdd 2t7b4g4vsa5smi47k61mv5bv1a22bojr MX DNSKEY NS SOA ...``

        RFC 5155 §3.3: neither length field is represented, an empty salt is ``-`` rather
        than nothing, and the hashed owner name is unpadded base32hex -- base32*hex*, per
        verified erratum 3544 correcting the document's own wording (see
        :func:`~namespy.dnssec.encode_base32hex`).
        """
        parts = [str(self.hash_algorithm), str(self.flags), str(self.iterations)]
        parts.append("-" if not self.salt else encode_hex_field(self.salt))
        parts.append(encode_base32hex(self.next_hashed_owner))
        parts.extend(type_name_of(value) for value in self.types)
        return " ".join(parts)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, RData_NSEC3):
            return self.to_wire() == other.to_wire()
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self.type_name, self.to_wire()))


class RData_NSEC3PARAM(RData):
    """``NSEC3PARAM`` RDATA -- the hash parameters a zone uses (RFC 5155 §4.1).

    Held at the zone apex, and the same four fields an NSEC3 record starts with. It is the
    record an operator reads to learn a zone's salt and iteration count, and the one to
    watch when a zone rotates its salt: §9.2 warns that changing it invalidates cached
    NSEC3 proofs much as a re-sign does.

    It carries no key material and proves nothing by itself -- §4.1¶3 notes the information
    "could also be derived from the NSEC3 RR" anyway -- so its presence is not evidence that
    a zone is signed and must not be read as such.
    """

    RType = DnsRType.NSEC3PARAM

    _HEAD_OCTETS = 5

    def __init__(
        self,
        hash_algorithm: int,
        flags: int,
        iterations: int,
        salt,
        *,
        wire: bytes | None = None,
    ) -> None:
        self.hash_algorithm = unsigned_field(
            hash_algorithm, bits=8, name="NSEC3PARAM hash algorithm"
        )
        self.flags = unsigned_field(flags, bits=8, name="NSEC3PARAM flags")
        self.iterations = unsigned_field(iterations, bits=16, name="NSEC3PARAM iterations")
        if isinstance(salt, (bytes, bytearray)):
            self.salt = bytes(salt)
        else:
            self.salt = b"" if salt in ("", "-") else decode_hex_field(salt, what="NSEC3PARAM salt")
        super().__init__(self.to_wire(), wire=wire)

    @classmethod
    def parse_from(cls, buffer: bytes, offset: int = 0, length: int | None = None):
        blob = cls.rdata_octets(buffer, offset, length)
        if len(blob) < cls._HEAD_OCTETS:
            raise DnsPacketParseError(
                f"NSEC3PARAM RDATA is {len(blob)} octet(s), must be at least {cls._HEAD_OCTETS}",
                data=buffer,
                offset=offset,
            )
        hash_algorithm, flags, iterations, salt_length = struct.unpack_from("!BBHB", blob, 0)
        salt = blob[cls._HEAD_OCTETS : cls._HEAD_OCTETS + salt_length]
        if len(salt) < salt_length:
            raise DnsPacketParseError(
                f"NSEC3PARAM salt of {salt_length} octet(s) runs past the end of its RDATA",
                data=buffer,
                offset=offset + cls._HEAD_OCTETS,
            )
        if len(blob) > cls._HEAD_OCTETS + salt_length:
            extra = len(blob) - cls._HEAD_OCTETS - salt_length
            raise DnsPacketParseError(
                f"NSEC3PARAM RDATA carries {extra} unexpected octet(s) after the salt",
                data=buffer,
                offset=offset + cls._HEAD_OCTETS + salt_length,
            )
        return cls(hash_algorithm, flags, iterations, salt, wire=blob)

    @property
    def opt_out(self) -> bool:
        """The Opt-Out flag, read exactly as in an NSEC3 RR (RFC 5155 §4.1.1)."""
        return bool(self.flags & NSEC3_OPT_OUT_FLAG)

    def to_wire(self) -> bytes:
        return (
            struct.pack("!BBHB", self.hash_algorithm, self.flags, self.iterations, len(self.salt))
            + self.salt
        )

    def to_presentation(self) -> str:
        """``1 0 12 aabbccdd`` -- §4.2, and RFC 5155 Appendix A's own apex line."""
        salt = "-" if not self.salt else encode_hex_field(self.salt)
        return f"{self.hash_algorithm} {self.flags} {self.iterations} {salt}"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, RData_NSEC3PARAM):
            return self.to_wire() == other.to_wire()
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self.type_name, self.to_wire()))
