"""Protocol constants for the DNS wire format.

Values follow the IANA registries, and every assignment carries the reference
that made it. Three details are worth stating because they are the ones people
get wrong:

**RCODE is 12 bits, not 4.** RFC 1035 section 4.1.1 gives the header a 4-bit
field; RFC 6891 section 6.1.3 adds an ``EXTENDED-RCODE`` octet in the OPT RR,
and an extended value of 0 means "unextended, values 0-15 only". Decoding a
header therefore yields 0-15; anything above that requires EDNS(0), which this
library does not yet send.

**The extended values moved.** RFC 2930 section 2.6 originally listed
``BADSIG=16, BADKEY=17, BADTIME=18, BADMODE=19, BADNAME=20, BADALG=21``; RFC
6891 then assigned 16 to ``BADVERS``, and the registry shifted the TSIG/SIG(0)
codes up by one. The numbering below is the current registry. RFC 7873's own
IANA table printed ``BADCOOKIE=23``, which collides with ``BADALG``; the
registry lists it at 25, and that is what is used here.

**QTYPE is a superset of RTYPE.** ``AXFR``, ``MAILB``, ``MAILA`` and ``ANY``
(252-255) are query-only pseudo-types (RFC 1035 sections 3.2.3 and 6), and
``OPT`` (41) never appears as a stored record (RFC 6891 section 6.3). Both
enums are written out explicitly rather than derived from one another so type
checkers can resolve ``DnsRType.SOA``; ``test_enums.py`` asserts the
superset relation, so the two tables cannot drift.

Unknown values are *not* an error: RFC 3597 section 3 requires a responder's
unknown types to be handled transparently, and RFC 5625 section 6.3 permits
dropping a message but does not require rejecting an unfamiliar code. Parsers
therefore fall back to the raw ``int`` rather than raising, which is why the
member lookup in :class:`~aiodns.packet.DnsRecord` is guarded.
"""

from enum import IntEnum


class _TypeMixin:
    """Shared lookup helper for the protocol constant spaces.

    Mixed in before :class:`IntEnum` so ``parse`` is a classmethod on the
    concrete enum. An unknown value degrades to a plain ``int`` instead of
    raising: RFC 3597 section 3 requires unknown types to be handled
    transparently, and inventing an enum member at runtime is not possible
    anyway. Rendering an unknown value wants ``getattr(value, "name", value)``.
    """

    @classmethod
    def parse(cls, value: int):
        """Return the enum member for ``value``, or ``value`` itself."""
        try:
            return cls(value)
        except ValueError:
            return int(value)


class DnsResponseCode(_TypeMixin, IntEnum):
    """Header RCODE (RFC 1035 section 4.1.1) and EDNS(0) extended values.

    Values 11-15 are unassigned in the registry; a header carrying one is
    decoded with :meth:`parse`, which returns the raw octet instead of raising,
    so an unfamiliar code never causes an otherwise valid response to be
    discarded.
    """

    no_error = 0  # NOERROR
    format_error = 1  # FORMERR -- RFC 1035 section 4.1.1
    server_failure = 2  # SERVFAIL
    name_error = 3  # NXDOMAIN
    not_implemented = 4  # NOTIMP
    refused = 5  # REFUSED
    yxdomain = 6  # RFC 2136 section 2.3 (UPDATE)
    yxrrset = 7  # RFC 2136 section 2.3
    nxrrset = 8  # RFC 2136 section 2.3
    not_auth = 9  # NOTAUTH -- RFC 2136 section 2.3
    not_zone = 10  # NOTZONE -- RFC 2136 section 2.3
    badvers = 16  # RFC 6891 section 6.1.3 (also spelled BADVERS)
    badsig = 17  # RFC 8945 (TSIG); 16 before RFC 6891 displaced it
    badkey = 18  # RFC 8945
    badtime = 19  # RFC 8945
    badmode = 20  # RFC 2930 (SIG(0)/TKEY)
    badname = 21  # RFC 2930
    badkey_policy = 22  # second BADKEY in the registry, from RFC 2930
    badalg = 23  # RFC 2930
    badtrunc = 24  # RFC 8945 (TSIG truncated a keyed hash)
    badcookie = 25  # RFC 7873; registry lists 25, the RFC's table said 23

    def __str__(self) -> str:
        return self.name  # type: ignore[return-value]


class DnsOpCode(_TypeMixin, IntEnum):
    """Header OPCODE field (RFC 1035 section 4.1.1, RFC 8482 section 4).

    The 4-bit space is sparse, and RFC 2929 section 3.1 is explicit that an
    unassigned opcode is *not* a syntax error -- a receiver answers it with
    ``NOTIMP`` rather than discarding the message. Decoding therefore degrades to
    a plain ``int`` via :meth:`parse` instead of raising, so a NOTIFY from a
    server using an opcode this enum has never heard of is still inspectable.
    """

    query = 0  # RFC 1035
    iquery = 1  # RFC 1035 -- obsolete, must not be emitted (RFC 8906)
    status = 2  # RFC 1035
    notify = 4  # RFC 1996 section 2
    update = 5  # RFC 2136 section 2


class DnsQR(IntEnum):
    """Header QR bit: a query or a response (RFC 1035 section 4.1.1)."""

    query = 0
    response = 1


class DnsRClass(_TypeMixin, IntEnum):
    """RR CLASS for stored records (RFC 1035 section 3.2.4)."""

    IN = 1
    CS = 2  # CSNET -- historical
    CH = 3  # CHAOS
    HS = 4  # Hesiod
    NONE = 254  # RFC 2136 section 3.5: UPDATE prerequisite, never in a zone
    ANY = 255  # QCLASS only (RFC 1035 section 3.2.3)


class DnsQClass(_TypeMixin, IntEnum):
    """QCLASS: every RR class plus the ``ANY`` wildcard (RFC 1035 section 3.2.3)."""

    IN = 1
    CS = 2
    CH = 3
    HS = 4
    NONE = 254
    ANY = 255


class DnsRType(_TypeMixin, IntEnum):
    """RR TYPE values from the IANA "DNS RRs" registry.

    The historical ARPANET block (1-65535, RFC 1035 section 3.2.3) is included
    for completeness; the entries worth caring about today are ``A``, ``AAAA``,
    ``NS``, ``CNAME``, ``SOA``, ``PTR``, ``MX``, ``TXT``, ``SRV``, ``OPT``,
    ``DS``/``RRSIG``/``DNSKEY``/``NSEC``/``NSEC3`` (DNSSEC), ``TLSA``, ``SSHFP``,
    ``URI``, ``CAA`` and -- added since this file was last touched --
    ``CSYNC``, ``ZONEMD``, ``SVCB`` and ``HTTPS``.

    Omitting a *current* type is not a cosmetic gap. Before ``SVCB``/``HTTPS``
    were listed here, a response containing one HTTPS RR was enough to break the
    RR builder, because a type that is not in the enum was passed onward as a
    bare ``int`` to code that expected a member. Any server answering
    ``HTTPS`` -- which is now most of them -- took the listener down.
    """

    A = 1  # RFC 1035 section 3.4.1
    NS = 2
    MD = 3  # obsolete, historical only
    MF = 4  # obsolete, historical only
    CNAME = 5  # RFC 1035 section 3.3.1
    SOA = 6  # RFC 1035 section 3.3.13
    MB = 7
    MG = 8
    MR = 9
    NULL = 10
    WKS = 11
    PTR = 12  # RFC 1035 section 3.3.12
    HINFO = 13
    MINFO = 14
    MX = 15  # RFC 7505
    TXT = 16  # RFC 1035 section 3.3.14
    RP = 17
    AFSDB = 18
    X25 = 19
    ISDN = 20
    RT = 21
    NSAP = 22
    NSAP_PTR = 23
    SIG = 24  # RFC 2535 (obsolete in favour of RRSIG)
    KEY = 25  # RFC 2535 (obsolete in favour of DNSKEY)
    PX = 26
    GPOS = 27  # obsolete, historical only
    AAAA = 28  # RFC 3596 section 3
    LOC = 29  # RFC 1876
    NXT = 30  # RFC 2535 (obsolete in favour of NSEC)
    EID = 31
    NIMLOC = 32
    SRV = 33  # RFC 2782
    ATMA = 34
    NAPTR = 35  # RFC 3403
    KX = 36
    CERT = 37  # RFC 4398
    A6 = 38  # historic (RFC 3363), superseded by AAAA
    DNAME = 39  # RFC 6672 section 4
    SINK = 40
    OPT = 41  # RFC 6891 section 6.1 -- transport-layer, never a stored RR
    APL = 42
    DS = 43  # RFC 4034 section 5
    SSHFP = 44  # RFC 4255
    IPSECKEY = 45  # RFC 4025
    RRSIG = 46  # RFC 4034 section 3
    NSEC = 47  # RFC 4034 section 4
    DNSKEY = 48  # RFC 4034 section 2
    DHCID = 49  # RFC 4701
    NSEC3 = 50  # RFC 5155 section 3
    NSEC3PARAM = 51  # RFC 5155 section 4
    TLSA = 52  # RFC 6698 section 3
    SMIMEA = 53  # RFC 8162 -- was listed as unassigned here
    HIP = 55  # RFC 8005
    NINFO = 56
    RKEY = 57
    TALINK = 58
    CDS = 59  # RFC 7344 section 3
    CDNSKEY = 60  # RFC 7344 section 3
    OPENPGPKEY = 61  # RFC 7929
    CSYNC = 62  # RFC 7499 section 4
    ZONEMD = 63  # RFC 8976 section 4.2
    SVCB = 64  # RFC 9460 section 12.3 -- Service Binding
    HTTPS = 65  # RFC 9460 section 12.4 -- HTTP(2) service binding
    SPF = 99  # RFC 7208 (historic; use TXT)
    UINFO = 100
    UID = 101
    GID = 102
    UNSPEC = 103
    NID = 104  # RFC 6742
    L32 = 105  # RFC 6742
    L64 = 106  # RFC 6742
    LP = 107  # RFC 6742
    EUI48 = 108  # RFC 7043 section 3
    EUI64 = 109  # RFC 7043 section 4
    TKEY = 249  # RFC 2930 -- key establishment, not a stored RR
    TSIG = 250  # RFC 8945 -- transaction signature, not a stored RR
    IXFR = 251  # RFC 1995 -- incremental zone transfer
    URI = 256  # RFC 7553
    CAA = 257  # RFC 8659 section 3
    TA = 32768  # RFC 8145 (DNSSEC Trust Anchor, experimental)
    DLV = 32769  # RFC 4431, deprecated by RFC 8880 which reuses this value for AMTRELAY
    Reserved = 65535

    def __repr__(self) -> str:
        return self.name


class DnsQType(_TypeMixin, IntEnum):
    """QTYPE: every RR type, plus the query-only pseudo-types 252-255.

    The values repeat :class:`DnsRType` on purpose -- writing both tables out
    keeps ``DnsQType.SOA`` resolvable by a type checker, and
    ``tests/test_enums.py`` asserts that the QTYPE table is a strict superset of
    the RTYPE table so they cannot drift apart. ``AXFR``, ``MAILB``, ``MAILA``
    and ``ANY`` exist only in a question (RFC 1035 sections 3.2.3, 6), and
    ``IXFR``/``TKEY``/``TSIG``/``OPT`` are RR-adjacent but not zone data.
    """

    A = 1
    NS = 2
    MD = 3
    MF = 4
    CNAME = 5
    SOA = 6
    MB = 7
    MG = 8
    MR = 9
    NULL = 10
    WKS = 11
    PTR = 12
    HINFO = 13
    MINFO = 14
    MX = 15
    TXT = 16
    RP = 17
    AFSDB = 18
    X25 = 19
    ISDN = 20
    RT = 21
    NSAP = 22
    NSAP_PTR = 23
    SIG = 24
    KEY = 25
    PX = 26
    GPOS = 27
    AAAA = 28
    LOC = 29
    NXT = 30
    EID = 31
    NIMLOC = 32
    SRV = 33
    ATMA = 34
    NAPTR = 35
    KX = 36
    CERT = 37
    A6 = 38
    DNAME = 39
    SINK = 40
    OPT = 41
    APL = 42
    DS = 43
    SSHFP = 44
    IPSECKEY = 45
    RRSIG = 46
    NSEC = 47
    DNSKEY = 48
    DHCID = 49
    NSEC3 = 50
    NSEC3PARAM = 51
    TLSA = 52
    SMIMEA = 53
    HIP = 55
    NINFO = 56
    RKEY = 57
    TALINK = 58
    CDS = 59
    CDNSKEY = 60
    OPENPGPKEY = 61
    CSYNC = 62
    ZONEMD = 63
    SVCB = 64
    HTTPS = 65
    SPF = 99
    UINFO = 100
    UID = 101
    GID = 102
    UNSPEC = 103
    NID = 104
    L32 = 105
    L64 = 106
    LP = 107
    EUI48 = 108
    EUI64 = 109
    TKEY = 249
    TSIG = 250
    IXFR = 251  # query-only: RFC 1995
    AXFR = 252  # query-only: RFC 1035 section 6
    MAILB = 253  # query-only: MB-type wildcard (RFC 1035 section 3.2.3)
    MAILA = 254  # query-only: MB-type wildcard (RFC 1035 section 3.2.3)
    ANY = 255  # query-only wildcard (RFC 1035 section 3.2.3)
    URI = 256
    CAA = 257
    TA = 32768
    DLV = 32769
    Reserved = 65535

    def __repr__(self) -> str:
        return self.name
