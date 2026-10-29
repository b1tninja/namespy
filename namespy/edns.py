"""EDNS(0) options: the type-length-value records inside an OPT RDATA.

RFC 6891 section 6.1.2 keeps the wire format small enough to state in one
sentence -- a 16-bit OPTION-CODE, a 16-bit OPTION-LENGTH, then that many
octets -- and puts the entire burden of meaning on the registry:

    OPTION-CODE  16 bits
    OPTION-LENGTH  16 bits
    OPTION-DATA  variable length

Three codes are modelled here, because those are the three whose rules are
short enough to enforce and whose absence is visible on the wire:

* **NSID (3)**, RFC 5001. A resolver asks by sending the option with no data
  -- "the resolver MUST NOT include any NSID payload data in the query
  message" (section 2.1) -- and the server answers with an opaque byte string
  identifying the instance that answered. Both halves of the asymmetry matter:
  a server "MUST ignore any NSID payload data that might be present in the
  query message" and "MUST NOT send an NSID option back to a resolver which
  did not request it" (section 2.2). The payload is opaque, which is exactly
  why RFC 5001 section 2.4 insists that a user interface shows it as
  hexadecimal -- two digits per octet -- rather than as text someone might try
  to interpret. :func:`nsid_presentation` is that rule.
* **COOKIE (10)**, RFC 7873. Client Cookie (8 octets) plus an optional Server
  Cookie of 8 to 32, so a legal COOKIE option is 8 octets or 16 to 40 of them
  -- section 5.2.2 lists exactly those lengths and makes a request carrying any
  other one a FORMERR. A client seeing an illegal length or a Client Cookie it
  did not send "MUST discard the response" (section 5.3), which is a rule about
  receiving, so it lives with the validator here rather than with the sender.
* **PADDING (12)**, RFC 7830. A request carrying it asks the responder to pad
  the reply up to the query size; section 4 makes that a MUST "unless doing so
  would violate the maximum UDP payload size", and section 6 then withdraws the
  whole option from unencrypted transport: "implementations MUST NOT use this
  option if the DNS transport is not encrypted." Both sentences are about the
  same option, and DNS over plain UDP is not encrypted, so a UDP responder obeys
  section 6 by *not* padding. The conflict is documented at the point of use in
  :mod:`namespy.server` rather than resolved silently.

The registry is wider than this module and the rule for what is not in it is
explicit (section 6.1.2): "Any OPTION-CODE values not understood by a responder
or requestor MUST be silently ignored." So an unknown option is *kept* here --
it is data a debugger wants -- and no code path treats its presence as an
error. A malformed one is the exception, and section 7 handles it: "If there is
a problem with processing the OPT record itself, such as an option value that
is badly formatted or that includes out-of-range values, a FORMERR MUST be
returned. If this occurs, the response MUST include an OPT record."

.. rubric:: References

* RFC 6891 section 6.1.2 (option format, ignore unknown codes), section 6.2.4
  (a responder's advertised size is an upper bound on what it will send)
* RFC 5001 sections 2.1-2.4 (NSID format, request and response rules,
  presentation format)
* RFC 7873 sections 5.2-5.3 (COOKIE lengths and when a response must be
  discarded)
* RFC 7830 sections 3-4, 6 (padding format and when it, and the option, is
  mandatory or forbidden)
"""

import struct

from .wire import DnsPacketParseError

__all__ = [
    "COOKIE_CLIENT_OCTETS",
    "COOKIE_MAX_OCTETS",
    "COOKIE_MIN_OCTETS",
    "COOKIE_MIN_SERVER_TOTAL_OCTETS",
    "COOKIE_OPTION_CODE",
    "EDNS_OPTION_HEADER_OCTETS",
    "MAX_EDNS_OPTION_OCTETS",
    "NSID_OPTION_CODE",
    "PADDING_OPTION_CODE",
    "EdnsOption",
    "client_cookie_of",
    "cookie_length_valid",
    "find_option",
    "nsid_of",
    "nsid_option",
    "nsid_presentation",
    "option_name",
    "pad_option",
    "parse_options",
    "serialize_options",
    "server_cookie_of",
]

#: Octets in an OPTION-CODE and an OPTION-LENGTH, i.e. the fixed part of one
#: option (RFC 6891 section 6.1.2).
EDNS_OPTION_HEADER_OCTETS = 4

#: An OPTION-LENGTH is a 16-bit field, so no single option can exceed this.
MAX_EDNS_OPTION_OCTETS = 0xFFFF

#: OPTION-CODE 3, "Name Server Identifier" (RFC 5001 section 2.3).
NSID_OPTION_CODE = 3

#: OPTION-CODE 10, "DNS Cookie" (RFC 7873 section 8).
COOKIE_OPTION_CODE = 10

#: OPTION-CODE 12, "EDNS Padding" (RFC 7830 section 3 assigns it; section 5 is
#: the IANA record).
PADDING_OPTION_CODE = 12

#: The Client Cookie is always this long (RFC 7873 section 4, Figure 1: "Client
#: Cookie (fixed size, 8 bytes)").
COOKIE_CLIENT_OCTETS = 8

#: Smallest legal COOKIE option: a Client Cookie alone, the form a client sends
#: to a server whose Server Cookie it does not have yet.
COOKIE_MIN_OCTETS = COOKIE_CLIENT_OCTETS

#: A Client Cookie plus the smallest possible Server Cookie (RFC 7873
#: section 4, Figure 2 -- the Server Cookie is "variable size, 8 to 32 bytes").
COOKIE_MIN_SERVER_TOTAL_OCTETS = COOKIE_CLIENT_OCTETS + 8

#: A Client Cookie plus the largest Server Cookie, and so the largest COOKIE
#: option there is (RFC 7873 section 5.2.2).
COOKIE_MAX_OCTETS = 40

#: IANA-registered codes with a name worth printing. Anything else prints as
#: its number, because inventing a name for an unregistered code would be the
#: kind of guess this library keeps away from the wire.
_OPTION_NAMES = {
    NSID_OPTION_CODE: "NSID",
    COOKIE_OPTION_CODE: "COOKIE",
    PADDING_OPTION_CODE: "PADDING",
}


def option_name(code: int) -> str:
    """The registered name of ``code``, or its number if it is unregistered."""
    return _OPTION_NAMES.get(code, str(code))


class EdnsOption:
    """One EDNS(0) option: a code and the octets that belong to it.

    Deliberately dumb. The meaning of ``data`` belongs to whoever asked for the
    code, and an option that tried to interpret unknown payload would repeat a
    mistake this module makes a point of avoiding -- NSID in particular is
    specified as opaque precisely so that nobody reads a server's chassis
    number as a domain name.
    """

    __slots__ = ("code", "data")

    def __init__(self, code: int, data: bytes = b""):
        if not 0 <= int(code) <= 0xFFFF:
            raise ValueError(f"EDNS option code out of range: {code}")
        if len(data) > MAX_EDNS_OPTION_OCTETS:
            raise ValueError(
                f"EDNS option {code} is {len(data)} octets, over the 16-bit "
                f"OPTION-LENGTH limit of {MAX_EDNS_OPTION_OCTETS}"
            )
        self.code = int(code)
        self.data = bytes(data)

    @property
    def name(self) -> str:
        """The registered name of this option's code, for display only."""
        return option_name(self.code)

    @property
    def octets(self) -> bytes:
        """This option as it appears inside an OPT record's RDATA."""
        return struct.pack("!HH", self.code, len(self.data)) + self.data

    def __bytes__(self) -> bytes:
        return self.octets

    def __eq__(self, other) -> bool:
        if not isinstance(other, EdnsOption):
            return NotImplemented
        return self.code == other.code and self.data == other.data

    def __hash__(self) -> int:
        return hash((self.code, self.data))

    def __repr__(self) -> str:
        body = self.data.hex() if self.data else "-"
        return f"<EdnsOption {self.name}({self.code}) {body}>"


def parse_options(rdata_options: bytes) -> tuple[EdnsOption, ...]:
    """Split an OPT record's options field into :class:`EdnsOption`s.

    Raises :exc:`~namespy.wire.DnsPacketParseError` if an option header is cut
    short or an OPTION-LENGTH points past the end of the record. Both are "an
    option value that is badly formatted" in RFC 6891 section 7's phrase, and a
    responder's answer to that is FORMERR -- so the caller wants a
    distinguishable failure, not a silently shortened list.
    """
    options = []
    offset = 0
    total = len(rdata_options)
    while offset < total:
        if total - offset < EDNS_OPTION_HEADER_OCTETS:
            raise DnsPacketParseError(
                f"truncated EDNS option header: {total - offset} octet(s) left, "
                f"need {EDNS_OPTION_HEADER_OCTETS}"
            )
        code, length = struct.unpack_from("!HH", rdata_options, offset)
        offset += EDNS_OPTION_HEADER_OCTETS
        if length > total - offset:
            raise DnsPacketParseError(
                f"EDNS option {code} claims {length} octets, {total - offset} remain"
            )
        options.append(EdnsOption(code, rdata_options[offset : offset + length]))
        offset += length
    return tuple(options)


def serialize_options(options) -> bytes:
    """Concatenate ``options`` into the options part of an OPT record's RDATA.

    Raises :exc:`ValueError` if the total would not fit in the OPT record's
    16-bit RDLENGTH -- a caller that asks for that much padding has misread
    RFC 7830 section 4, which forbids padding past the advertised size anyway.
    """
    parts = [bytes(option) for option in options]
    total = sum(len(part) for part in parts)
    if total > MAX_EDNS_OPTION_OCTETS:
        raise ValueError(
            f"EDNS options total {total} octets, over the OPT RDLENGTH limit of "
            f"{MAX_EDNS_OPTION_OCTETS}"
        )
    return b"".join(parts)


def find_option(options, code: int) -> EdnsOption | None:
    """The first option with ``code``, or ``None``.

    First, not last, because that is the documented tie-break: RFC 7873
    section 5.2 says of a request holding several COOKIE options that "only the
    first (the one closest to the DNS header) COOKIE option is considered, any
    further COOKIE options are ignored", and section 5.3 repeats it for
    responses. RFC 6891 section 6.1.2 does not order options at all, so this is
    the only ordering rule available.
    """
    for option in options:
        if option.code == code:
            return option
    return None


def nsid_option(payload: bytes = b"") -> EdnsOption:
    """An NSID option -- empty for a query, carrying ``payload`` for a reply.

    Passing nothing is how a resolver asks: RFC 5001 section 2.1's "the resolver
    MUST NOT include any NSID payload data in the query message".
    """
    return EdnsOption(NSID_OPTION_CODE, payload)


def nsid_of(options) -> bytes | None:
    """The payload of the NSID option in ``options``, or ``None`` if there is none.

    On a query an NSID option carries no payload, so this returns ``b""`` --
    which is how a responder tells "asked" from "not asked" and why the empty
    bytes are kept distinct from :const:`None`. On a response, RFC 5001 section
    2.2 expects data; an NSID option with none is a server that has nothing to
    say about which instance it is.
    """
    option = find_option(options, NSID_OPTION_CODE)
    return None if option is None else option.data


def nsid_presentation(data: bytes) -> str:
    """NSID payload in the one form RFC 5001 allows a user interface to show.

    Section 2.4: "User interfaces MUST read and write the contents of the NSID
    option as a sequence of hexadecimal digits, two digits per payload octet."
    The payload is opaque, so anything prettier than hex would be an
    interpretation nobody had the standing to make.
    """
    return data.hex()


def cookie_length_valid(length: int) -> bool:
    """Whether a COOKIE option of ``length`` octets is legal.

    RFC 7873 section 5.2.2: "In summary, valid cookie lengths are 8 and 16 to 40
    inclusive." Eight is a Client Cookie with no Server Cookie -- the bootstrap
    case -- and the 16-to-40 band is that plus a Server Cookie of 8 to 32.
    Anything else is out of range, and RFC 6891 section 7 wants FORMERR for an
    option value "that includes out-of-range values".
    """
    return length == COOKIE_MIN_OCTETS or (
        COOKIE_MIN_SERVER_TOTAL_OCTETS <= length <= COOKIE_MAX_OCTETS
    )


def client_cookie_of(data: bytes) -> bytes:
    """The Client Cookie part of a COOKIE option's data (RFC 7873 section 4,
    Figure 1: the option always opens with eight octets of it)."""
    return data[:COOKIE_CLIENT_OCTETS]


def server_cookie_of(data: bytes) -> bytes:
    """The Server Cookie part, or ``b""`` when the option carries only a client one."""
    return data[COOKIE_CLIENT_OCTETS:]


def pad_option(size: int) -> EdnsOption:
    """A PADDING option of ``size`` octets, all zero.

    RFC 7830 section 3: "The PADDING octets SHOULD be set to 0x00." Other values
    MAY be used -- and "PADDING octets of any value MUST be accepted in the
    messages received" -- but non-zero octets are the case the RFC reserves for
    worrying about compression before encryption, which is not this problem.

    Reach for this on an encrypted transport. Section 6: "implementations MUST
    NOT use this option if the DNS transport is not encrypted", because padding
    on plain UDP hides nothing and only tells an observer how much traffic to
    expect.
    """
    if size < 0:
        raise ValueError(f"padding size cannot be negative: {size}")
    return EdnsOption(PADDING_OPTION_CODE, b"\x00" * size)
