"""EDNS(0) options: the type-length-value records inside an OPT RDATA.

RFC 6891 section 6.1.2 keeps the wire format small enough to state in one
sentence -- a 16-bit OPTION-CODE, a 16-bit OPTION-LENGTH, then that many
octets -- and puts the entire burden of meaning on the registry:

    OPTION-CODE  16 bits
    OPTION-LENGTH  16 bits
    OPTION-DATA  variable length

Four codes are modelled here, because those are the four whose rules are
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
* **ERROR (15)**, RFC 8914. Two octets of INFO-CODE followed by EXTRA-TEXT, and
  the whole option is built to be read by a human: section 2 says the text "is
  intended for human consumption (not automated parsing)", that it "may be null
  terminated but MUST NOT be assumed to be", and that "the length MUST be derived
  from the OPTION-LENGTH field" -- which is why :attr:`ExtendedDNSError.extra_text`
  keeps exactly the octets the option carried, and why the display helper
  :meth:`~ExtendedDNSError.text` is the only place a trailing NUL is dropped.
  Receiving is deliberately tolerant, because section 3 is emphatic about it:
  "Receivers MUST be able to accept EDE codes and EXTRA-TEXT in all messages,
  including those with a NOERROR RCODE but need not act on them", and "Senders MAY
  include more than one EDE option and receivers MUST be able to accept (but not
  necessarily process or act on) multiple EDE options". So
  :func:`extended_errors_of` returns *all* of them and raises nothing. What it must
  not do is change an answer: section 3's "Applications MUST continue to follow
  requirements from applicable specifications on how to process RCODEs no matter
  what EDE values are also received", and section 6's "MUST NOT alter DNS protocol
  processing", together mean no caller may branch on an INFO-CODE.

The registry is wider than this module and the rule for what is not in it is
explicit (section 6.1.2): "Any OPTION-CODE values not understood by a responder
or requestor MUST be ignored." So an unknown option is *kept* here --
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
* RFC 8914 section 2 (the ERROR option's format and its EXTRA-TEXT rules),
  section 3 (multiple options, tolerance, and the rule that EDE never changes
  RCODE processing), sections 4.1-4.25 and 5.2 (the INFO-CODE registry), section
  6 (why EDE is unauthenticated and diagnostic only)
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
    "ERROR_OPTION_CODE",
    "EXTENDED_ERROR_INFO_OCTETS",
    "EXTENDED_ERROR_PRIVATE_USE_MIN",
    "MAX_EDNS_OPTION_OCTETS",
    "MAX_EXTENDED_ERROR_CODE",
    "NSID_OPTION_CODE",
    "PADDING_OPTION_CODE",
    "EdnsOption",
    "ExtendedDNSError",
    "client_cookie_of",
    "cookie_length_valid",
    "extended_dns_error_option",
    "extended_error_name",
    "extended_error_option_valid",
    "extended_error_presentation",
    "extended_errors_of",
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

#: OPTION-CODE 15. RFC 8914 section 5.1 registers it as "Extended DNS Error", and
#: section 2 then calls it EDE throughout ("The Extended DNS Error (EDE) option can
#: be included in any response"), so the short form is what gets printed.
ERROR_OPTION_CODE = 15

#: The INFO-CODE is "16 bits, which is the principal contribution of this
#: document" (RFC 8914 section 2) -- also the largest code the field can hold.
MAX_EXTENDED_ERROR_CODE = 0xFFFF

#: Octets of INFO-CODE, the only part of an EDE option that is not optional:
#: section 2 allows EXTRA-TEXT to be "zero octets in length" but always expects an
#: INFO-CODE, so an option shorter than this carries nothing that can be read.
EXTENDED_ERROR_INFO_OCTETS = 2

#: RFC 8914 section 5.2, Table 2 splits the field: "0 - 49151 | First Come First
#: Served" and "49152 - 65535 | Private Use". A code at or above this is not
#: undefined, it is somebody else's meaning -- which is why an unregistered code
#: still prints as a number instead of being rejected.
EXTENDED_ERROR_PRIVATE_USE_MIN = 49152

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
    ERROR_OPTION_CODE: "EDE",
}

#: The "Extended DNS Error Codes" registry as RFC 8914 section 5.2 Table 3
#: populates it, with the Purpose column's wording kept verbatim -- a code that
#: prints as something other than the name the registry gives it is a code whose
#: meaning this project invented. Codes 25-49151 are "Unassigned" and 49152-65535
#: "Reserved for Private Use" (§5.2 Table 2), so they are absent here on purpose
#: and print as their number.
_EXTENDED_ERROR_NAMES = {
    0: "Other Error",
    1: "Unsupported DNSKEY Algorithm",
    2: "Unsupported DS Digest Type",
    3: "Stale Answer",
    4: "Forged Answer",
    5: "DNSSEC Indeterminate",
    6: "DNSSEC Bogus",
    7: "Signature Expired",
    8: "Signature Not Yet Valid",
    9: "DNSKEY Missing",
    10: "RRSIGs Missing",
    11: "No Zone Key Bit Set",
    12: "NSEC Missing",
    13: "Cached Error",
    14: "Not Ready",
    15: "Blocked",
    16: "Censored",
    17: "Filtered",
    18: "Prohibited",
    19: "Stale NXDomain Answer",
    20: "Not Authoritative",
    21: "Not Supported",
    22: "No Reachable Authority",
    23: "Network Error",
    24: "Invalid Data",
}


def extended_error_name(info_code: int) -> str:
    """The registry name of ``info_code``, or its number if it is unregistered.

    The same rule as :func:`option_name`: a code this project has no entry for is
    somebody else's meaning -- unassigned space, or the 49152-65535 private-use
    range RFC 8914 section 5.2 reserves for it -- so it prints as a number rather
    than a guess.
    """
    return _EXTENDED_ERROR_NAMES.get(int(info_code), str(int(info_code)))


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


class ExtendedDNSError:
    """One Extended DNS Error: an INFO-CODE and the EXTRA-TEXT sent with it.

    RFC 8914 section 2 asks very little of either part. The code "serves as an
    index into the 'Extended DNS Errors' registry" and nothing more; the text "is
    intended for human consumption (not automated parsing)". So this class reads
    the two fields and interprets neither -- there is no :attr:`name`-driven
    behaviour to hang off a code, because section 3 forbids the inference:
    "systems interpreting the extended error codes MUST NOT assume that a
    combination will make sense", and the same section's "Applications MUST
    continue to follow requirements from applicable specifications on how to
    process RCODEs no matter what EDE values are also received" is what keeps this
    a diagnostic object rather than a decision one.

    The two octets of INFO-CODE are the only mandatory part -- section 2 allows
    EXTRA-TEXT to be "zero octets in length" -- and :attr:`extra_text` holds
    exactly the octets the option carried, which is what "the length MUST be
    derived from the OPTION-LENGTH field" asks for. Anything prettier than that,
    including dropping a trailing NUL, belongs to the reader: see :attr:`text`.
    """

    __slots__ = ("extra_text", "info_code")

    def __init__(self, info_code: int, extra_text: bytes = b""):
        code = int(info_code)
        if not 0 <= code <= MAX_EXTENDED_ERROR_CODE:
            raise ValueError(f"extended error INFO-CODE out of range: {info_code}")
        payload = bytes(extra_text)
        limit = MAX_EDNS_OPTION_OCTETS - EXTENDED_ERROR_INFO_OCTETS
        if len(payload) > limit:
            raise ValueError(
                f"extended error EXTRA-TEXT is {len(payload)} octets, over the "
                f"{limit} that fit beside an INFO-CODE in a 16-bit OPTION-LENGTH"
            )
        self.info_code = code
        self.extra_text = payload

    @property
    def name(self) -> str:
        """The registry name of this code, for display only."""
        return extended_error_name(self.info_code)

    @property
    def private_use(self) -> bool:
        """Whether this code sits in the range RFC 8914 section 5.2 reserves for
        private use -- unregistered, but not a mistake."""
        return self.info_code >= EXTENDED_ERROR_PRIVATE_USE_MIN

    @property
    def octets(self) -> bytes:
        """The option's payload: INFO-CODE then EXTRA-TEXT (RFC 8914 section 2)."""
        return struct.pack("!H", self.info_code) + self.extra_text

    @property
    def option(self) -> EdnsOption:
        """This error as the EDNS(0) option that carries it."""
        return EdnsOption(ERROR_OPTION_CODE, self.octets)

    @property
    def text(self) -> str:
        """EXTRA-TEXT decoded for a human, never for a parser.

        Two decisions, both from RFC 8914. Section 2's "EDE text may be null
        terminated but MUST NOT be assumed to be" means a trailing NUL is a
        convention some senders follow, so this drops one -- from the *display*
        only, never from :attr:`extra_text`, which stays the exact octets the
        OPTION-LENGTH described. And because EXTRA-TEXT arrives from whoever ran
        the server, decoding cannot be allowed to fail: an invalid sequence
        becomes U+FFFD rather than an exception, since section 6 insists EDE "MUST
        NOT alter DNS protocol processing" and a UnicodeDecodeError on the way to
        an answer is exactly that alteration.
        """
        decoded = self.extra_text.decode("utf-8", errors="replace")
        if decoded.endswith("\x00"):
            decoded = decoded[:-1]
        return decoded

    def __eq__(self, other) -> bool:
        if not isinstance(other, ExtendedDNSError):
            return NotImplemented
        return self.info_code == other.info_code and self.extra_text == other.extra_text

    def __hash__(self) -> int:
        return hash((self.info_code, self.extra_text))

    def __repr__(self) -> str:
        shown = extended_error_presentation(self)
        return f"<ExtendedDNSError {shown}>"


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


#: How much EXTRA-TEXT a single line of output will carry. RFC 8914 section 3
#: tells senders to keep it short -- "implementers and operators creating EDE
#: options SHOULD avoid lengthy EXTRA-TEXT contents", because long text triggers
#: the truncation the same paragraph is about -- so a receiver that prints all of
#: it is displaying a thing the specification discourages sending. The cap is
#: applied on display, never to :attr:`ExtendedDNSError.extra_text`.
_TEXT_PRESENTATION_LIMIT = 96


def extended_dns_error_option(info_code: int, extra_text: bytes = b"") -> EdnsOption:
    """An ERROR option carrying ``info_code`` and, optionally, ``extra_text``.

    The text is for a human: RFC 8914 section 2 says so outright, and warns
    against putting "private information in the EXTRA-TEXT field that an observer
    would not otherwise have access to" -- this is a plain-UDP option, so anything
    written here is published to whoever can see the response.
    """
    return ExtendedDNSError(info_code, extra_text).option


def extended_error_option_valid(option: EdnsOption) -> bool:
    """Whether an ERROR option is long enough to hold an INFO-CODE.

    This is the one judgement a responder may make about an EDE option, and it is
    RFC 6891 section 7's, not RFC 8914's: "an option value that is badly formatted
    or that includes out-of-range values" earns a FORMERR. One octet cannot be an
    INFO-CODE, so it is badly formatted. Anything longer than that is *somebody's*
    meaning -- unassigned or private-use codes included, which RFC 8914 section
    5.2 sanctions -- and section 3's "Receivers MUST be able to accept EDE codes
    and EXTRA-TEXT in all messages" forbids grading it.
    """
    return len(option.data) >= EXTENDED_ERROR_INFO_OCTETS


def extended_errors_of(options) -> tuple[ExtendedDNSError, ...]:
    """Every Extended DNS Error in ``options``, in the order they arrived.

    All of them, because RFC 8914 section 3 makes plurality legal in both
    directions: "Senders MAY include more than one EDE option and receivers MUST
    be able to accept (but not necessarily process or act on) multiple EDE options
    in a DNS message." Returning the first would be a policy about which error
    matters, and this module has no standing to make one.

    Raises nothing, including on a malformed option, which it skips. That is
    deliberate and it is not the same question as :func:`extended_error_option_valid`
    answers: a *responder* judges a request's options and may answer FORMERR,
    while a *receiver* of an answer must let the option's badness stop at the
    option -- section 6's "EDE content should be treated only as diagnostic
    information and MUST NOT alter DNS protocol processing".
    """
    errors = []
    for option in options:
        if option.code != ERROR_OPTION_CODE:
            continue
        if not extended_error_option_valid(option):
            continue
        info_code = struct.unpack_from("!H", option.data)[0]
        errors.append(ExtendedDNSError(info_code, option.data[EXTENDED_ERROR_INFO_OCTETS:]))
    return tuple(errors)


def _presentation_text(text: str) -> str:
    """EXTRA-TEXT made safe to put on a terminal, and short enough to read.

    EXTRA-TEXT is written by whoever ran the server, and RFC 8914 section 6 is
    blunt about what that means: "EDE information is unauthenticated information,
    unless secured by a form of secured DNS transaction" and "An attacker (e.g., a
    man in the middle (MITM) or malicious recursive server) could insert an
    extended error response into untrusted data". So control characters -- the
    ones that move a cursor or clear a screen -- are escaped rather than emitted,
    and the line is capped per :data:`_TEXT_PRESENTATION_LIMIT`. The cap cuts the
    text before escaping, so an escape sequence is never chopped in half.
    """
    truncated = text[:_TEXT_PRESENTATION_LIMIT]
    if len(text) > _TEXT_PRESENTATION_LIMIT:
        truncated += "..."
    escaped = []
    for character in truncated:
        code = ord(character)
        if code < 0x20 or code == 0x7F:
            escaped.append(f"\\x{code:02x}")
        else:
            escaped.append(character)
    return "".join(escaped)


def extended_error_presentation(error: ExtendedDNSError) -> str:
    """One readable line for an EDE: ``22 (No Reachable Authority): source=us``.

    The number leads because it is the only part with a definition; the name in
    parentheses is this project's copy of the RFC 8914 section 5.2 registry, and
    appears only when there is one. Text follows a colon, escaped and capped by
    :func:`_presentation_text`.
    """
    label = str(error.info_code)
    name = error.name
    if name != label:
        label = f"{label} ({name})"
    text = error.text
    if not text:
        return label
    return f"{label}: {_presentation_text(text)}"
