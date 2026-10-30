"""MQTYPE: asking several QTYPEs in one exchange (RFC 10029).

A client that wants a name's A, AAAA and HTTPS records normally sends three
queries, and an iterative resolver walks the same servers three times to answer
them. RFC 10029 fixes that without touching the Question section -- QDCOUNT stays
one, and RFC 9619's "In the DNS, QDCOUNT Is (Usually) One" argument survives
untouched. Instead the extra types ride in an EDNS(0) option:

    OPTION-CODE     MQTYPE-Query (20) in queries, MQTYPE-Response (21) in answers
    OPTION-LENGTH   2 * n
    OPTION-DATA     QT1 ... QTn, each a 2-octet RRTYPE in network order

The asymmetry of the two codes is the design, not an accident. Section 3.3 makes
an inbound MQTYPE-Response a FORMERR on its own, so a responder's list cannot
share a code with a requestor's; and section 3.5 makes the *absence* of a
MQTYPE-Response the way a server says "I do not support this", so an option that
answered a query with the same number the query used could not tell a
non-supporting server from a supporting one that happened to agree.

**Two lists, and only one of them may be empty.** Section 3.3 requires FORMERR for
"an MQTYPE-Query option with an empty QT list", while section 3.4 says the opposite
of the answer: "Note that it is possible for the resulting MQTYPE-Response option to
contain an empty list, but as described above, the option must still be returned."
An empty answer means "I do support this, and I combined nothing" -- section A.3's
DS-plus-NS example is exactly that, because the DS is authoritative and the NS at
the parent is not. This module therefore has two constructors rather than one that
takes a flag, because the flag would be a standing invitation to apply the wrong
rule.

**Absence is not a negative answer**, which is the trap in this extension. A QTx
missing from MQTYPE-Response means one of four things, and section 3.5 lists them
without choosing: the recursive server had nothing in cache, the flags or RCODE
mismatched, the server was unwilling, or the response would have been too big. None
of them means NXDOMAIN or NODATA, so :func:`qtypes_still_needed` exists to keep the
two apart -- "The client MUST subsequently initiate separate standalone queries for
all QTx values for which an answer is still required."

.. rubric:: References

* RFC 10029 section 3.1 (the two option codes and the QT list format), section 3.2
  (a client MUST generate packets conforming to the section 3.3 parsing rules),
  section 3.3 (the eight conditions that oblige a server to answer FORMERR),
  section 3.4 (response generation, including the empty list and the rule that the
  option must never itself cause truncation), section 3.5 (what a client does with a
  missing, present, or malformed answer), section 4 (amplification and operator
  limits), appendix A (worked examples used as the test oracle)
* RFC 6891 section 6.1.2 (option format), section 7 (FORMERR for a badly formatted
  option value, and the OPT record that must accompany it)
* RFC 6895 section 3.1 (the data/QTYPE/Meta partition every QTx is checked against;
  see :func:`namespy.enums.rrtype_class`)
* RFC 9619 (why QDCOUNT is one, and why this extension does not change that)
"""

import struct

from .edns import (
    MQTYPE_QUERY_OPTION_CODE,
    MQTYPE_RESPONSE_OPTION_CODE,
    EdnsOption,
)
from .enums import DnsOpCode, is_data_rrtype, rrtype_class
from .wire import DnsPacketParseError

__all__ = [
    "MQTYPE_RECOMMENDED_QTX_LIMIT",
    "QTYPE_OCTETS",
    "mqtype_answered_qtypes",
    "mqtype_query_option",
    "mqtype_query_rejection",
    "mqtype_response_option",
    "mqtype_supported",
    "qtypes_of",
    "qtypes_still_needed",
]

#: Octets per QTx: "The OPTION-DATA is a list of 2-octet values in network order,
#: most significant bit (MSB) first" (RFC 10029 section 3.1). A payload that is not
#: a multiple of this is not a short list, it is a damaged one.
QTYPE_OCTETS = 2

#: RFC 10029 section 4: "Implementors SHOULD therefore allow operators to configure
#: limits on the number of QTx values specified and/or the resulting response size.
#: ... In public DNS, it is expected that a limit of four QTx values would be
#: appropriate, but when used with DNS-SD or within private networks, higher limits
#: would be acceptable."
#:
#: Offered as a number, never enforced here. Silently dropping the fifth type a
#: caller asked for would be the library making a policy decision the RFC assigns to
#: an operator, and failing closed instead would break the DNS-SD deployment the
#: same paragraph blesses. A server that wants a limit should compare against this
#: and answer for itself, with the reason in an EDE option.
MQTYPE_RECOMMENDED_QTX_LIMIT = 4


def _offence(qtypes, *, primary_qtype=None, empty_allowed: bool) -> str | None:
    """Why this QT list may not be sent, or ``None`` if it may.

    Section 3.3's conditions, applied on the *sending* side. That placement is what
    section 3.2 asks for -- "DNS clients implementing this specification MUST
    generate packets that conform to the server request parsing rules described in
    Section 3.3" -- and the consequence is worth stating plainly: a caller cannot
    build a message that a conforming server is obliged to refuse.

    Returns the reason as a short string rather than raising so that the same helper
    can serve :func:`mqtype_query_rejection`, which has to report a reason rather
    than abort.
    """
    values = tuple(int(qtype) for qtype in qtypes)
    if not values:
        return None if empty_allowed else "empty QT list"
    if len(values) != len(set(values)):
        return "duplicate QTx"
    for value in values:
        if not 0 <= value <= 0xFFFF:
            return f"QTx {value} outside the 16-bit field"
        if not is_data_rrtype(value):
            return f"QTx {value} is a {rrtype_class(value)} RRTYPE, not a data one"
    if primary_qtype is not None and int(primary_qtype) in values:
        return f"QTx duplicates the primary QTYPE ({primary_qtype})"
    return None


def mqtype_query_option(qtypes, *, primary_qtype=None) -> EdnsOption:
    """A MQTYPE-Query option asking for ``qtypes`` alongside the primary question.

    ``primary_qtype`` is optional because a caller that builds the option before it
    knows the question may legitimately omit it, but passing it is what makes
    section 3.3's last condition checkable -- "A duplicate QTx (or one duplicating
    the primary QTYPE field) in a query" is a FORMERR, and asking a server for the
    type the Question section already asks for wastes the exchange this extension
    exists to save.

    Raises :exc:`ValueError` carrying the section 3.3 reason. An empty list raises,
    per section 3.3; use :func:`mqtype_response_option` for the empty list that *is*
    legal, which is an answer.
    """
    reason = _offence(qtypes, primary_qtype=primary_qtype, empty_allowed=False)
    if reason is not None:
        raise ValueError(f"cannot send a MQTYPE-Query option: {reason}")
    return EdnsOption(MQTYPE_QUERY_OPTION_CODE, _serialise(qtypes))


def mqtype_response_option(qtypes=()) -> EdnsOption:
    """A MQTYPE-Response option listing the QTYPEs that were fully combined.

    Empty is legal and meaningful: section 3.4 allows the list to be empty while
    still requiring "the option must still be returned", because the option's
    presence is what tells the client the server supports the extension at all.
    Section A.3's figure is that case -- a recursive DS query with an extra NS
    request, where the NS answer is not authoritative at the parent so nothing could
    be merged.

    Still refuses duplicates, because section 3.5 makes a client discard an answer
    whose list repeats a QTx, and a server that cannot produce a list its own
    clients accept has no business sending one.
    """
    reason = _offence(qtypes, empty_allowed=True)
    if reason is not None:
        raise ValueError(f"cannot send a MQTYPE-Response option: {reason}")
    return EdnsOption(MQTYPE_RESPONSE_OPTION_CODE, _serialise(qtypes))


def _serialise(qtypes) -> bytes:
    """The QT list as octets: each QTYPE as ``!H``, concatenated (section 3.1)."""
    return b"".join(struct.pack("!H", int(qtype)) for qtype in qtypes)


def qtypes_of(option: EdnsOption) -> tuple[int, ...]:
    """The QTYPEs listed in a MQTYPE option, in the order they arrived.

    Order is preserved and not sorted, because section 3.4 lets a server "stop
    processing further QTx combinations" once the response gets large -- the order
    is then a fact about what the server did, and sorting it would invent a
    canonical form the wire does not have.

    Raises :exc:`~namespy.wire.DnsPacketParseError` on a payload that is not a whole
    number of 2-octet values. That is RFC 6891 section 7's "option value that is
    badly formatted", and it is deliberately not repaired by dropping the odd octet:
    a truncated list would read as a server that declined the last type rather than
    one whose message came apart.
    """
    data = bytes(option.data)
    if len(data) % QTYPE_OCTETS:
        raise DnsPacketParseError(
            f"{option.name} option is {len(data)} octets, not a whole number of "
            f"{QTYPE_OCTETS}-octet QTYPEs"
        )
    return tuple(
        struct.unpack_from("!H", data, offset)[0] for offset in range(0, len(data), QTYPE_OCTETS)
    )


def _with_code(options, code: int) -> list[EdnsOption]:
    return [option for option in options if option.code == code]


def mqtype_query_rejection(
    options,
    *,
    opcode: int = 0,
    qdcount: int = 1,
    primary_qtype: int | None = None,
) -> str | None:
    """Why a server must answer FORMERR, or ``None`` if nothing is wrong.

    RFC 10029 section 3.3, all eight conditions, in the order the document lists
    them, on top of "the error cases discussed in Section 7 of [RFC6891]":

    1. a MQTYPE-Query option in a message whose OPCODE is not QUERY (0);
    2. a MQTYPE-Response option in any inbound message;
    3. more than one MQTYPE-Query option;
    4. a MQTYPE-Query with no primary question (QDCOUNT = 0);
    5. a MQTYPE-Query whose primary question is a non-data RRTYPE (ANY, AXFR);
    6. a MQTYPE-Query option with an empty QT list;
    7. an invalid QTx, e.g. one corresponding to a Meta RRTYPE;
    8. a duplicate QTx, or one duplicating the primary QTYPE.

    Conditions 6 to 8 are the list itself and are shared with the sending side
    through :func:`_offence`, which is how the module keeps one definition of
    "valid" rather than two that can drift apart.

    Never raises, including on a payload whose length is not a whole QTYPE: that is
    simply the badly-formatted-option case, and it belongs in the list of reasons
    rather than escaping as an exception a caller has to remember to catch. Returns
    the reason as a string so the caller chooses its own posture -- this is a
    *receiving* rule, and a receiver may reasonably ignore what it cannot honour.
    See :mod:`namespy.server` for the posture this project's server takes and why.
    """
    queries = _with_code(options, MQTYPE_QUERY_OPTION_CODE)
    if _with_code(options, MQTYPE_RESPONSE_OPTION_CODE):
        # Condition 2, checked before the others even when a Query option is present
        # too: it is the only one that says "any inbound DNS message" rather than "in
        # a query", so it holds whatever else is true of the message.
        return "MQTYPE-Response option in an inbound message"
    if not queries:
        return None
    if int(opcode) != int(DnsOpCode.QUERY):
        return f"MQTYPE-Query option with opcode {opcode}, not QUERY"
    if len(queries) > 1:
        return f"{len(queries)} MQTYPE-Query options in one query"
    if qdcount == 0:
        return "MQTYPE-Query option with no primary question (QDCOUNT=0)"
    if primary_qtype is not None and not is_data_rrtype(primary_qtype):
        return f"MQTYPE-Query option with a non-data primary question ({primary_qtype})"
    try:
        qtypes = qtypes_of(queries[0])
    except DnsPacketParseError as exc:
        return str(exc)
    return _offence(qtypes, primary_qtype=primary_qtype, empty_allowed=False)


def mqtype_supported(response_options) -> bool:
    """Whether an answer came from a server that supports MQTYPE.

    Section 3.5, first paragraph: "If the response to a query containing an
    MQTYPE-Query option does not contain an MQTYPE-Response option, or if it
    erroneously contains an MQTYPE-Query option, the client MUST treat the response
    as if this option is unsupported by the server and MUST process the primary
    response as if the MQTYPE-Query option had not been used."

    The distinction that matters is the one between this function and
    :func:`mqtype_answered_qtypes`. Unsupported is a *normal* outcome -- most servers
    do not implement the extension yet, the primary answer is still good, and the
    only cost is the extra queries section 3.5 asks for. Malformed is not normal: the
    server claimed support and then contradicted itself, so the answer cannot be
    trusted at all. A function returning ``False`` for both would quietly turn
    "discard this response" into "ask somewhere else", which is how a protocol bug
    becomes a resolution that never ends.
    """
    if _with_code(response_options, MQTYPE_QUERY_OPTION_CODE):
        return False
    return bool(_with_code(response_options, MQTYPE_RESPONSE_OPTION_CODE))


def mqtype_answered_qtypes(response_options, *, primary_qtype: int | None = None):
    """The QTYPEs a supporting server fully combined into this answer.

    Call it only after :func:`mqtype_supported` says the server supports the
    extension; what went out is compared with what came back by
    :func:`qtypes_still_needed`, which is the caller's own record of the request.

    Raises :exc:`~namespy.wire.DnsPacketParseError` for the three conditions section
    3.5 groups together -- "If the MQTYPE-Response option is present more than once
    or if a QTx value is duplicated (or duplicates the primary QTYPE field), the
    client MUST treat the answer as invalid (equivalent to FORMERR)". Those are not
    an unsupported server: it answered, and answered self-contradictorily, which is
    why the consequence is throwing the response away rather than falling back.

    A QTx that is merely *absent* is not an error and raises nothing. Section 3.5
    lists four innocent reasons for it; see :func:`qtypes_still_needed`.
    """
    responses = _with_code(response_options, MQTYPE_RESPONSE_OPTION_CODE)
    if len(responses) > 1:
        raise DnsPacketParseError(f"{len(responses)} MQTYPE-Response options in one answer")
    if not responses:
        raise DnsPacketParseError("answer carries no MQTYPE-Response option")
    qtypes = qtypes_of(responses[0])
    if len(qtypes) != len(set(qtypes)):
        raise DnsPacketParseError(f"duplicate QTx in MQTYPE-Response: {qtypes}")
    if primary_qtype is not None and int(primary_qtype) in qtypes:
        raise DnsPacketParseError(f"MQTYPE-Response repeats the primary QTYPE ({primary_qtype})")
    return qtypes


def qtypes_still_needed(requested, answered) -> tuple[int, ...]:
    """Which requested QTYPEs the answer did not cover, in the order they were asked.

    Section 3.5: "The client MUST subsequently initiate separate standalone queries
    for all QTx values for which an answer is still required", where the values still
    required are exactly those missing from MQTYPE-Response -- "Absence of QTx values
    that were requested by the client but are not present in the MQTYPE-Response
    option indicates that" one of four things, none of which is a negative answer
    about the name.

    So the result of this function is a work list, not a verdict, and a caller must
    not cache its members as NODATA. A server that could not fit the HTTPS records
    into the response has said nothing about whether the HTTPS RRset exists.
    """
    covered = {int(qtype) for qtype in answered}
    return tuple(int(qtype) for qtype in requested if int(qtype) not in covered)
