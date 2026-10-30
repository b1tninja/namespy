"""MQTYPE (RFC 10029): the QT list, its validity rules, and both reading rules.

Appendix A supplies three worked examples, and they are used here as the oracle
rather than re-derived from the prose, because they pin down the three cases that a
naive implementation gets wrong in three different directions:

* **A.1** -- a query for A asking AAAA and HTTPS, answered with ``MQTYPE-Response:
  AAAA HTTPS``. The ordinary case, and the only one of the three where every
  requested type comes back.
* **A.2** -- a stub query for DS asking DNSKEY, answered with ``MQTYPE-Response:
  DNSKEY``. One requested type, so the list is a single 2-octet value; nothing in the
  format special-cases a list of one.
* **A.3** -- a recursive query for DS asking NS, answered with ``MQTYPE-Response:
  [empty]``. The response option is present, so the server supports MQTYPE, and the
  list is empty, so nothing was combined -- the DS is authoritative and the NS at the
  parent side of the zone cut is not, and section 3.4 forbids merging answers whose
  flags disagree. An implementation that read "empty list" as "does not support this"
  or as "no such records" is wrong twice over.

.. rubric:: References

* RFC 10029 section 3.1 (option format), section 3.2 (a client must generate
  conforming packets), section 3.3 (the eight FORMERR conditions), section 3.4 (the
  answer, including the empty list), section 3.5 (absent, present, and malformed
  answers read three different ways), appendix A (the figures above)
* RFC 6891 section 6.1.2 (unknown option codes must be ignored), section 7 (a badly
  formatted option value is a FORMERR)
* RFC 6895 section 3.1 (which numbers are data TYPEs, and which are not)
"""

import pytest

from namespy.edns import (
    MQTYPE_QUERY_OPTION_CODE,
    MQTYPE_RESPONSE_OPTION_CODE,
    EdnsOption,
    option_name,
    parse_options,
    serialize_options,
)
from namespy.enums import DnsQType
from namespy.mqtype import (
    MQTYPE_RECOMMENDED_QTX_LIMIT,
    mqtype_answered_qtypes,
    mqtype_query_option,
    mqtype_query_rejection,
    mqtype_response_option,
    mqtype_supported,
    qtypes_of,
    qtypes_still_needed,
)
from namespy.wire import DnsPacketParseError

# --------------------------------------------------------------------- the wire


def test_a_query_option_is_two_octets_per_type_in_network_order() -> None:
    """Section 3.1: "a list of 2-octet values in network order, MSB first"."""
    option = mqtype_query_option([DnsQType.AAAA, DnsQType.HTTPS])
    assert MQTYPE_QUERY_OPTION_CODE == option.code
    assert option.data == bytes([0x00, 0x1C, 0x00, 0x41]), "28 then 65, big-endian"
    assert option.octets.startswith(b"\x00\x14\x00\x04"), "code 20, length 4"


def test_the_option_survives_an_opt_record_round_trip() -> None:
    """The QT list must survive being packed into, and read out of, an OPT RDATA."""
    option = mqtype_query_option([DnsQType.DNSKEY], primary_qtype=DnsQType.DS)
    restored = parse_options(serialize_options([option]))
    assert (option,) == restored
    assert (DnsQType.DNSKEY,) == qtypes_of(restored[0])


def test_the_requested_order_survives() -> None:
    """Section 3.4 lets a server stop early once the response gets large, so the
    order the client chose is a fact about the exchange and must not be sorted."""
    requested = [DnsQType.HTTPS, DnsQType.AAAA, DnsQType.TXT]
    assert tuple(requested) == qtypes_of(mqtype_query_option(requested))


def test_an_odd_sized_payload_is_a_damaged_option() -> None:
    """Three octets is not "a list of one and a half types". Section 3.1 fixes the
    element size, so this is RFC 6891 section 7's badly-formatted option value, and
    repairing it by dropping the stray octet would invent a declined QTYPE."""
    with pytest.raises(DnsPacketParseError, match="not a whole number"):
        qtypes_of(EdnsOption(MQTYPE_QUERY_OPTION_CODE, b"\x00\x1c\x00"))


def test_both_codes_print_by_their_registry_names() -> None:
    """RFC 10029 section 5 registers the two names, and a debugger that prints "20"
    teaches a reader nothing they could not get from the number alone."""
    assert "MQTYPE-Query" == option_name(MQTYPE_QUERY_OPTION_CODE)
    assert "MQTYPE-Response" == option_name(MQTYPE_RESPONSE_OPTION_CODE)


# ----------------------------------------------------------- appendix A, figures


def test_a1_a_query_for_a_asking_aaaa_and_https() -> None:
    """Figure 3: the primary question is A, the option asks for two more, and the
    server's answer lists both -- the record case for the whole extension."""
    asked = mqtype_query_option([DnsQType.AAAA, DnsQType.HTTPS], primary_qtype=DnsQType.A)
    assert (DnsQType.AAAA, DnsQType.HTTPS) == qtypes_of(asked)

    answer = mqtype_response_option([DnsQType.AAAA, DnsQType.HTTPS])
    assert mqtype_supported([answer])
    answered = mqtype_answered_qtypes([answer], primary_qtype=DnsQType.A)
    assert (DnsQType.AAAA, DnsQType.HTTPS) == answered
    assert () == qtypes_still_needed([DnsQType.AAAA, DnsQType.HTTPS], answered)


def test_a2_a_query_for_ds_asking_dnskey() -> None:
    """Figure 4: one requested type is still a list, and DS-plus-DNSKEY is the
    pairing the extension exists for -- a stub validator needs both from one walk."""
    asked = mqtype_query_option([DnsQType.DNSKEY], primary_qtype=DnsQType.DS)
    assert b"\x00\x30" == asked.data

    answer = mqtype_response_option([DnsQType.DNSKEY])
    assert (DnsQType.DNSKEY,) == mqtype_answered_qtypes([answer], primary_qtype=DnsQType.DS)


def test_a3_an_empty_answer_list_still_means_the_server_supports_this() -> None:
    """Figure 5: ``MQTYPE-Response: [empty]``. The option is there, so the server
    implements RFC 10029; the list is empty, so it combined nothing. Both halves of
    that sentence must be true at once, which is why an empty MQTYPE-Response is
    constructible while an empty MQTYPE-Query is not."""
    empty = mqtype_response_option()
    assert MQTYPE_RESPONSE_OPTION_CODE == empty.code
    assert b"" == empty.data
    assert mqtype_supported([empty]), "presence is the support signal, not contents"
    assert () == mqtype_answered_qtypes([empty], primary_qtype=DnsQType.DS)
    assert (DnsQType.NS,) == qtypes_still_needed([DnsQType.NS], ()), (
        "the NS answer still has to be fetched, and its absence says nothing about the name"
    )


# ------------------------------------------------- section 3.2: sending something
# a conforming server would accept. Section 3.2 makes the client responsible for
# satisfying section 3.3's list, so the constructors enforce it and these tests are
# the same eight rules read from the sending end.


def test_a_query_cannot_ask_for_nothing() -> None:
    """Section 3.3: "An MQTYPE-Query option with an empty QT list" is a FORMERR. A
    client that cannot build one cannot send one."""
    with pytest.raises(ValueError, match="empty QT list"):
        mqtype_query_option([])


def test_a_query_cannot_ask_twice_for_one_type() -> None:
    """Section 3.3: "A duplicate QTx ... in a query"."""
    with pytest.raises(ValueError, match="duplicate QTx"):
        mqtype_query_option([DnsQType.AAAA, DnsQType.AAAA])


def test_a_query_cannot_ask_for_what_the_question_already_asks() -> None:
    """Section 3.3's parenthetical: "(or one duplicating the primary QTYPE field)".
    Only checkable once the primary is known, so it is opt-in -- and an omitted
    primary_qtype must not block the send, since a caller may build the option first.
    """
    with pytest.raises(ValueError, match="duplicates the primary"):
        mqtype_query_option([DnsQType.A], primary_qtype=DnsQType.A)
    assert b"\x00\x01" == mqtype_query_option([DnsQType.A]).data


@pytest.mark.parametrize(
    ("qtype", "why"),
    [
        (DnsQType.OPT, "meta"),  # 41, the Meta-RR hiding inside the data band
        (DnsQType.TKEY, "meta"),
        (DnsQType.TSIG, "meta"),
        (DnsQType.ANY, "query"),
        (DnsQType.AXFR, "query"),
        (DnsQType.IXFR, "query"),
        (0, "reserved"),  # section 3.1: "must never be allocated for ordinary use"
        (200, "reserved"),  # unassigned, and 128-255 is Q/Meta space
        (65280, "reserved"),  # private use is allocated to *somebody*, not to data
        (65535, "reserved"),  # "Reserved (Standards Action)"
    ],
)
def test_a_qtx_must_name_a_data_rrtype(qtype: int, why: str) -> None:
    """Section 3.1: each value "must be for a data RRTYPE as described in Section 3.1
    of [RFC6895]"; section 3.3 gives a Meta RRTYPE as an "e.g.", not the only kind. The
    reason names the category so an operator can see which rule fired."""
    with pytest.raises(ValueError, match=f"is a {why} RRTYPE"):
        mqtype_query_option([qtype])


def test_a_number_too_big_for_the_field_is_refused_before_the_classifier_sees_it() -> None:
    """QTYPE is a 16-bit field, so 65536 cannot name a type at all -- not even an
    unassigned one.

    The guard earns its place by sitting *in front of* the classifier:
    ``rrtype_class`` raises for an out-of-range number, and :func:`_offence` is shared
    with :func:`mqtype_query_rejection`, which promises never to raise. Without this
    check first, a caller's arithmetic slip would escape the receiver as an exception
    instead of arriving as one more reason to answer FORMERR.
    """
    for bad in (-1, 0x10000):
        with pytest.raises(ValueError, match="outside the 16-bit field"):
            mqtype_query_option([bad])


def test_a_type_this_project_has_never_heard_of_is_still_a_valid_qtx() -> None:
    """300 is unassigned today and sits in the band RFC 6895 section 3.1 allocates to
    data TYPEs, so it is a legitimate QTx. Refusing it would be RFC 3597 section 3's
    forbidden move -- treating an unknown type as an error -- and would break the next
    type to be assigned before this library is updated for it."""
    assert (300,) == qtypes_of(mqtype_query_option([300]))


def test_a_response_option_may_be_empty_but_not_repeated() -> None:
    """Section 3.4 permits an empty answer list while section 3.5 makes a client
    discard an answer that repeats one: both halves of the asymmetry in one call."""
    assert b"" == mqtype_response_option().data
    with pytest.raises(ValueError, match="duplicate QTx"):
        mqtype_response_option([DnsQType.A, DnsQType.A])


def test_the_public_dns_type_limit_is_offered_rather_than_enforced() -> None:
    """Section 4 asks implementors to let *operators* configure a limit, and expects
    four to be appropriate in public DNS. That is a server's knob, not a client
    library's: silently dropping a caller's fifth type would be this library making a
    policy choice the RFC assigns elsewhere."""
    assert 4 == MQTYPE_RECOMMENDED_QTX_LIMIT
    asked = [DnsQType.AAAA, DnsQType.HTTPS, DnsQType.TXT, DnsQType.SOA, DnsQType.MX]
    assert tuple(asked) == qtypes_of(mqtype_query_option(asked))


# ------------------------------------------- section 3.3: what a server must refuse


def test_a_query_with_nothing_mqtype_in_it_is_not_rejected() -> None:
    """The common case: an NSID request must not acquire a complaint about MQTYPE."""
    assert mqtype_query_rejection([EdnsOption(3, b"")]) is None


def test_an_option_this_server_does_not_know_is_still_ignored() -> None:
    """RFC 6891 section 6.1.2's "MUST be ignored" is not suspended by the existence of
    RFC 10029; a private code beside a valid MQTYPE-Query changes nothing."""
    options = [EdnsOption(0xFFF0, b"who knows"), mqtype_query_option([DnsQType.AAAA])]
    assert mqtype_query_rejection(options, primary_qtype=DnsQType.A) is None


@pytest.mark.parametrize(
    ("options", "opcode", "qdcount", "primary", "expect"),
    [
        pytest.param([mqtype_query_option([28])], 4, 1, DnsQType.A, "not QUERY", id="opcode"),
        pytest.param(
            [mqtype_response_option([28])], 0, 1, DnsQType.A, "inbound message", id="response-in"
        ),
        pytest.param(
            [mqtype_query_option([28]), mqtype_query_option([1])],
            0,
            1,
            DnsQType.A,
            "2 MQTYPE-Query",
            id="two-options",
        ),
        pytest.param([mqtype_query_option([28])], 0, 0, None, "QDCOUNT=0", id="no-question"),
        pytest.param(
            [mqtype_query_option([28])], 0, 1, DnsQType.AXFR, "non-data primary", id="axfr-primary"
        ),
        pytest.param([EdnsOption(20, b"")], 0, 1, DnsQType.A, "empty QT list", id="empty-list"),
        pytest.param([EdnsOption(20, b"\x00\xf9")], 0, 1, DnsQType.A, "meta RRTYPE", id="meta-qtx"),
        pytest.param(
            # Built by hand, because mqtype_query_option refuses to: a duplicate can
            # only ever arrive from somebody else's implementation.
            [EdnsOption(20, b"\x00\x1c\x00\x1c")],
            0,
            1,
            DnsQType.A,
            "duplicate QTx",
            id="duplicate-qtx",
        ),
        pytest.param(
            [mqtype_query_option([28])],
            0,
            1,
            DnsQType.AAAA,
            "duplicates the primary",
            id="primary-qtx",
        ),
        pytest.param(
            [EdnsOption(20, b"\x00\x1c\x00")], 0, 1, DnsQType.A, "whole number", id="ragged"
        ),
    ],
)
def test_every_section_3_3_condition_earns_a_formerr(options, opcode, qdcount, primary, expect):
    """All eight of section 3.3's bullets, plus the ragged-payload case RFC 6891
    section 7 covers. The function never raises, so a damaged option lands in the same
    stream of reasons as a semantically bad one."""
    reason = mqtype_query_rejection(options, opcode=opcode, qdcount=qdcount, primary_qtype=primary)
    assert reason is not None, "no condition may pass silently"
    assert expect in reason


# ------------------------------------- section 3.5: three outcomes, not two
#
# Absent, present-and-good, and present-but-contradictory are different commands to
# the client: fall back, use it, and throw it away. A two-valued reading of this is
# the main way to get the extension wrong, so the distinction gets its own tests.


def test_an_answer_without_the_option_is_unsupported_rather_than_wrong() -> None:
    """Section 3.5: no MQTYPE-Response means "not supported", and the primary answer
    stands -- "MUST process the primary response as if the MQTYPE-Query option had not
    been used". Nothing raised, because nothing went wrong."""
    plain = [EdnsOption(3, b"ns-1")]
    assert not mqtype_supported(plain)
    with pytest.raises(DnsPacketParseError, match="no MQTYPE-Response"):
        mqtype_answered_qtypes(plain)


def test_the_ordinary_server_still_has_all_its_work_left() -> None:
    """The overwhelmingly common case today: the server has never heard of RFC 10029,
    so every requested type must be re-asked on its own. Getting this wrong is how a
    name stops resolving for the second and third types."""
    assert (DnsQType.AAAA, DnsQType.HTTPS) == qtypes_still_needed(
        [DnsQType.AAAA, DnsQType.HTTPS], mqtype_answered_qtypes([mqtype_response_option()])
    )


def test_an_answer_carrying_the_query_option_back_is_unsupported() -> None:
    """Section 3.5 covers a server that echoes the request's option: "or if it
    erroneously contains an MQTYPE-Query option, the client MUST treat the response as
    if this option is unsupported". Misunderstood, not lying -- which is why it is not
    the invalid case, and the primary answer survives."""
    echoed = [mqtype_query_option([DnsQType.AAAA])]
    assert not mqtype_supported(echoed)


def test_a_partial_answer_leaves_the_rest_as_a_work_list() -> None:
    """Section 3.4 lets a server that runs out of room answer some types and omit
    others; the omitted ones are neither NODATA nor a refusal, just unfinished. Order
    follows the request, not the answer, because the caller is holding a plan."""
    answered = mqtype_response_option([DnsQType.AAAA])
    assert (DnsQType.HTTPS, DnsQType.TXT) == qtypes_still_needed(
        [DnsQType.AAAA, DnsQType.HTTPS, DnsQType.TXT], qtypes_of(answered)
    )


@pytest.mark.parametrize(
    ("options", "expect"),
    [
        pytest.param(
            [mqtype_response_option([28]), mqtype_response_option([1])],
            "2 MQTYPE-Response",
            id="twice",
        ),
        pytest.param([EdnsOption(21, b"\x00\x1c\x00\x1c")], "duplicate QTx", id="repeats-a-qtx"),
        pytest.param([mqtype_response_option([28])], "repeats the primary", id="repeats-primary"),
    ],
)
def test_an_answer_that_contradicts_itself_is_invalid_not_unsupported(options, expect) -> None:
    """Section 3.5's other branch: "If the MQTYPE-Response option is present more than
    once or if a QTx value is duplicated (or duplicates the primary QTYPE field), the
    client MUST treat the answer as invalid (equivalent to FORMERR)".

    The third case is only visible when a primary is supplied, since a QTx cannot
    duplicate a question nobody asked. Reading any of these as "not supported" would
    be the dangerous mistake: the server *did* claim support, so a client that fell
    back would go on using an answer it had been told to discard.
    """
    primary = DnsQType.AAAA if expect == "repeats the primary" else DnsQType.A
    assert mqtype_supported(options), "the server claimed support before contradicting itself"
    with pytest.raises(DnsPacketParseError, match=expect):
        mqtype_answered_qtypes(options, primary_qtype=primary)
