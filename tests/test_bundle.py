"""Reading a MQTYPE-Query answer (RFC 10029 section 3.5) without getting it wrong.

The codec is in ``test_mqtype.py`` and the responder in ``test_server.py``. What is
under test here is the client's *reading*, which is where the extension's one real trap
sits. Section 3.5 gives four reasons a requested QTx may be absent --

    *  (for responses from recursive servers) the server does not have any records for
       that QTx value in cache, and/or
    *  the individual responses could not be combined into one message because of RCODE
       or other flag mismatches, and/or
    *  the server was unwilling to process the request (for example, because a limit was
       exceeded), and/or
    *  the response size limit would be exceeded.

-- and none of the four is a negative answer about the name. An implementation that read
absence as NODATA would cache a falsehood on the strength of a server having said
nothing, so most of what follows hammers the same seam: what the answer *did* claim,
versus what it merely failed to claim.

.. rubric:: References

* RFC 10029 section 3.2 (a client must send conforming packets), section 3.4 (a listed
  QTx is one whose flags matched the primary's and whose RRs all fit), section 3.5 (the
  three readings, the four innocent absences, and the RFC 2181 section 5.4.1 ranking
  rule), appendix A.3 (an empty list that still means "supported")
* RFC 6891 section 6.1.2 (an unknown OPTION-CODE MUST be ignored, which is why an
  unextended answer is ordinary rather than an error), section 7 (a malformed option
  value is a wire error)
* RFC 2308 section 5, which is why a negative learned this way is worth believing at
  all: it carries an SOA and a TTL, and a verdict that does not is not cacheable
"""

import ipaddress

import pytest

from namespy.bundle import BundleState, collect_bundle, query_option_for
from namespy.edns import EdnsOption
from namespy.enums import DnsQR, DnsQType, DnsRClass, DnsResponseCode, DnsRType
from namespy.mqtype import mqtype_query_option, mqtype_response_option
from namespy.names import DomainName
from namespy.packet import DnsQuestion, DnsRecord, Response

QNAME = DomainName("www.example.com.")
ZONE = DomainName("example.com.")
OTHER = DomainName("somewhere.else.")
TARGET = DomainName("cdn.example.net.")
V4 = ipaddress.IPv4Address("93.184.216.34")
V6 = ipaddress.IPv6Address("2606:2800:220:1:248:1893:25c8:1946")

A = int(DnsQType.A)
AAAA = int(DnsQType.AAAA)
HTTPS = int(DnsQType.HTTPS)


def record(name, rtype, payload, ttl=300):
    return DnsRecord(name, rtype, DnsRClass.IN, ttl, rdata=payload)


def combined(*, answers=(), nameservers=(), options=(), aa=True, rcode=0):
    """A response, optionally extended with the option records a server sent back."""
    response = Response(
        QR=DnsQR.RESPONSE,
        AA=aa,
        RCODE=rcode,
        questions=[DnsQuestion(QNAME, DnsQType.A)],
        answers=list(answers),
        nameservers=list(nameservers),
    )
    if options:
        response.add_edns(1232, options=list(options))
    return response


def read(response, requested=(AAAA, HTTPS), primary=A):
    return collect_bundle(response, primary_qtype=primary, requested=requested, terminal_name=QNAME)


# ---------------------------------------------------------------- no answer either way


def test_a_server_that_says_nothing_is_unsupported_rather_than_wrong():
    """Section 3.5, first sentence: no MQTYPE-Response means "not supported", and the
    primary answer is untouched -- "MUST process the primary response as if the
    MQTYPE-Query option had not been used". Not void, not an error, just ordinary."""
    result = read(combined(answers=[record(QNAME, A, V4.packed)]))
    assert result.supported is False
    assert result.void is False
    assert result.combined == ()
    assert result.still_needed == (AAAA, HTTPS)
    assert result.state_of(AAAA) is BundleState.NEEDED


def test_an_option_echoed_back_is_the_same_nonanswer():
    """A server that replies with MQTYPE-Query has misunderstood rather than lied.
    Section 3.5 puts it in the same sentence as silence -- "or if it erroneously
    contains an MQTYPE-Query option, the client MUST treat the response as if this
    option is unsupported" -- so the primary answer still stands."""
    result = read(combined(options=[mqtype_query_option([AAAA])]))
    assert result.supported is False
    assert result.void is False
    assert result.state_of(HTTPS) is BundleState.NEEDED


def test_an_empty_list_still_means_supported():
    """Appendix A.3 in one assertion: the option is present and its list is empty, so
    the server implements the extension and combined nothing. Reading the empty list as
    "unsupported" would throw away the only thing the response had to say."""
    result = read(combined(options=[mqtype_response_option()]))
    assert result.supported is True
    assert result.combined == ()
    assert result.still_needed == (AAAA, HTTPS)


def test_an_unreadable_option_is_nobodys_business():
    """A malformed TLV that is not the bundle's is RFC 6891 section 7's problem, not a
    reason to doubt the answer. The bundle is reported unsupported and nothing raises,
    because a resolution walk must not die inside a reading helper."""
    response = combined(options=[EdnsOption(9999, b"")])
    response.additional_records[0].rdata = b"\x00\x03"  # length says 3, only 2 arrive
    result = read(response)
    assert result.supported is False
    assert result.still_needed == (AAAA, HTTPS)


# ---------------------------------------------------------------- the ordinary success


def test_everything_that_was_listed_and_delivered_is_combined():
    """Section 3.4: a QTx is listed "to indicate that the given query type was completely
    processed", so its records are the answer and travel with it."""
    result = read(
        combined(
            answers=[
                record(QNAME, A, V4.packed),
                record(QNAME, AAAA, V6.packed),
                record(QNAME, HTTPS, b"\x00\x01\x00\x00\x01\x00\x03\x02h2"),
            ],
            options=[mqtype_response_option([AAAA, HTTPS])],
        )
    )
    assert result.supported is True
    assert result.combined == (AAAA, HTTPS)
    assert result.still_needed == ()
    assert result.state_of(AAAA) is BundleState.COMBINED
    assert [bytes(r.rdata) for r in result.records_for(HTTPS)] == [
        b"\x00\x01\x00\x00\x01\x00\x03\x02h2"
    ]
    assert result.types[0].qtype == AAAA, "the order the client asked, not the server's"


def test_each_type_gets_only_its_own_records():
    """One message, several types: the AAAA entry must not collect the A record. The
    classifier matched the primary's type and nobody has filtered the rest until now."""
    result = read(
        combined(
            answers=[record(QNAME, A, V4.packed), record(QNAME, AAAA, V6.packed)],
            options=[mqtype_response_option([AAAA, HTTPS])],
        )
    )
    assert {int(r.rtype) for r in result.records_for(AAAA)} == {AAAA}
    assert result.state_of(HTTPS) is BundleState.NODATA


# ------------------------------------------------------- absence is not a negative answer


def test_records_do_not_make_up_for_a_missing_list_entry():
    """The trap this module exists for. The answer section happens to carry an AAAA --
    from a cache, from an earlier question, from anywhere -- but the server did not list
    it, so it has not claimed the RRset is complete, and section 3.4's "completely
    processed" is the only thing that makes an answer here trustworthy."""
    result = read(
        combined(
            answers=[record(QNAME, A, V4.packed), record(QNAME, AAAA, V6.packed)],
            options=[mqtype_response_option([HTTPS])],
        )
    )
    assert result.state_of(AAAA) is BundleState.NEEDED
    assert result.records_for(AAAA) == (), "not harvested: it was never claimed"
    assert result.still_needed == (AAAA,)


def test_an_absent_qtx_under_nxdomain_is_still_only_a_work_item():
    """Tempting to read NXDOMAIN as answering everything, and wrong: section 3.5's four
    reasons apply to absence whatever the RCODE. The *listed* type shares the verdict,
    because section 3.4 required its flags to match; the unlisted one was never compared
    to anything."""
    result = read(
        combined(
            rcode=DnsResponseCode.NAME_ERROR,
            nameservers=[record(ZONE, DnsRType.SOA, b"")],
            options=[mqtype_response_option([AAAA])],
        )
    )
    assert result.state_of(AAAA) is BundleState.NXDOMAIN
    assert result.state_of(HTTPS) is BundleState.NEEDED


def test_a_listed_type_with_no_records_is_nodata_and_says_who_said_so():
    """Section 3.4 lets a QTx be listed only after checking its flags match the primary's,
    so a listed type with nothing in the Answer section is an authoritative denial --
    worth believing, and worth caching, exactly as far as AA reaches."""
    result = read(
        combined(
            answers=[record(QNAME, A, V4.packed)],
            nameservers=[record(ZONE, DnsRType.SOA, b"")],
            options=[mqtype_response_option([AAAA])],
        )
    )
    assert result.state_of(AAAA) is BundleState.NODATA
    assert result.types[0].authoritative is True


def test_a_nodata_in_an_answer_nobody_is_authoritative_for_is_marked_as_such():
    """The same reading, minus the authority: section 3.5 defers to RFC 2181 section
    5.4.1's "ranked the same as the answer for the primary question", and a primary that
    is not authoritative cannot lend authority to a type that merely travelled with it."""
    result = read(
        combined(
            aa=False,
            answers=[record(QNAME, A, V4.packed)],
            options=[mqtype_response_option([AAAA])],
        )
    )
    assert result.state_of(AAAA) is BundleState.NODATA
    assert result.types[0].authoritative is False


def test_a_record_for_another_name_is_not_an_answer_for_this_one():
    """The extras are not what the Question section asked, so nobody upstream filtered
    their owners. Harvesting an AAAA owned by another name would answer this lookup with
    data about something else -- RFC 5452 section 6's mistake wearing a different hat."""
    result = read(
        combined(
            answers=[record(QNAME, A, V4.packed), record(OTHER, AAAA, V6.packed)],
            options=[mqtype_response_option([AAAA])],
        )
    )
    assert result.state_of(AAAA) is BundleState.NODATA
    assert result.records_for(AAAA) == ()


def test_the_alias_target_is_the_name_a_bundle_is_harvested_against():
    """The walk follows CNAMEs and so do the extras, because Sname keeps its QTYPE through
    a re-anchor; the records therefore live at the target. Harvesting against the name the
    walk ended at, rather than the name it started at, is what makes an aliased name
    bundle at all."""
    response = combined(
        answers=[record(TARGET, AAAA, V6.packed)], options=[mqtype_response_option([AAAA])]
    )
    result = collect_bundle(response, primary_qtype=A, requested=(AAAA,), terminal_name=TARGET)
    assert result.state_of(AAAA) is BundleState.COMBINED
    assert result.records_for(AAAA)[0].name == TARGET


# ------------------------------------------------------ an answer that contradicts itself


@pytest.mark.parametrize(
    ("options", "expect"),
    [
        pytest.param(
            [mqtype_response_option([AAAA]), mqtype_response_option([HTTPS])],
            "2 MQTYPE-Response",
            id="twice",
        ),
        pytest.param([EdnsOption(21, b"\x00\x1c\x00\x1c")], "duplicate QTx", id="repeated"),
        pytest.param([mqtype_response_option([A])], "repeats the primary", id="is-primary"),
    ],
)
def test_a_contradictory_answer_voids_the_primary_too(options, expect):
    """Section 3.5: "If the MQTYPE-Response option is present more than once or if a QTx
    value is duplicated (or duplicates the primary QTYPE field), the client MUST treat the
    answer as invalid (equivalent to FORMERR)".

    The word is *answer*, not option. One response now claims to settle several
    (QNAME, QCLASS, QTx) combinations and the claim itself is broken, so the primary is
    not salvageable -- and a reading that discarded only the bundle would go on serving an
    answer the client had been told to throw away. Every requested type returns to the
    work list, because the client now owes standalone queries for all of them.
    """
    result = read(
        combined(
            answers=[record(QNAME, A, V4.packed), record(QNAME, AAAA, V6.packed)],
            options=options,
        )
    )
    assert result.void is True
    assert expect in result.reason
    assert result.supported is True, "it did claim support, before contradicting itself"
    assert result.still_needed == (AAAA, HTTPS)
    assert result.records_for(AAAA) == (), "nothing survives an invalid answer"


def test_a_type_listed_but_never_asked_is_ignored_not_harvested():
    """A server that lists HTTPS when nobody requested it is odd rather than
    self-contradictory: section 3.5's list of invalid shapes does not include it, so the
    answer stands. It is reported, because a server inventing types is worth a log line,
    and it is not harvested, because there is no request for it to answer."""
    result = read(
        combined(
            answers=[
                record(QNAME, A, V4.packed),
                record(QNAME, HTTPS, b"\x00\x01\x00\x00\x01\x00\x03\x02h2"),
            ],
            options=[mqtype_response_option([HTTPS, int(DnsQType.TXT)])],
        )
    )
    assert result.void is False
    assert result.state_of(HTTPS) is BundleState.COMBINED
    assert result.unrequested == (int(DnsQType.TXT),)


def test_nothing_requested_is_not_a_bundle():
    """A caller that asked for no extras gets no verdicts -- including not a NODATA for
    every type in the registry -- and is told plainly that nothing was supported."""
    result = collect_bundle(combined(), primary_qtype=A, requested=())
    assert result.supported is False
    assert result.types == ()
    assert result.still_needed == ()


# ------------------------------------------------------------------ the result as a todo list


def test_the_work_list_shrinks_as_the_standalone_queries_land():
    """Section 3.5 makes the re-ask part of the protocol, so the result has to be able to
    record that a type finished that way. NEEDED is only allowed to survive on a type
    nobody answered at all."""
    result = read(combined(options=[mqtype_response_option([AAAA])]))
    assert result.still_needed == (HTTPS,)

    answer = combined(answers=[record(QNAME, HTTPS, b"\x00\x01\x00\x00\x01\x00\x03\x02h2")])
    settled = result.reasked(
        HTTPS, state=BundleState.COMBINED, records=answer.answers, response=answer
    )
    assert settled.still_needed == ()
    assert settled.state_of(HTTPS) is BundleState.COMBINED
    assert settled.records_for(HTTPS) == tuple(answer.answers)
    assert settled.types[1].response is answer
    assert result.state_of(HTTPS) is BundleState.NEEDED, "the original is untouched"


def test_a_result_knows_its_own_answer():
    """``primary`` is what resolve() would have returned. It travels inside the bundle
    rather than being a second return value a caller has to pair up correctly."""
    response = combined(answers=[record(QNAME, A, V4.packed)])
    assert read(response).with_primary(response).primary is response


def test_a_type_nobody_asked_about_has_no_state_and_no_records():
    """Neither a KeyError nor a borrowed NODATA. A result speaks only for the types it was
    asked about, which is the same discipline the answer is read with: no inference, and
    no verdict for a question that was never put."""
    result = read(combined(options=[mqtype_response_option([AAAA])]))
    assert result.state_of(int(DnsQType.TXT)) is None
    assert result.records_for(int(DnsQType.TXT)) == ()
    assert result.types[0].answered is True
    assert result.types[1].answered is False, "HTTPS: still needed, nothing known"


def test_a_re_asked_type_is_no_longer_answered_of_nothing():
    """:meth:`~namespy.bundle.BundledType.answered` is what a caller renders as "asked
    separately" rather than "no answer", so it has to turn true on the standalone path --
    including when that path came back empty, which is an answer of a kind."""
    result = read(combined(options=[mqtype_response_option()]))
    assert not result.types[0].answered
    settled = result.reasked(AAAA, state=BundleState.NODATA)
    assert settled.types[0].answered is True, "NODATA is a verdict; NEEDED is not"


def test_the_answer_says_where_each_type_was_answered():
    """``separate`` is the difference between a record the server put in this packet and one
    the client went and fetched, and nothing else on the entry distinguishes them: both end
    up ``COMBINED`` with records attached. Without the flag, reporting a bundle honestly and
    reporting it attractively are the same act and honesty loses -- which is how the first
    version of the CLI report came to describe a re-asked AAAA as "combined".
    """
    harvested = read(
        combined(
            answers=[record(QNAME, A, V4.packed), record(QNAME, AAAA, V6.packed)],
            options=[mqtype_response_option([AAAA])],
        )
    )
    assert harvested.types[0].separate is False, "it travelled in the primary answer"
    settled = harvested.reasked(HTTPS, state=BundleState.COMBINED, response=object())
    assert settled.types[1].separate is True
    assert settled.types[0].separate is False, "one type's re-ask is not the other's"


# ------------------------------------------------------------------------- what may be sent


def test_no_extras_means_no_option_at_all():
    """An empty MQTYPE-Query is a FORMERR by section 3.3, so the way to ask for no extras
    is not to send the option -- there is no flag inside it meaning "on, with nothing"."""
    assert query_option_for(A, ()) is None
    assert query_option_for(A, []) is None


def test_the_option_asks_for_the_types_it_was_given():
    option = query_option_for(A, [AAAA, HTTPS])
    assert option is not None
    assert option.data == bytes([0x00, 0x1C, 0x00, 0x41])


@pytest.mark.parametrize(
    ("primary", "extras", "offence"),
    [
        pytest.param(A, [A], "duplicates the primary", id="same-as-primary"),
        pytest.param(A, [AAAA, AAAA], "duplicate", id="twice-listed"),
        pytest.param(A, [int(DnsQType.AXFR)], "not a data one", id="transfer-is-a-qtype"),
        pytest.param(A, [int(DnsRType.OPT)], "not a data one", id="opt-is-a-meta-rr"),
    ],
)
def test_a_list_a_server_must_refuse_is_not_sent(primary, extras, offence):
    """Section 3.2: "DNS clients implementing this specification MUST generate packets
    that conform to the server request parsing rules described in Section 3.3". The
    checking happens here, on the way out, against the same conditions the server applies
    on the way in -- one validator, so the two ends cannot drift apart about what is
    sendable. The last case is the one a range check would get wrong: OPT is numbered
    inside the data band and is not data."""
    with pytest.raises(ValueError, match=offence):
        query_option_for(primary, extras)
