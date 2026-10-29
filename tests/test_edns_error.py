"""Extended DNS Errors (RFC 8914): the option's two fields and nothing else.

EDE is a small option with a suspicious amount of latitude in it. RFC 8914
section 2 gives a 16-bit INFO-CODE that "serves as an index into the 'Extended
DNS Errors' registry" and a UTF-8 EXTRA-TEXT "intended for human consumption (not
automated parsing)" that "may be null terminated but MUST NOT be assumed to be".
Section 3 then removes almost every inference a receiver might draw from those two
fields: codes and RCODEs need not make sense together, a receiver MUST accept them
"in all messages, including those with a NOERROR RCODE", several may arrive at
once, and "Applications MUST continue to follow requirements from applicable
specifications on how to process RCODEs no matter what EDE values are also
received". Section 6 finishes the job by calling the whole thing "unauthenticated
information" that "MUST NOT alter DNS protocol processing".

So the tests below assert an absence as much as a presence. There is no code here
that changes what a resolution does, no exception escaping a malformed option, and
no rendering that lets a stranger's octets reach a terminal raw -- and each of
those absences is a paragraph of the specification, not a mood.

.. rubric:: References

* RFC 8914 section 2 (the option format, the two fields, the NUL and
  OPTION-LENGTH rules, the private-information warning)
* RFC 8914 section 3 (dropping EDE before other data, attributing the source,
  no RCODE matching, multiple options, tolerance, keeping EXTRA-TEXT short)
* RFC 8914 sections 4.22-4.23 (the codes this project sends itself)
* RFC 8914 section 5.1 (OPTION-CODE 15) and section 5.2 Tables 2-3 (the code
  registry and its private-use range)
* RFC 8914 section 6 (unauthenticated, MITM-insertable, diagnostic only)
* RFC 6891 section 7 (the FORMERR a responder owes a badly formatted option)
"""

import pytest

from namespy.edns import (
    EDNS_OPTION_HEADER_OCTETS,
    ERROR_OPTION_CODE,
    EXTENDED_ERROR_INFO_OCTETS,
    EXTENDED_ERROR_PRIVATE_USE_MIN,
    MAX_EDNS_OPTION_OCTETS,
    MAX_EXTENDED_ERROR_CODE,
    ExtendedDNSError,
    extended_dns_error_option,
    extended_error_name,
    extended_error_option_valid,
    extended_error_presentation,
    extended_errors_of,
    nsid_option,
    option_name,
    parse_options,
    serialize_options,
)


def wire_of(*options) -> bytes:
    """The OPT RDATA that would carry *options*, so tests read them as a wire does."""
    return serialize_options(list(options))


# ------------------------------------------------------------- the option's shape


def test_the_option_code_is_the_one_iana_records() -> None:
    """Section 5.1: "a new EDNS(0) option, entitled 'Extended DNS Error', with the
    assigned value of 15". The name printed for it is the short one the document
    itself uses -- "The Extended DNS Error (EDE) option" -- not a coinage."""
    assert 15 == ERROR_OPTION_CODE
    assert "EDE" == option_name(ERROR_OPTION_CODE)


def test_the_payload_is_the_info_code_then_the_text() -> None:
    """Section 2's figure puts INFO-CODE at octet 4, in "network most significant
    bit (MSB) byte order", with EXTRA-TEXT following it. Byte-level because a
    transposed code is a *different error*, silently: 0x0016 is No Reachable
    Authority and 0x1600 is 5632, a code nobody has."""
    option = extended_dns_error_option(22, b"ns1: no response")
    assert b"\x00\x16ns1: no response" == option.data
    assert ERROR_OPTION_CODE == option.code


def test_the_text_is_optional_and_the_code_is_not() -> None:
    """Section 2: EXTRA-TEXT "may be zero octets in length, indicating that there
    is no EXTRA-TEXT included", while OPTION-LENGTH "should be 2 plus the length of
    the EXTRA-TEXT field". Two octets is therefore a complete option."""
    bare = ExtendedDNSError(23)
    assert b"\x00\x17" == bare.octets
    assert "" == bare.text


def test_an_option_is_reconstructible_from_the_wire_it_was_serialised_to() -> None:
    """The round trip is the only claim this module gets to make about section 2's
    figure: what :func:`serialize_options` writes, :func:`extended_errors_of` must
    read back unchanged -- text and all, including octets no decoder would like."""
    sent = ExtendedDNSError(6, b"signature expired 4711 s ago")
    (received,) = extended_errors_of(parse_options(wire_of(sent.option)))
    assert sent == received


# ------------------------------------------------------- what the two fields mean


def test_a_registry_name_is_the_one_the_registry_gives_it() -> None:
    """Section 5.2 Table 3's Purpose column, verbatim. A code that prints as a
    paraphrase is a code whose meaning this project invented, which is exactly what
    an index into a registry is not supposed to allow."""
    assert "Other Error" == extended_error_name(0)
    assert "Stale Answer" == extended_error_name(3)
    assert "No Reachable Authority" == extended_error_name(22)
    assert "Invalid Data" == extended_error_name(24)


def test_a_code_with_no_entry_prints_as_its_number() -> None:
    """Unassigned (25-49151) and private-use (49152-65535) space per section 5.2
    Table 2. A code from either is somebody else's meaning, so it renders as a
    number and :attr:`private_use` says which kind of unknown it is."""
    assert "25" == extended_error_name(25)
    assert "49151" == extended_error_name(49151)
    assert "49152" == extended_error_name(EXTENDED_ERROR_PRIVATE_USE_MIN)
    assert ExtendedDNSError(EXTENDED_ERROR_PRIVATE_USE_MIN).private_use
    assert not ExtendedDNSError(24).private_use
    assert ExtendedDNSError(MAX_EXTENDED_ERROR_CODE).private_use


def test_the_text_keeps_the_octets_the_option_carried() -> None:
    """Section 2's two sentences in tension, resolved in favour of the bytes:
    "EDE text may be null terminated but MUST NOT be assumed to be; the length MUST
    be derived from the OPTION-LENGTH field." So :attr:`extra_text` is what arrived,
    NUL included, and only :attr:`text` -- the display -- drops one, and only a
    trailing one. Invalid UTF-8 likewise survives in ``extra_text`` and becomes
    U+FFFD on screen."""
    nulless = ExtendedDNSError(3, b"stale")
    nulled = ExtendedDNSError(3, b"stale\x00")
    assert b"stale\x00" == nulled.extra_text, "the OPTION-LENGTH described that octet"
    assert nulless.text == nulled.text == "stale"
    assert "\ufffd\ufffd" == ExtendedDNSError(0, b"\xff\xfe").text, "one per bad octet"
    assert ExtendedDNSError(0, b"\xff\xfe").extra_text == b"\xff\xfe"


def test_a_code_is_a_code_only() -> None:
    """Section 3: "systems interpreting the extended error codes MUST NOT assume
    that a combination will make sense", and the same paragraph leaves RCODE
    processing alone. There is accordingly nothing on this class but the two fields
    and how they print -- no severity, no retryability, no `is_dnssec_failure`."""
    public = {name for name in dir(ExtendedDNSError) if not name.startswith("_")}
    assert {
        "extra_text",
        "info_code",
        "name",
        "octets",
        "option",
        "private_use",
        "text",
    } == public


# ---------------------------------------------------- reading what a server sent


def test_every_option_in_a_message_is_returned_not_the_first() -> None:
    """Section 3: "Senders MAY include more than one EDE option and receivers MUST
    be able to accept (but not necessarily process or act on) multiple EDE options
    in a DNS message." Choosing one would be deciding which error matters; the
    order the sender chose is kept instead."""
    blob = wire_of(
        nsid_option(b"ns-a"),
        ExtendedDNSError(22, b"upstream").option,
        ExtendedDNSError(13, b"cached").option,
    )
    errors = extended_errors_of(parse_options(blob))
    assert [22, 13] == [error.info_code for error in errors]


def test_options_the_receiver_has_no_business_reading_are_left_alone() -> None:
    """Section 5.2 sanctions codes this project cannot name, and section 3's "MUST
    be able to accept EDE codes and EXTRA-TEXT in all messages" is not conditional
    on the code being registered or the text being pleasant."""
    blob = wire_of(
        ExtendedDNSError(65535, b"mine").option,
        ExtendedDNSError(40000).option,
    )
    errors = extended_errors_of(parse_options(blob))
    assert [(65535, b"mine"), (40000, b"")] == [(e.info_code, e.extra_text) for e in errors]
    assert all(error.private_use or error.name.isdigit() for error in errors)


@pytest.mark.parametrize("data", [b"", b"\x00"])
def test_an_option_too_short_to_hold_a_code_is_the_one_thing_skipped(data) -> None:
    """Fewer than two octets is not an unreadable meaning, it is no meaning at all
    -- and RFC 6891 section 7 names that "an option value that is badly formatted".
    :func:`extended_error_option_valid` is the predicate a responder needs to answer
    it; :func:`extended_errors_of` uses the same predicate to skip, because a
    *receiver* of an answer must let the option's badness stop at the option."""
    option = ExtendedDNSError(1).option
    broken = option.__class__(ERROR_OPTION_CODE, data)
    assert not extended_error_option_valid(broken)
    assert extended_error_option_valid(ExtendedDNSError(0).option)
    assert () == extended_errors_of([broken])
    assert [1] == [e.info_code for e in extended_errors_of([broken, option])]


def test_a_bad_option_cannot_escape_as_an_exception() -> None:
    """Section 6: "EDE content should be treated only as diagnostic information and
    MUST NOT alter DNS protocol processing." An exception raised on the way to an
    answer would be the clearest possible alteration of it, so the function that
    reads EDE raises nothing, ever -- the malformed option above is skipped, and the
    well-formed ones beside it still come through."""
    readable = ExtendedDNSError(15, b"blocked").option
    assert [15] == [e.info_code for e in extended_errors_of([readable])]
    assert () == extended_errors_of([])
    assert () == extended_errors_of([nsid_option(b"ns-a")]), "not our code, not our problem"


# ----------------------------------------------------------------- what gets shown


def test_the_presentation_leads_with_the_number_it_can_prove() -> None:
    """The number is the only part with a definition; the name beside it is this
    project's copy of a registry that could change underneath it. Codes with no
    entry get no parentheses rather than a guess."""
    assert "22 (No Reachable Authority)" == extended_error_presentation(ExtendedDNSError(22))
    assert "49152" == extended_error_presentation(ExtendedDNSError(49152))
    assert "23 (Network Error): timeout" == extended_error_presentation(
        ExtendedDNSError(23, b"timeout")
    )


def test_somebody_elses_text_cannot_write_on_the_terminal() -> None:
    """Section 6: "EDE information is unauthenticated information" and "An attacker
    (e.g., a man in the middle (MITM) or malicious recursive server) could insert an
    extended error response into untrusted data". EXTRA-TEXT is therefore hostile
    input wherever it is displayed: control octets arrive escaped, so a response
    cannot clear the screen or move the cursor while telling you about itself."""
    shown = extended_error_presentation(ExtendedDNSError(15, b"no\x1b[2J\x07yes\r\n"))
    for hostile in ("\x1b", "\x07", "\r", "\n"):
        assert hostile not in shown
    assert "no\\x1b[2J\\x07yes" in shown


def test_a_lengthy_text_is_cut_because_sending_it_was_discouraged() -> None:
    """Section 3: "implementers and operators creating EDE options SHOULD avoid
    lengthy EXTRA-TEXT contents", since long text is what triggers the truncation
    that paragraph is about. A receiver cannot un-send it, so it declines to print
    all of it -- and the cap lands on the *display*, never on the octets."""
    wordy = ExtendedDNSError(0, b"x" * 500)
    shown = extended_error_presentation(wordy)
    assert shown.endswith("...")
    assert len(shown) < 200
    assert b"x" * 500 == wordy.extra_text, "the sender's octets are not ours to trim"


# ---------------------------------------------------------------- what goes out


def test_extra_text_is_bounded_by_the_option_it_has_to_fit_in() -> None:
    """A 16-bit OPTION-LENGTH (RFC 6891 section 6.1.2) minus the INFO-CODE is the
    most any one option can carry; an over-long text would serialise as a length
    that cannot exist, so it is refused where the value is built rather than at the
    wire. Section 3's "SHOULD avoid lengthy EXTRA-TEXT" makes the limit unreachable
    in honest code."""
    limit = MAX_EDNS_OPTION_OCTETS - EXTENDED_ERROR_INFO_OCTETS
    assert limit == len(ExtendedDNSError(0, b"x" * limit).extra_text)
    assert 0xFFFF == MAX_EDNS_OPTION_OCTETS, "the width of OPTION-LENGTH itself"
    assert EDNS_OPTION_HEADER_OCTETS == 4
    with pytest.raises(ValueError, match="over the 65533 that fit beside an INFO-CODE"):
        ExtendedDNSError(0, b"x" * (limit + 1))


@pytest.mark.parametrize("info_code", [-1, MAX_EXTENDED_ERROR_CODE + 1, 1 << 20])
def test_a_code_outside_the_registry_field_is_refused(info_code) -> None:
    """The field is 16 bits (section 2), so a code that does not fit is not an
    unusual code, it is a programming error -- and unlike a *received* code it is
    one this program wrote, which is the kind worth raising about."""
    with pytest.raises(ValueError, match="extended error INFO-CODE out of range"):
        ExtendedDNSError(info_code)


def test_the_codes_this_project_sends_are_its_own_two() -> None:
    """Section 4.23, "The resolver could not reach any of the authoritative name
    servers (or they potentially refused to reply)", is what a walk that ran out of
    servers has hit; section 4.22, "The requested operation or query is not
    supported", is what a non-QUERY opcode earns. Nothing else is invented, and the
    attribution section 3 asks for -- "the source of the error SHOULD be attributed
    in the EXTRA-TEXT field" -- is in the text."""
    from namespy.server import (
        _OWN_FAILURE_ERRORS,
        EDE_NO_REACHABLE_AUTHORITY,
        EDE_NOT_SUPPORTED,
    )

    assert 22 == EDE_NO_REACHABLE_AUTHORITY
    assert 21 == EDE_NOT_SUPPORTED
    assert {b"namespy: no authoritative answer", b"namespy: only QUERY is supported"} == {
        text for _, text in _OWN_FAILURE_ERRORS.values()
    }
    assert all(
        text.startswith(b"namespy: ") and len(text) < 64 for _, text in _OWN_FAILURE_ERRORS.values()
    )
