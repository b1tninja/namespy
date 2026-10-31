"""Serving DNSSEC: who is owed the proof records, and who is not.

RFC 4035 §3.2.1¶1 is a single sentence with two halves that point in opposite directions. The
resolver side of a security-aware recursive server "MUST set the DO bit when sending requests,
regardless of the state of the DO bit in the initiating request received by the name server side" --
so the walk always asks. Then: "If the DO bit in an initiating query is not set, the name server side
MUST strip any authenticating DNSSEC RRs from the response but MUST NOT strip any DNSSEC RR types
that the initiating query explicitly requested." Always-ask plus never-tell-except-when-asked is the
combination that lets one resolver serve a DNSSEC-aware stub and an ancient one at the same time, so
both halves are tested here rather than only the pleasant one.

RFC 8020 §2¶5 puts the positive obligation on the cached path: when the NXDOMAIN answered from cache
came from a signed zone, "the iterative, caching resolver MUST return these NSEC or NSEC3 records in
the response to the triggering query if the query had the DNSSEC OK (DO) bit set". Without that the
proof stored with a cached denial is a private artefact of the resolver.

RFC 3225 §2 is the reason the strip is not cosmetic: DNSSEC records push answers past the 512-octet
UDP ceiling into TCP retries (§2¶1-¶2), and there were reports of non-DNSSEC-aware "resolvers being
unable to handle responses which contain DNSSEC security RRs, resulting in the resolver failing (in
the worst case) or entire responses being ignored (in the better case)" (§2¶3). §2¶5 makes the
client's willingness binary, which is what makes QTYPE=* something other than a request for RRSIGs.
"""

import ipaddress
from types import SimpleNamespace

import pytest

from namespy.cache import NegativeEntry
from namespy.dnssec import DNSSEC_SECURITY_TYPES
from namespy.enums import DnsRClass, DnsResponseCode, DnsRType
from namespy.names import DomainName
from namespy.packet import (
    EDNS_DO_BIT,
    DnsPacket,
    DnsQuestion,
    DnsRecord,
    Query,
    Response,
)
from namespy.rdata import RData_A, RData_NSEC, RData_RRSIG
from namespy.resolver import RecursiveResolver, _synthesize_response
from namespy.server import DnsServer

ZONE = "example.com."
HOST = DomainName("www." + ZONE)
HOST_IP = ipaddress.IPv4Address("93.184.216.34")
A = int(DnsRType.A)
ANY = 255
NOW = 1000.0


def _record(name, rtype, rdata, ttl=300):
    return DnsRecord(DomainName(name), rtype, DnsRClass.IN, ttl, rdata=rdata)


def _rrsig(covered, owner, signer=ZONE):
    return RData_RRSIG(
        type_covered=covered,
        algorithm=13,
        labels=len([label for label in DomainName(owner).labels() if label]),
        original_ttl=300,
        expiration=2**31 - 1,
        inception=0,
        key_tag=1,
        signer_name=signer,
        signature=b"\x01" * 8,
    )


def _a_pair():
    """An answer and the signature over it, which RFC 4035 §3.1.1¶2 keeps in the same section."""
    return [
        _record(HOST, DnsRType.A, RData_A(HOST_IP)),
        _record(HOST, DnsRType.RRSIG, _rrsig(A, HOST)),
    ]


def _denial_pair():
    """A proof and its signature, which §3.1.1¶3 keeps in the Authority section."""
    nsec = _record(HOST, DnsRType.NSEC, RData_NSEC(DomainName("zz." + ZONE), [A]))
    signature = _record(HOST, DnsRType.RRSIG, _rrsig(int(DnsRType.NSEC), HOST))
    return [nsec, signature]


def _sname():
    return SimpleNamespace(questions=[DnsQuestion(HOST, A, int(DnsRClass.IN))])


def _denial_entry(proofs):
    soa = _record(ZONE, DnsRType.SOA, b"\x00" * 4)
    return NegativeEntry(
        HOST, A, int(DnsRClass.IN), DnsResponseCode.NAME_ERROR, soa, NOW + 300, proofs
    )


def _query(dnssec: bool, qtype: int = A):
    query = Query(questions=[DnsQuestion(HOST, qtype, int(DnsRClass.IN))])
    query.add_edns(1232, flags=EDNS_DO_BIT if dnssec else 0)
    return query


def _types_of(response, section):
    return [int(record.rtype) for record in getattr(response, section)]


# --------------------------------------------------------------- the echo: RFC 8020 §2¶5


def test_a_dnssec_aware_resolver_echoes_the_proof_of_a_cached_denial():
    """The whole point of storing proofs: a descendant query gets the evidence, not just the RCODE."""
    response = _synthesize_response(_sname(), _denial_entry(tuple(_denial_pair())), dnssec_ok=True)

    assert _types_of(response, "nameservers") == [
        int(DnsRType.SOA),
        int(DnsRType.NSEC),
        int(DnsRType.RRSIG),
    ]
    assert response.NSCOUNT == len(response.nameservers), "the header must count what it carries"


def test_the_proof_is_not_echoed_to_a_client_that_did_not_ask():
    """dnssec_ok=False is the resolver-side half of §3.2.1's second sentence.

    A server passes its resolver's instance knob here, so this is also what a caller sees from a
    resolver that never asks for DNSSEC data: no phantom records appear in an answer nobody asked
    for, and the RCODE stays the only difference from an unsigned denial.
    """
    response = _synthesize_response(_sname(), _denial_entry(tuple(_denial_pair())), dnssec_ok=False)

    assert _types_of(response, "nameservers") == [int(DnsRType.SOA)]


def test_an_entry_from_a_cache_that_never_heard_of_proofs_still_answers():
    """The cache protocol is duck-typed, so a missing attribute is not a lookup failure."""

    class LegacyEntry:
        rcode = DnsResponseCode.NAME_ERROR
        soa = _record(ZONE, DnsRType.SOA, b"\x00" * 4)

    response = _synthesize_response(_sname(), LegacyEntry(), dnssec_ok=True)

    assert _types_of(response, "nameservers") == [int(DnsRType.SOA)]


# ------------------------------------------------------------------ the strip: §3.2.1¶1


def test_every_security_type_vanishes_from_every_section():
    """RRSIG, DNSKEY, NSEC, NSEC3 and NSEC3PARAM -- RFC 4035 §3.1 plus RFC 5155 §11's two."""
    response = Response(
        ID=7,
        QR=1,
        questions=[DnsQuestion(HOST, A, int(DnsRClass.IN))],
        answers=_a_pair(),
        nameservers=[
            _record(HOST, DnsRType.DNSKEY, b"\x00\x01\x00\x03\x05"),
            *_denial_pair(),
        ],
        additional_records=[
            _record("ns." + ZONE, DnsRType.NSEC3, b"\x01\x00\x00\x00\x02\x12\x34"),
            _record(ZONE, DnsRType.NSEC3PARAM, b"\x01\x00\x00\x00\x02\x12\x34"),
        ],
    )

    DnsServer._strip_dnssec(_query(dnssec=False), response)

    assert _types_of(response, "answers") == [A]
    assert _types_of(response, "nameservers") == []
    assert _types_of(response, "additional_records") == []
    assert (response.ANCOUNT, response.NSCOUNT, response.ARCOUNT) == (1, 0, 0), (
        "a header still claiming the stripped records is a message that lies about its own length"
    )


def test_a_type_the_query_named_is_never_stripped():
    """§3.2.1¶1's exception: "MUST NOT strip any DNSSEC RR types that the query requested".

    A client that asks for RRSIG at a name wants the signatures, and the strip exists to spare
    clients records they cannot parse -- not to withhold data they asked for by name. The exception
    is per type rather than a switch, so the NSEC in the same response still goes: it authenticates
    a denial this client never asked about, and keeping it because *something* DNSSEC-shaped was
    requested is how the strip quietly becomes a no-op.

    The client's DO bit is not consulted here. It is decided once, at :meth:`_reply`, whether this
    helper runs at all -- one guard, one place, so a DO=1 client is covered by the funnel test below
    rather than by a second reading of the same list.
    """
    response = Response(
        ID=7,
        QR=1,
        questions=[DnsQuestion(HOST, DnsRType.RRSIG, int(DnsRClass.IN))],
        answers=_a_pair(),
        nameservers=_denial_pair(),
    )

    DnsServer._strip_dnssec(_query(dnssec=False, qtype=int(DnsRType.RRSIG)), response)

    assert DnsRType.RRSIG in _types_of(response, "answers")
    assert _types_of(response, "nameservers") == [int(DnsRType.RRSIG)], (
        "the NSEC was never asked for"
    )


def test_a_multi_type_query_counts_as_asking_for_the_types_it_listed():
    """A QTx in RFC 10029's list is as explicit a request as a QTYPE, so it earns the exception.

    The QT list lives in OPT RDATA rather than the question section, which makes it tempting to read
    only the questions here. That would strip the RRSIGs from the answer to a client that named RRSIG
    among the types it wanted, and §3.2.1's exception is about what was requested.
    """
    response = Response(
        ID=7,
        QR=1,
        questions=[DnsQuestion(HOST, A, int(DnsRClass.IN))],
        answers=_a_pair(),
        nameservers=_denial_pair(),
    )

    DnsServer._strip_dnssec(_query(dnssec=False), response, mqtype_answered=[int(DnsRType.RRSIG)])

    assert DnsRType.RRSIG in _types_of(response, "answers")
    assert _types_of(response, "nameservers") == [int(DnsRType.RRSIG)]


def test_wildcard_is_not_a_request_for_the_security_types():
    """QTYPE=* asks for every type at a name; RFC 3225 §2¶5 asks whether the client can take any.

    Willingness travels on DO and nowhere else, so treating ANY as an explicit request for RRSIG
    would let one question type defeat the strip entirely -- and the resolvers RFC 3225 §2¶3
    describes as unable to handle DNSSEC records are exactly the ones that send ANY.
    """
    response = Response(
        ID=7,
        QR=1,
        questions=[DnsQuestion(HOST, ANY, int(DnsRClass.IN))],
        answers=_a_pair(),
    )

    DnsServer._strip_dnssec(_query(dnssec=False, qtype=ANY), response)

    assert _types_of(response, "answers") == [A]


def test_a_ds_record_survives_because_it_is_data_and_not_decoration():
    """DS is deliberately outside the set: withdrawing one from a referral breaks the walk.

    RFC 4035 §3.1¶1 lists DS among what a signed zone adds for a DO=1 query, so a set built from
    that sentence alone would sweep referrals away. A DS is a resource record a client can name, and
    a non-DNSSEC client that receives one in a referral is no worse off than one that received the
    zone's SOA -- which the strip has never touched.
    """
    assert int(DnsRType.DS) not in DNSSEC_SECURITY_TYPES
    ds = _record("sub." + ZONE, DnsRType.DS, b"\x00\x01\x08\x02" + b"\x00" * 20)
    response = Response(
        ID=7,
        QR=1,
        questions=[DnsQuestion("sub." + ZONE, A, int(DnsRClass.IN))],
        nameservers=[ds, *_denial_pair()],
    )

    DnsServer._strip_dnssec(_query(dnssec=False), response)

    assert _types_of(response, "nameservers") == [int(DnsRType.DS)]


def test_strip_is_a_no_op_when_there_is_nothing_to_withdraw():
    response = Response(
        ID=7,
        QR=1,
        questions=[DnsQuestion(HOST, A, int(DnsRClass.IN))],
        answers=[_record(HOST, DnsRType.A, RData_A(HOST_IP))],
    )

    DnsServer._strip_dnssec(_query(dnssec=False), response)

    assert _types_of(response, "answers") == [A]
    assert response.ANCOUNT == 1


# ------------------------------------------------------------- the funnel where DO is read


def test_the_reply_funnel_strips_and_still_answers_with_edns():
    """End to end through :meth:`DnsServer._reply`, which is where the client's DO is honoured.

    The static helper passing its own tests would not show a wrong guard here: this one line decides
    what every real client sees, and it sits next to ``_apply_edns``, whose reply OPT must survive
    the strip even though an upstream OPT must never be forwarded (RFC 6891 §6.1.1).
    """

    class FakeTransport:
        def __init__(self):
            self.sent = []

        def get_extra_info(self, name, default=None):
            return default

        def sendto(self, data, addr):
            self.sent.append(bytes(data))

    def reply_to(dnssec: bool):
        server = DnsServer(RecursiveResolver())
        server.transport = FakeTransport()
        server._reply(
            Response(
                ID=7,
                QR=1,
                AA=True,
                questions=[DnsQuestion(HOST, A, int(DnsRClass.IN))],
                answers=_a_pair(),
                nameservers=_denial_pair(),
            ),
            ("127.0.0.1", 5342),
            request=_query(dnssec),
        )
        assert len(server.transport.sent) == 1
        parsed, consumed = DnsPacket.parse(server.transport.sent[0])
        assert consumed == len(server.transport.sent[0])
        return parsed

    unsigned = reply_to(False)
    assert _types_of(unsigned, "answers") == [A]
    assert _types_of(unsigned, "nameservers") == []
    assert unsigned.opt() is not None, "an EDNS client gets an EDNS reply whatever was stripped"

    signed = reply_to(True)
    assert _types_of(signed, "answers") == [A, int(DnsRType.RRSIG)]
    assert _types_of(signed, "nameservers") == [int(DnsRType.NSEC), int(DnsRType.RRSIG)]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
