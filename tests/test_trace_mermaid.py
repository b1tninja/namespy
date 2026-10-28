import ipaddress

from namespy.enums import DnsQType, DnsRClass, DnsRType
from namespy.names import DomainName
from namespy.packet import DnsRecord
from namespy.resolver import (
    Answer,
    Demote,
    Done,
    Fail,
    NeedAddress,
    Nodata,
    Nxdomain,
    Referral,
    SendQuery,
    SlistEntry,
    Sname,
    VolunteeredGlue,
)
from namespy.trace import Trace


def test_to_mermaid_emits_sequence_diagram_with_zone_lanes():
    sname = Sname(DomainName("example.com"), DnsQType.A)
    trace = Trace(sname)

    root_entry = SlistEntry(
        DomainName("."),
        DomainName("a.root-servers.net"),
        [ipaddress.IPv4Address("198.41.0.4")],
    )
    com_entry = SlistEntry(
        DomainName("com"),
        DomainName("a.gtld-servers.net"),
        [ipaddress.IPv4Address("192.5.6.30")],
    )

    trace.record(SendQuery(root_entry, sname.questions))
    trace.record(Referral(DomainName("."), DomainName("com"), 0, 1))
    trace.record(SendQuery(com_entry, sname.questions))
    trace.record(
        Answer(
            [
                DnsRecord(
                    DomainName("example.com"),
                    DnsRType.A,
                    DnsRClass.IN,
                    0,
                    rdata=b"\x5d\xb8\xd8\x22",
                )
            ]
        )
    )
    trace.record(Done(None))

    out = trace.to_mermaid()
    assert out.startswith("sequenceDiagram")
    assert "participant C as client" in out
    assert "participant Z0 as ." in out
    assert "participant Z1 as com" in out
    assert "C->>Z0: example.com A" in out
    assert "Z0-->>C: referral com" in out
    assert "C->>Z1: example.com A" in out
    assert "Z1-->>C: AA, 1 records" in out
    assert "Note over C: done" in out


def test_to_mermaid_negative_responses_render_as_notes():
    sname = Sname(DomainName("missing.example.com"), DnsQType.A)
    trace = Trace(sname)

    entry = SlistEntry(
        DomainName("example.com"),
        DomainName("ns.example.com"),
        [ipaddress.IPv4Address("203.0.113.1")],
    )
    trace.record(SendQuery(entry, sname.questions))
    trace.record(Nxdomain())
    trace.record(Done(None))

    out = trace.to_mermaid()
    assert "Note over C: NXDOMAIN" in out

    trace2 = Trace(Sname(DomainName("example.com"), DnsQType.MX))
    soa = DnsRecord(DomainName("example.com"), DnsRType.SOA, DnsRClass.IN, 0, rdata=b"")
    trace2.record(SendQuery(entry, trace2.sname.questions))
    trace2.record(Nodata(soa))
    trace2.record(Done(None))
    out2 = trace2.to_mermaid()
    assert "Note over C: NODATA SOA=example.com" in out2


def test_to_mermaid_demote_renders_as_note():
    sname = Sname(DomainName("example.com"), DnsQType.A)
    trace = Trace(sname)

    entry = SlistEntry(
        DomainName("."),
        DomainName("bad.root-servers.net"),
        [ipaddress.IPv4Address("198.41.0.4")],
    )
    trace.record(SendQuery(entry, sname.questions))
    trace.record(Demote(entry, "rcode server_failure"))

    out = trace.to_mermaid()
    assert "Note over C: demote bad.root-servers.net (rcode server_failure)" in out


def test_to_mermaid_glueless_child_appended_below_parent():
    parent_sname = Sname(DomainName("example.com"), DnsQType.A)
    parent = Trace(parent_sname)
    parent.record(NeedAddress(DomainName("ns.glueless")))
    child = parent.child(Sname(DomainName("ns.glueless"), DnsQType.A))

    child_entry = SlistEntry(
        DomainName("."),
        DomainName("a.root-servers.net"),
        [ipaddress.IPv4Address("198.41.0.4")],
    )
    child.record(SendQuery(child_entry, child.sname.questions))
    child.record(
        Answer(
            [
                DnsRecord(
                    DomainName("ns.glueless"),
                    DnsRType.A,
                    DnsRClass.IN,
                    0,
                    rdata=b"\xcb\x00\x71\x01",
                )
            ]
        )
    )
    child.record(Done(None))

    out = parent.to_mermaid()
    assert "Note over C: glueless: resolve ns.glueless" in out
    # parent + child each open with their own sequenceDiagram block
    assert out.count("sequenceDiagram") == 2


def test_to_mermaid_records_volunteered_glue_under_both_verdicts():
    """The line a researcher reads off the diagram: who offered what, and how it was treated.

    Both verdicts are rendered because the *default* policy produces the refused
    kind on exactly the traffic worth studying. The diagram is a record of what was
    seen, not only of what was acted on.
    """
    refused = Trace(Sname(DomainName("www.example.com"), DnsQType.A))
    refused.record(Referral(DomainName("com"), DomainName("example.com"), 1, 2))
    refused.record(
        VolunteeredGlue(
            ns_name=DomainName("ns.evil.net"),
            records=(),
            addresses=(ipaddress.IPv4Address("203.0.113.66"),),
            used=False,
            reason="not authoritative for this name (RFC 5452 section 6)",
        )
    )
    assert "volunteered glue ns.evil.net (203.0.113.66) discarded" in refused.to_mermaid()

    believed = Trace(Sname(DomainName("www.example.com"), DnsQType.A))
    believed.record(
        VolunteeredGlue(
            ns_name=DomainName("ns.evil.net"),
            records=(),
            addresses=(ipaddress.IPv4Address("203.0.113.66"),),
            used=True,
            reason="believed under GluePolicy.PERMISSIVE",
        )
    )
    assert "volunteered glue ns.evil.net (203.0.113.66) believed" in believed.to_mermaid()


def test_to_mermaid_renders_a_failure_once():
    """One event, one line.

    This note used to be emitted twice for a single ``Fail``, which a reader would
    take for two distinct failures -- the reason an event that only ever becomes a
    note still earns a test of its own.
    """
    trace = Trace(Sname(DomainName("example.com"), DnsQType.A))
    trace.record(Fail("max hops"))

    assert trace.to_mermaid().count("Note over C: FAIL max hops") == 1
