"""Who may be believed about a nameserver's address -- and what is recorded either way.

RFC 5452 section 6 tells a resolver to refuse the data a responder is not
authoritative for, and Namespy does that by default. ``GluePolicy.PERMISSIVE``
exists so the refusal can be *measured*: someone reproducing a poisoning vector,
or auditing what a parent volunteers about someone else's nameservers, has to see
the address take effect rather than only learn that an address was thrown away.
These tests pin both halves -- the adoption, and the boundaries the policy does
not move.
"""

import inspect
import ipaddress
import logging

import pytest

from namespy.enums import DnsQR, DnsQType, DnsRClass, DnsRType
from namespy.names import DomainName
from namespy.packet import DnsQuestion, DnsRecord, Response
from namespy.resolver import (
    Demote,
    GluePolicy,
    RecursiveResolver,
    Slist,
    SlistEntry,
    Sname,
    VolunteeredGlue,
    classify,
    resolve_steps,
)

COM = DomainName("com")
ZONE = DomainName("example.com")
GTLD = DomainName("a.gtld-servers.net")
GTLD_IP = ipaddress.IPv4Address("192.5.6.30")
NS1 = DomainName("ns1.example.com")
NS1_IP = ipaddress.IPv4Address("198.51.100.53")
#: Outside both `com.` and `example.com.` -- the referral may not speak for it.
EVIL = DomainName("ns.evil.net")
EVIL_IP = ipaddress.IPv4Address("203.0.113.66")
DECOY = DomainName("decoy.example")
DECOY_IP = ipaddress.IPv4Address("203.0.113.99")


def _descent():
    """Stand at ``com.`` looking up ``www.example.com``: ``(sname, slist, entry)``.

    Built fresh per test because ``classify`` mutates the slist it is given.
    """
    sname = Sname(DomainName("www.example.com"), DnsQType.A)
    slist = Slist(sname)
    slist.zone = COM
    slist.match = 1
    slist.entries = [SlistEntry(COM, GTLD, [GTLD_IP])]
    return sname, slist, slist.best()


def _referral(ns_targets, glue=()):
    """A ``.com`` referral of ``example.com.`` to *ns_targets*, carrying *glue*."""
    return Response(
        QR=DnsQR.RESPONSE,
        AA=False,
        questions=[DnsQuestion(DomainName("www.example.com"), DnsQType.A)],
        nameservers=[
            DnsRecord(ZONE, DnsRType.NS, DnsRClass.IN, 172800, rdata=target)
            for target in ns_targets
        ],
        additional_records=[
            DnsRecord(name, DnsRType.A, DnsRClass.IN, 172800, rdata=address.packed)
            for name, address in glue
        ],
    )


def _glue_events(steps):
    return [step for step in steps if isinstance(step, VolunteeredGlue)]


# ------------------------------------------------------------------ the defaults


def test_the_safe_policy_is_what_you_get_by_asking_for_nothing():
    """Every layer must default to filtering, not just the one being called.

    Same reasoning as the QNAME-minimisation default test: this is a deviation
    from a specified defense, so an ordinary ``RecursiveResolver()`` -- and a
    driver calling ``classify`` or ``resolve_steps`` with no opinion -- has to be
    the refusing kind. A default that had to be set in three places is a default
    that gets forgotten in one.
    """
    for function in (classify, resolve_steps):
        default = inspect.signature(function).parameters["glue_policy"].default
        assert default is GluePolicy.STRICT
    assert RecursiveResolver().glue_policy is GluePolicy.STRICT


def test_a_clean_delegation_records_nothing():
    """Glue a zone ships for its own nameserver is not an observation.

    Without this, the event would fire on every ordinary referral and a trace
    full of ``VolunteeredGlue`` would mean nothing.
    """
    sname, slist, entry = _descent()
    steps = list(classify(_referral([NS1], glue=[(NS1, NS1_IP)]), sname, slist, entry))

    assert _glue_events(steps) == []
    assert slist.entries[0].addresses == [NS1_IP]
    assert "bailiwick" not in slist.entries[0].history


# ---------------------------------------------------------------------- adoption


def test_permissive_adopts_the_address_a_referral_volunteered():
    """The point of the policy: the volunteered address becomes the next hop.

    Everything else about the response is unchanged -- the NS name was always
    legitimate (RFC 1034 section 4.2.2) and the entry is not demoted. What the
    policy decides is only whether ``203.0.113.66`` is where the next query goes.
    """
    sname, slist, entry = _descent()
    steps = list(
        classify(
            _referral([EVIL], glue=[(EVIL, EVIL_IP)]),
            sname,
            slist,
            entry,
            glue_policy=GluePolicy.PERMISSIVE,
        )
    )

    (ns_entry,) = slist.entries
    assert ns_entry.addresses == [EVIL_IP]
    assert ns_entry.history["bailiwick"] == "out-of-bailiwick glue accepted (unverified)"
    assert not ns_entry.history.get("demoted")

    (glue,) = _glue_events(steps)
    assert glue.used is True
    assert glue.addresses == (EVIL_IP,)


def test_strict_still_records_what_it_refused():
    """Observation is not a permissive-mode feature.

    The default policy keeps refusing -- that is the behaviour a caller depends
    on -- but the address it refused now survives in the trace instead of being
    destroyed inside the classifier. This is what makes the exposure measurable
    without anyone having to lower their own defenses in order to count it.
    """
    sname, slist, entry = _descent()
    steps = list(classify(_referral([EVIL], glue=[(EVIL, EVIL_IP)]), sname, slist, entry))

    (ns_entry,) = slist.entries
    assert ns_entry.addresses == []
    assert ns_entry.history["bailiwick"] == "out-of-bailiwick glue discarded"

    (glue,) = _glue_events(steps)
    assert glue.used is False
    assert glue.ns_name == EVIL
    assert glue.addresses == (EVIL_IP,)
    assert glue.reason == "not authoritative for this name (RFC 5452 section 6)"


def test_the_policies_differ_in_the_address_and_in_nothing_else():
    """Same traffic, one flag: the two runs have to stay comparable.

    A measurement means something only if the policy is the single variable, so
    this pins the shared shape -- the events, their order, the names learned, the
    zone descended to -- and the one field that differs.
    """
    referral = _referral([EVIL], glue=[(EVIL, EVIL_IP)])

    strict_sname, strict_slist, strict_entry = _descent()
    strict_steps = list(classify(referral, strict_sname, strict_slist, strict_entry))

    lenient_sname, lenient_slist, lenient_entry = _descent()
    lenient_steps = list(
        classify(
            referral,
            lenient_sname,
            lenient_slist,
            lenient_entry,
            glue_policy=GluePolicy.PERMISSIVE,
        )
    )

    assert [type(step) for step in strict_steps] == [type(step) for step in lenient_steps]
    assert [type(step).__name__ for step in strict_steps] == ["Referral", "VolunteeredGlue"]
    assert strict_slist.zone == lenient_slist.zone == ZONE
    assert strict_slist.entries[0].ns == lenient_slist.entries[0].ns == EVIL
    assert strict_slist.entries[0].addresses == []
    assert lenient_slist.entries[0].addresses == [EVIL_IP]
    assert [event.used for event in _glue_events(strict_steps)] == [False]
    assert [event.used for event in _glue_events(lenient_steps)] == [True]


# --------------------------------------------------- what the policy does not move


def test_permissive_does_not_reach_for_another_names_address():
    """Matching answer to question is a different defense (RFC 5452 section 9.1).

    That rule protects against an off-path forger guessing which reply to forge,
    not against a parent volunteering data nobody asked for, and this policy says
    nothing about it. A referral for ``ns.evil.net.`` carrying an address for
    some other owner name buys nothing under either policy.
    """
    for policy in (GluePolicy.STRICT, GluePolicy.PERMISSIVE):
        sname, slist, entry = _descent()
        steps = list(
            classify(
                _referral([EVIL], glue=[(DECOY, DECOY_IP)]),
                sname,
                slist,
                entry,
                glue_policy=policy,
            )
        )

        assert slist.entries[0].addresses == []
        assert _glue_events(steps) == []


def test_permissive_does_not_un_demote_a_lame_delegation():
    """Glue is mandatory below the cut, and that is reachability, not trust.

    RFC 1034 section 4.2.1: a nameserver inside the zone being delegated to it
    must be reachable without having first reached it. Volunteered data about
    *other* nameservers cannot change that, so the lame demotion stands either
    way -- otherwise the resolver descends into the zone it cannot reach, the
    two-branches-per-level blowup the check exists to prevent.
    """
    sname, slist, entry = _descent()
    steps = list(
        classify(
            _referral([NS1], glue=[(EVIL, EVIL_IP)]),
            sname,
            slist,
            entry,
            glue_policy=GluePolicy.PERMISSIVE,
        )
    )

    (ns_entry,) = slist.entries
    assert ns_entry.addresses == []
    assert ns_entry.history["lame"] == "in-bailiwick without glue"
    assert ns_entry.history["demoted"] is True
    assert any(isinstance(step, Demote) for step in steps)


# ------------------------------------------------------------------ construction


def test_lowering_the_filter_says_so_in_the_log(caplog):
    """A resolver built this way should be visible in the log of the run.

    The measurements are only interpretable after the fact if the record shows
    the defense was off, and a debug line would not survive the default level.
    """
    with caplog.at_level(logging.WARNING, logger="namespy.resolver"):
        resolver = RecursiveResolver(glue_policy=GluePolicy.PERMISSIVE)

    assert resolver.glue_policy is GluePolicy.PERMISSIVE
    assert "out-of-bailiwick glue will be believed" in caplog.text


def test_the_default_construction_says_nothing_about_glue(caplog):
    """The warning belongs to the deviation, not to the ordinary case."""
    with caplog.at_level(logging.WARNING, logger="namespy.resolver"):
        resolver = RecursiveResolver()

    assert resolver.glue_policy is GluePolicy.STRICT
    assert "out-of-bailiwick glue" not in caplog.text


def test_a_policy_that_could_not_apply_is_refused_at_the_door():
    """Strings arrive from config files and flags; nonsense must not be a default.

    The failure worth guarding is a typo that silently resolves with the safe
    policy while the researcher reports numbers they believe came from the
    permissive one.
    """
    assert RecursiveResolver(glue_policy="permissive").glue_policy is GluePolicy.PERMISSIVE
    assert RecursiveResolver(glue_policy="strict").glue_policy is GluePolicy.STRICT

    with pytest.raises(ValueError, match="GluePolicy"):
        RecursiveResolver(glue_policy="believe-everything")


def test_the_event_cannot_be_rewritten_afterwards():
    """A trace is read long after the response that produced it is gone."""
    (glue,) = _glue_events(
        [VolunteeredGlue(ns_name=EVIL, records=[], addresses=[EVIL_IP], used=True, reason="x")]
    )

    assert glue.addresses == (EVIL_IP,)
    with pytest.raises(AttributeError):
        glue.addresses = ()
