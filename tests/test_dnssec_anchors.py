"""Trust anchors and the first live chain: RFC 9718's document, the root's own keys.

Two fixtures, both captured from the running Internet on 2026-10-31 and embedded so the
tests never need the network: the IANA root-anchors.xml byte for byte as fetched, and a
real DNS response carrying the root apex DNSKEY RRset with its covering RRSIG (fetched
DO=1 over DNS-over-HTTPS, -- the answer was verified against the anchor file's digests
before being pinned, which is what makes an embedded copy trustworthy). Together they let
this suite do something no earlier fixture here could: walk the whole chain -- published
anchor to live key to live signature -- and land on SECURE.

The fixture RRSIG's own window (2026-10-29 to 2026-11-18, root signatures live about a
week-to-fortnight) is pinned with an explicit ``now``, so the test says the same thing in
2031 as it says today; what it cannot say forever is that *these* octets are still what
the root serves, which is why the digests are cross-checked against the anchor document
independently rather than trusted from the same fetch.
"""

import base64
import datetime

import pytest

from namespy import crypto
from namespy.anchors import (
    TrustAnchor,
    TrustAnchorFetchError,
    TrustAnchorFormatError,
    active_anchors,
    fetch_root_anchors,
    parse_root_anchors,
)
from namespy.crypto import crypto_available
from namespy.packet import DnsPacket
from namespy.rdata import RData_DNSKEY, RData_DS, RData_RRSIG
from namespy.verify import ChainOutcome, authenticate_dnskey_rrset


def _needs_backend() -> None:
    """Skip unless the probe itself reports a backend -- the convention in test_crypto_backend."""
    if not crypto_available():
        pytest.skip("namespy[crypto] is not installed")


# ------------------------------------------------------ live fixture: IANA root-anchors.xml
#
# Fetched 2026-10-31 from https://data.iana.org/root-anchors/root-anchors.xml (RFC 9718
# §3.1¶3), stored base64 so the bytes are exactly the bytes the server sent. Three keys:
# the withdrawn 2010 KSK (Kjqmt7v, tag 19036, validUntil 2019-01-11), the 2017 KSK
# (Klajeyz, 20326) and the 2024 KSK (Kmyv6jo, 38696) -- the latter two carrying the
# optional PublicKey/Flags pair RFC 9718 §2.2¶12 added.

IANA_ANCHORS_B64 = (
    "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPFRydXN0QW5jaG9yIGlkPSIwQzA1RkRENi00MjJDLTQ5MTAt"
    "OEVENi00MzBFRDE1RTExQzIiIHNvdXJjZT0iaHR0cDovL2RhdGEuaWFuYS5vcmcvcm9vdC1hbmNob3JzL3Jvb3QtYW5jaG9ycy54"
    "bWwiPgogICAgPFpvbmU+LjwvWm9uZT4KICAgIDxLZXlEaWdlc3QgaWQ9IktqcW10N3YiIHZhbGlkRnJvbT0iMjAxMC0wNy0xNVQw"
    "MDowMDowMCswMDowMCIgdmFsaWRVbnRpbD0iMjAxOS0wMS0xMVQwMDowMDowMCswMDowMCI+CiAgICAgICAgPEtleVRhZz4xOTAz"
    "NjwvS2V5VGFnPgogICAgICAgIDxBbGdvcml0aG0+ODwvQWxnb3JpdGhtPgogICAgICAgIDxEaWdlc3RUeXBlPjI8L0RpZ2VzdFR5"
    "cGU+CiAgICAgICAgPERpZ2VzdD40OUFBQzExRDdCNkY2NDQ2NzAyRTU0QTE2MDczNzE2MDdBMUE0MTg1NTIwMEZEMkNFMUNEREUz"
    "MkYyNEU4RkI1PC9EaWdlc3Q+CiAgICA8L0tleURpZ2VzdD4KICAgIDxLZXlEaWdlc3QgaWQ9IktsYWpleXoiIHZhbGlkRnJvbT0i"
    "MjAxNy0wMi0wMlQwMDowMDowMCswMDowMCI+CiAgICAgICAgPEtleVRhZz4yMDMyNjwvS2V5VGFnPgogICAgICAgIDxBbGdvcml0"
    "aG0+ODwvQWxnb3JpdGhtPgogICAgICAgIDxEaWdlc3RUeXBlPjI8L0RpZ2VzdFR5cGU+CiAgICAgICAgPERpZ2VzdD5FMDZENDRC"
    "ODBCOEYxRDM5QTk1QzBCMEQ3QzY1RDA4NDU4RTg4MDQwOUJCQzY4MzQ1NzEwNDIzN0M3RjhFQzhEPC9EaWdlc3Q+CiAgICAgICAg"
    "PFB1YmxpY0tleT5Bd0VBQWF6L3RBbTh5VG40TWZlaDVleUk5NldTVmV4VEJBdmtNZ0p6a0tUT2lXMXZrSWJ6eGVGMysvNFJnV09x"
    "N0hyeFJpeEhsRmxFeE9MQUpyNWVtTHZON1NXWGduTGg0K0I1eFFsTlZ6OE9nOGt2QXJNdE5ST3hWUXVDYVNuSURkRDVMS3lXYlJk"
    "Mm45V0dlMlI4UHpnQ21yM0VnVkxyanlCeFdlekYwakxId1ZOOGVmUzNyQ2ovRVdndklXZ2I5dGFycFZVREsvYjU4RGErc3FxbHMz"
    "ZU5idXY3cHIrZW9aRytTckRLNm5XZUwzYzZINUFweHo3TGpWYzF1VElkc0lYeHVPTFlBNC9pbEJtU1ZJenVEV2ZkUlVmaEhkWTYr"
    "Y244SEZSbSsyaE04QW5YR1h3czk1NTVLclVCNXFpaHlsR2E4c3ViWDJObjZVd05SMUFrVVRWNzRiVT08L1B1YmxpY0tleT4KICAg"
    "ICAgICA8RmxhZ3M+MjU3PC9GbGFncz4KICAgIDwvS2V5RGlnZXN0PgogICAgPEtleURpZ2VzdCBpZD0iS215djZqbyIgdmFsaWRG"
    "cm9tPSIyMDI0LTA3LTE4VDAwOjAwOjAwKzAwOjAwIj4KICAgICAgICA8S2V5VGFnPjM4Njk2PC9LZXlUYWc+CiAgICAgICAgPEFs"
    "Z29yaXRobT44PC9BbGdvcml0aG0+CiAgICAgICAgPERpZ2VzdFR5cGU+MjwvRGlnZXN0VHlwZT4KICAgICAgICA8RGlnZXN0PjY4"
    "M0QyRDBBQ0I4QzlCNzEyQTE5NDhCMjdGNzQxMjE5Mjk4RDBBNDUwRDYxMkM0ODNBRjQ0NEE0QzBGQjJCMTY8L0RpZ2VzdD4KICAg"
    "ICAgICA8UHVibGljS2V5PkF3RUFBYTk2amV1a25abGFlU3J2eUFKajZaSHYyOGhoT0treDNyTEdYVmFDNnJYVHNEYzQ0OS9jaWRs"
    "dHBreUd3Q0pObk9BbEZOS0YyakJvc1pCVTVlZUhzcGFRV09tT0VsWnNqSUNNUU1DM2FlSGJHaVNodlpzeDR3TVlTakg4ZTdWcmhi"
    "dTZpcndDelZCQXBFU2piVWRwV1dtRW5oYXRoV3Uxam8rc2lGVWlSQUF4bTlxeUpOZy93T1pxcXpML2RML3E4UGtjUlU1b1VLRXBV"
    "Z2U3MU0zZWoyLzdDUHFwZFZ3dU1vVHZvQitaT1Q0WWVHeXhNdkhtYnJ4bEZ6R09IT2lqdHpOK3UxVFFOYXRYMlhCdXpaTlExSytz"
    "MkNYa1BJWm83czZKZ1p5dmFCZXZZdHhQdllMdzR6OW1SN0sydmFGMThVWUg5WjlHTlVVZWF5ZmZLQzczUFljPTwvUHVibGljS2V5"
    "PgogICAgICAgIDxGbGFncz4yNTc8L0ZsYWdzPgogICAgPC9LZXlEaWdlc3Q+CjwvVHJ1c3RBbmNob3I+Cg=="
)

IANA_ANCHORS_XML = base64.b64decode(IANA_ANCHORS_B64).decode("utf-8")

# ------------------------------------------------- live fixture: signed root DNSKEY RRset
#
# A DNS response (root/DNSKEY, DO=1) captured over DNS-over-HTTPS on 2026-10-31: the
# root apex DNSKEY RRset -- KSK 38696, KSK 20326, ZSK 8763 -- and the one RRSIG the
# response carried, made by KSK 38696, labels 0, original TTL 172800, window 2026-10-29
# through 2026-11-18.

ROOT_DNSKEY_WIRE = (
    "2f3a81a000010004000000010000300001000030000100012ff001080101030803010001af7a8deba49d995a792aefc80263"
    "e991efdbc86138a931deb2c65d5682eab5d3b03738e3dfdc89d96da64c86c0224d9ce02514d285da3068b19054e5e787b296"
    "9058e98e12566c8c808c40c0b769e1db1a24a1bd9b31e303184a31fc7bb56b85bbba8abc02cd5040a444a36d47695969849e"
    "16ad856bb58e8fac8855224400319bdab224d83fc0e66aab32ff74bfeaf0f91c454e6850a1295207bbd4cdde8f6ffb08faa9"
    "755c2e3284efa01f99393e18786cb132f1e66ebc6517318e1ce8a3b7337ebb54d035ab57d9706ecd9350d4afacd825e43c86"
    "68eece89819caf6817af62dc4fbd82f0e33f6647b2b6bda175f14607f59f4635451e6b27df282ef73d87000030000100012f"
    "f001080101030803010001acffb409bcc939f831f7a1e5ec88f7a59255ec53040be432027390a4ce896d6f9086f3c5e177fb"
    "fe118163aaec7af1462c47945944c4e2c026be5e98bbcded25978272e1e3e079c5094d573f0e83c92f02b32d3513b1550b82"
    "6929c80dd0f92cac966d17769fd5867b647c3f38029abdc48152eb8f207159ecc5d232c7c1537c79f4b7ac28ff11682f2168"
    "1bf6d6aba555032bf6f9f036beb2aaa5b3778d6eebfba6bf9ea191be4ab0caea759e2f773a1f9029c73ecb8d5735b9321db0"
    "85f1b8e2d8038fe2941992548cee0d67dd4547e11dd63af9c9fc1c5466fb684cf009d7197c2cf79e792ab501e6a8a1ca519a"
    "f2cb9b5f6367e94c0d47502451357be1b5000030000100012ff001080100030803010001ca2b37135cf6dd2e7b565e9cf8d5"
    "311ba3950d982c1274a51ff85cc8c76f2f6faf4ddc4711522a75a9c5e8393cbdfce03f557aa752d5b8eb1b24ec1eda1a8332"
    "373625c577cb231cc3a7671bb9a69ffe501220eed6ac62054c31d52233562efdcfaddf4775430fefe8d60b3673a7cb04eee8"
    "7b9487b635b1946afc665caf12c43571d0a322a93ab3abf11dfea9deb02baf48281f3464166d917f6b744a8a264fb26178c4"
    "673674ce4005b6198d802ade02853d3d5954eba7723ac68b8dfdf02949549bd48d38ab3eb4ae8bb929916caebed53fed3da4"
    "5a301484bafd86eaf5df9c9d6ec8c6c6beda519ff60372f4e3ae9e83cc4e97c85e3841dc09de82b1e1e900002e000100012f"
    "f00113003008000002a3006b00df006ae52f809728005059096217b1ab96607ef3fea08cf6594250805f1b856f2cb772e75e"
    "d2013f4791712417ad883bfa5bb1c10620fb78a2655dbe0493dc3667ffa43bbeb8d3daa659073c92d787d592d2811564a50d"
    "93fd309370345cbe543924dd3d69ff2284d65b1c86c6e9feb9d57b79142a56946f49d94115aa8f5920c80e45f441021fc9ee"
    "f64c1e2db0f0670368960f27ba535e7b11c3c174d78abf871f8757003a578f21ac4bb3536834722efd9aea118e7333e18d27"
    "867bd936dad3d8d88f3ddac8148f5629c8eb839838e46a66c62db8b5d4ac1743e9459f57c2e37f76f43067c1b3b068658009"
    "c55c8daf9090175dc22f0fb8c6b6ccb2641675306ace9e6212d07d540000290200000080000000"
)

#: A moment inside the fixture RRSIG's own window, pinned so the suite says the same
#: thing in ten years that it says today.
ROOT_NOW = 1794312000

_ANCHORS = parse_root_anchors(IANA_ANCHORS_XML)


def _live_rrset():
    """The fixture's DNSKEY records and covering RRSIGs, parsed from the wire bytes."""
    packet, _used = DnsPacket.parse(bytes.fromhex(ROOT_DNSKEY_WIRE))
    dnskeys = [r.rdata for r in packet.answers if isinstance(r.rdata, RData_DNSKEY)]
    rrsigs = [r.rdata for r in packet.answers if isinstance(r.rdata, RData_RRSIG)]
    return dnskeys, rrsigs


# ------------------------------------------------------------------------------ §2.2 parsing


def test_the_published_file_parses_to_three_anchors():
    assert [a.key_tag for a in _ANCHORS] == [19036, 20326, 38696]
    assert all(a.zone == "." for a in _ANCHORS)
    assert [a.key_id for a in _ANCHORS] == ["Kjqmt7v", "Klajeyz", "Kmyv6jo"]
    assert all(a.algorithm == 8 and a.digest_type == 2 for a in _ANCHORS)
    assert all(len(a.digest) == 32 for a in _ANCHORS)


def test_the_withdrawn_key_is_active_only_inside_its_window():
    """§2.2¶7 read literally: validUntil is when a key stops being trusted, not recorded."""
    old = _ANCHORS[0]
    assert old.active(datetime.datetime(2018, 1, 1, tzinfo=datetime.UTC))
    assert not old.active(datetime.datetime(2019, 1, 11, tzinfo=datetime.UTC))
    assert not old.active()  # today, on every run of this suite

    current = _ANCHORS[2]  # Kmyv6jo, the 2024 KSK, pre-published before its ceremony
    assert not current.active(datetime.datetime(2024, 7, 17, tzinfo=datetime.UTC))
    assert current.active(datetime.datetime(2024, 7, 18, tzinfo=datetime.UTC))
    assert current.active()
    assert _ANCHORS[1].valid_until is None  # 20326: no recorded end
    assert [a.key_tag for a in active_anchors(_ANCHORS)] == [20326, 38696]


def test_publickeyinfo_is_carried_where_iana_publishes_it():
    """The 2010 entry predates the format's second half; the two KSKs carry it (§2.2¶12)."""
    assert _ANCHORS[0].public_key is None
    assert _ANCHORS[0].flags is None
    for anchor in _ANCHORS[1:]:
        assert anchor.flags == 257
        assert anchor.public_key is not None
        assert len(anchor.public_key) == 260  # RSA-2048


def test_the_published_keys_tag_and_digest_themselves():
    """The file's PublicKey octets rebuild the key the file's Digest describes.

    This is the anchor file checking *this package*: key tag (RFC 4034 Appendix B,
    erratum 4552) and DS digest (§5.1.4, SHA-256 per RFC 4509) computed over the live
    root keys IANA published, matching the numbers published beside them. No network, no
    backend, and nothing taken on trust from a DNS response -- both sides come from the
    one document, and agreement means the digest code and the document agree about the
    real keys.
    """
    for anchor in _ANCHORS[1:]:
        record = RData_DNSKEY(anchor.flags, 3, anchor.algorithm, anchor.public_key)
        assert record.key_tag == anchor.key_tag
        assert anchor.matches_dnskey(record)


def test_a_tag_preserving_edit_of_the_live_key_breaks_only_the_digest():
    """Two same-parity octet trades keep the weighted checksum (±255 nets to zero) and
    change the digest -- pinning that the digest, not the 16-bit tag, is the binding.
    The key tag is a checksum for finding candidate keys (RFC 4034 Appendix B), and
    RFC 4034 §8 is blunt that it is the DS record's "cryptographic digest" that points
    at a key; an edit this test cannot see coming is exactly what §5.1.4 guards."""
    anchor = _ANCHORS[2]
    key = bytearray(anchor.public_key)
    key[100] ^= 0x01
    key[102] ^= 0x01
    record = RData_DNSKEY(257, 3, anchor.algorithm, bytes(key))
    assert record.key_tag == anchor.key_tag  # tag survives, as it must
    assert not anchor.matches_dnskey(record)  # and the digest is what notices


def test_a_matching_digest_on_a_non_zone_key_excludes_the_pair():
    """RFC 4034 §5.2¶1: bit 7 or the DS is useless, however perfect its arithmetic."""
    anchor = _ANCHORS[2]
    record = RData_DNSKEY(256, 3, anchor.algorithm, anchor.public_key)  # zone key set
    ds = RData_DS.for_dnskey(".", record)  # a DS computed honestly, over these RDATA
    rebuilt = TrustAnchor(
        zone=".",
        key_tag=ds.key_tag,
        algorithm=ds.algorithm,
        digest_type=ds.digest_type,
        digest=ds.digest,
    )
    assert rebuilt.matches_dnskey(record)  # bit 7 set: the pair is usable
    solo = RData_DNSKEY(1, 3, anchor.algorithm, anchor.public_key)  # SEP bit only
    assert not solo.is_zone_key
    ds_solo = RData_DS.for_dnskey(".", solo)  # a DS that matches this key in every field
    anchor_solo = TrustAnchor(
        zone=".",
        key_tag=ds_solo.key_tag,
        algorithm=ds_solo.algorithm,
        digest_type=ds_solo.digest_type,
        digest=ds_solo.digest,
    )
    assert anchor_solo.key_tag == solo.key_tag
    assert anchor_solo.matches_dnskey(solo) is False  # digest cannot save it


# ------------------------------------------------------------------------------ §2.1 strictness


def _document(
    body: str, *, zone: str | None = ".", valid_from: str | None = "2024-01-01T00:00:00+00:00"
):
    """One KeyDigest around *body*, with each part switchable for the bad cases."""
    window = "" if valid_from is None else f" validFrom='{valid_from}'"
    zone_part = "" if zone is None else f"<Zone>{zone}</Zone>"
    return f"<TrustAnchor>{zone_part}<KeyDigest{window}>{body}</KeyDigest></TrustAnchor>"


_FULL = (
    "<KeyTag>1</KeyTag><Algorithm>8</Algorithm><DigestType>2</DigestType><Digest>"
    + "AB" * 32
    + "</Digest>"
)

_BAD = {
    "wrong root": "<NotTrustAnchor><Zone>.</Zone></NotTrustAnchor>",
    "no zone": _document(_FULL, zone=None),
    "no keydigest": "<TrustAnchor><Zone>.</Zone></TrustAnchor>",
    "no validFrom": _document(_FULL, valid_from=None),
    "tag over 65535": _document(
        f"<KeyTag>70000</KeyTag><Algorithm>8</Algorithm><DigestType>2</DigestType><Digest>{'AB' * 32}</Digest>"
    ),
    "algorithm over 255": _document(
        f"<KeyTag>1</KeyTag><Algorithm>256</Algorithm><DigestType>2</DigestType><Digest>{'AB' * 32}</Digest>"
    ),
    "digest not hex": _document(
        "<KeyTag>1</KeyTag><Algorithm>8</Algorithm><DigestType>2</DigestType><Digest>zzzz</Digest>"
    ),
    "digest wrong length": _document(
        f"<KeyTag>1</KeyTag><Algorithm>8</Algorithm><DigestType>2</DigestType><Digest>{'AB' * 31}</Digest>"
    ),
    "publickey without flags": _document(_FULL + "<PublicKey>oWVr</PublicKey>"),
    "flags without publickey": _document(_FULL + "<Flags>257</Flags>"),
    "element outside schema": _document(_FULL + "<Future>?</Future>"),
    "repeated keytag": _document(
        f"<KeyTag>1</KeyTag><KeyTag>2</KeyTag><Algorithm>8</Algorithm><DigestType>2</DigestType><Digest>{'AB' * 32}</Digest>"
    ),
    "negative tag": _document(
        f"<KeyTag>-1</KeyTag><Algorithm>8</Algorithm><DigestType>2</DigestType><Digest>{'AB' * 32}</Digest>"
    ),
    "keytag not a number": _document(
        f"<KeyTag>Kjqmt7v</KeyTag><Algorithm>8</Algorithm><DigestType>2</DigestType><Digest>{'AB' * 32}</Digest>"
    ),
    "empty digest": _document(
        "<KeyTag>1</KeyTag><Algorithm>8</Algorithm><DigestType>2</DigestType><Digest> </Digest>"
    ),
    "publickey not base64": _document(
        _FULL + "<PublicKey>not base64!!</PublicKey><Flags>257</Flags>"
    ),
    "bad validFrom": _document(_FULL, valid_from="18 July 2024"),
    "not xml at all": "TrustAnchor?Zone?.?",
}


@pytest.mark.parametrize("case", sorted(_BAD), ids=sorted(_BAD))
def test_the_schema_is_enforced_because_this_file_feeds_trust(case):
    with pytest.raises(TrustAnchorFormatError):
        parse_root_anchors(_BAD[case])


def test_a_fully_unknown_digest_type_still_parses():
    """§2.2¶5 defers digest types to the IANA registry; parsing must not pre-judge."""
    document = (
        "<TrustAnchor><Zone>.</Zone><KeyDigest validFrom='2024-01-01T00:00:00+00:00'>"
        "<KeyTag>1</KeyTag><Algorithm>8</Algorithm><DigestType>99</DigestType>"
        "<Digest>" + "AB" * 17 + "</Digest></KeyDigest></TrustAnchor>"
    )
    (anchor,) = parse_root_anchors(document)
    assert anchor.comparable is False
    assert anchor.digest == bytes.fromhex("AB" * 17)


def test_namespaced_copies_parse_and_naive_times_read_as_utc():
    namespaced = IANA_ANCHORS_XML.replace(
        "<TrustAnchor ", '<TrustAnchor xmlns="https://data.iana.org/DNS-KEY/1.1" ', 1
    )
    assert [a.key_tag for a in parse_root_anchors(namespaced)] == [19036, 20326, 38696]

    zulu = IANA_ANCHORS_XML.replace("2024-07-18T00:00:00+00:00", "2024-07-18T00:00:00Z")
    (third,) = [a for a in parse_root_anchors(zulu) if a.key_tag == 38696]
    assert third.valid_from == datetime.datetime(2024, 7, 18, tzinfo=datetime.UTC)
    naive = IANA_ANCHORS_XML.replace("2024-07-18T00:00:00+00:00", "2024-07-18T00:00:00")
    (third,) = [a for a in parse_root_anchors(naive) if a.key_tag == 38696]
    assert third.valid_from.utcoffset() == datetime.timedelta(0)


# ------------------------------------------------------------------------------ §3.1 retrieval


def test_fetch_parses_what_the_opener_returns():
    anchors = fetch_root_anchors(opener=lambda _url, _timeout: IANA_ANCHORS_XML.encode("utf-8"))
    assert [a.key_tag for a in anchors] == [19036, 20326, 38696]


def test_fetch_failures_are_fetch_errors_and_bad_bytes_are_fetch_errors():
    def broken(_url, _timeout):
        raise OSError("connection reset")

    with pytest.raises(TrustAnchorFetchError):
        fetch_root_anchors(opener=broken)
    with pytest.raises(TrustAnchorFetchError):
        fetch_root_anchors(opener=lambda _url, _timeout: b"\xff\xfe\x00not xml")


def test_a_malformed_retrieval_is_a_format_error_not_a_fetch_error():
    """The operator's next action differs, and the exception type is how they tell."""
    with pytest.raises(TrustAnchorFormatError):
        fetch_root_anchors(opener=lambda _url, _timeout: b"<TrustAnchor/>")


# --------------------------------------------------------------------- the live chain, end to end


def test_the_fixture_is_the_signed_root_rrset():
    dnskeys, rrsigs = _live_rrset()
    assert sorted(int(k.key_tag) for k in dnskeys) == [8763, 20326, 38696]
    assert [int(r.key_tag) for r in rrsigs] == [38696]
    (rrsig,) = rrsigs
    assert str(rrsig.signer_name) == "."
    assert rrsig.labels == 0
    assert rrsig.original_ttl == 172800
    assert rrsig.inception <= ROOT_NOW < rrsig.expiration


def test_the_live_anchor_set_matches_the_live_key_set():
    """Without any backend: the published digests pick out exactly the published keys.

    19036 -- the withdrawn 2010 KSK -- is the informative half of this assertion: it is
    absent from today's RRset and matches nothing, which is what an operator whose
    software still trusts only that key will experience at the next query: not a
    failure, but the absence of a path.
    """
    dnskeys, _rrsigs = _live_rrset()
    by_tag = {int(k.key_tag): k for k in dnskeys}
    assert _ANCHORS[0].matches_dnskey(by_tag[38696]) is False
    assert _ANCHORS[1].matches_dnskey(by_tag[20326])
    assert _ANCHORS[2].matches_dnskey(by_tag[38696])
    assert _ANCHORS[2].matches_dnskey(by_tag[20326]) is False


def test_the_root_chains_from_the_published_anchors():
    """Anchor to key to signature, on live octets: the whole point of the module."""
    _needs_backend()
    dnskeys, rrsigs = _live_rrset()
    trusted = [a.ds_record() for a in active_anchors(_ANCHORS)]
    verdict = authenticate_dnskey_rrset(".", dnskeys, rrsigs, trusted, now=ROOT_NOW)
    assert verdict.secure
    assert verdict.matched_key_tag == 38696
    assert verdict.attempts == 1


def test_the_other_ksk_matching_the_anchor_proves_nothing_by_itself():
    """RFC 4035 §5.2¶5 is about *the matched key's* signature, not any signature.

    20326 is an active anchor and sits in the RRset, but the response carried only
    38696's signature over the set. Trusting only the 20326 anchor, the matched key has
    signed nothing here -- and a validator that let *some* verified signature stand in
    for *the* matched key's would call this secure. It is not; the ceremony that moves
    signing to a new KSK is exactly the moment that confusion would bite.
    """
    _needs_backend()
    dnskeys, rrsigs = _live_rrset()
    only_20326 = [_ANCHORS[1].ds_record()]
    verdict = authenticate_dnskey_rrset(".", dnskeys, rrsigs, only_20326, now=ROOT_NOW)
    assert verdict.outcome is ChainOutcome.BOGUS
    assert "5.2\u00b65" in verdict.reason
    assert verdict.attempts == 0  # no RRSIG even named key 20326: nothing was checkable


def test_the_withdrawn_anchor_finds_no_path_and_says_so_in_digest_terms():
    dnskeys, rrsigs = _live_rrset()
    verdict = authenticate_dnskey_rrset(
        ".", dnskeys, rrsigs, [_ANCHORS[0].ds_record()], now=ROOT_NOW
    )
    assert verdict.outcome is ChainOutcome.BOGUS
    assert "5.2\u00b64" in verdict.reason


def test_one_edited_octet_of_the_signing_key_severs_the_chain_before_any_arithmetic():
    dnskeys, rrsigs = _live_rrset()
    (signing,) = [k for k in dnskeys if int(k.key_tag) == 38696]
    edited = bytearray(signing.public_key)
    edited[7] ^= 0x40
    replaced = [
        RData_DNSKEY(k.flags, k.protocol, k.algorithm, bytes(edited)) if k is signing else k
        for k in dnskeys
    ]
    verdict = authenticate_dnskey_rrset(
        ".", replaced, rrsigs, [_ANCHORS[2].ds_record()], now=ROOT_NOW
    )
    assert verdict.outcome is ChainOutcome.BOGUS
    assert "5.2\u00b64" in verdict.reason


def test_a_flipped_octet_of_the_signature_refuses_the_chain_after_the_arithmetic():
    """The paired key matches; the signature says no -- §5.2¶5's actual refusal."""
    _needs_backend()
    dnskeys, rrsigs = _live_rrset()
    (rrsig,) = rrsigs
    signature = bytearray(rrsig.signature)
    signature[-1] ^= 0x01
    tampered = RData_RRSIG(
        rrsig.type_covered,
        rrsig.algorithm,
        rrsig.labels,
        rrsig.original_ttl,
        rrsig.expiration,
        rrsig.inception,
        rrsig.key_tag,
        rrsig.signer_name,
        bytes(signature),
    )
    trusted = [a.ds_record() for a in active_anchors(_ANCHORS)]
    verdict = authenticate_dnskey_rrset(".", dnskeys, [tampered], trusted, now=ROOT_NOW)
    assert verdict.outcome is ChainOutcome.BOGUS
    assert verdict.attempts == 1
    assert "5.2\u00b65" in verdict.reason


def test_an_unsigned_apex_rrset_is_the_simpler_bogus():
    dnskeys, _rrsigs = _live_rrset()
    trusted = [a.ds_record() for a in active_anchors(_ANCHORS)]
    verdict = authenticate_dnskey_rrset(".", dnskeys, [], trusted, now=ROOT_NOW)
    assert verdict.outcome is ChainOutcome.BOGUS
    assert "no RRSIG" in verdict.reason


def test_a_trust_point_with_an_unusable_digest_type_is_indeterminate_not_bogus():
    """RFC 4035 §5.2¶8/¶10, at the digest rather than the signature layer."""
    dnskeys, rrsigs = _live_rrset()
    signing = next(k for k in dnskeys if int(k.key_tag) == 38696)
    mystery = RData_DS(signing.key_tag, signing.algorithm, 99, b"\x00" * 20)
    verdict = authenticate_dnskey_rrset(".", dnskeys, rrsigs, [mystery], now=ROOT_NOW)
    assert verdict.outcome is ChainOutcome.INDETERMINATE
    assert "5.2\u00b610" in verdict.reason


def test_without_a_backend_the_live_chain_is_indeterminate(monkeypatch):
    """The whole Indeterminate argument, run against the real root: a missing optional
    dependency must never read as "the root is forging"."""
    monkeypatch.setattr(crypto, "_BACKEND", None)
    monkeypatch.setattr(crypto, "_PROBED", True)
    dnskeys, rrsigs = _live_rrset()
    trusted = [a.ds_record() for a in active_anchors(_ANCHORS)]
    verdict = authenticate_dnskey_rrset(".", dnskeys, rrsigs, trusted, now=ROOT_NOW)
    assert verdict.outcome is ChainOutcome.INDETERMINATE
    assert "could not be examined" in verdict.reason


def test_the_two_degenerate_argument_cases_are_programming_errors():
    dnskeys, rrsigs = _live_rrset()
    trusted = [_ANCHORS[2].ds_record()]
    with pytest.raises(ValueError, match="dnskeys is empty"):
        authenticate_dnskey_rrset(".", [], rrsigs, trusted)
    with pytest.raises(ValueError, match="trusted is empty"):
        authenticate_dnskey_rrset(".", dnskeys, rrsigs, [])


def test_a_ds_pointing_at_a_non_zone_key_names_the_exclusion_precisely():
    """The chain-level sibling of the anchor-level §5.2¶1 test, on live RDATA."""
    dnskeys, rrsigs = _live_rrset()
    signing = next(k for k in dnskeys if int(k.key_tag) == 38696)
    solo = RData_DNSKEY(1, 3, signing.algorithm, signing.public_key)  # zone bit clear
    ds = RData_DS.for_dnskey(".", solo)  # matches solo in tag, algorithm and digest
    verdict = authenticate_dnskey_rrset(".", [solo], rrsigs, [ds], now=ROOT_NOW)
    assert verdict.outcome is ChainOutcome.BOGUS
    assert "Zone Flag" in verdict.reason


def test_a_live_signature_under_a_foreign_signer_is_no_signature_at_all():
    """16-bit tags collide; §5.2¶5's "signed the child zone's ... RRset" is about the
    signer, not the number. The fixture's own RRSIG, relabelled as signer "com.", is
    refused as evidence about the root although tag and algorithm agree with the
    matched anchor key -- the signer check is what stops one zone's signature being
    carried across a boundary by a colliding tag, and it runs before any arithmetic."""
    dnskeys, rrsigs = _live_rrset()
    (rrsig,) = rrsigs
    foreign = RData_RRSIG(
        rrsig.type_covered,
        rrsig.algorithm,
        rrsig.labels,
        rrsig.original_ttl,
        rrsig.expiration,
        rrsig.inception,
        rrsig.key_tag,
        "com.",
        rrsig.signature,
    )
    trusted = [a.ds_record() for a in active_anchors(_ANCHORS)]
    verdict = authenticate_dnskey_rrset(".", dnskeys, [foreign], trusted, now=ROOT_NOW)
    assert verdict.outcome is ChainOutcome.BOGUS
    assert verdict.attempts == 0


def test_the_repr_shows_the_operator_the_window_and_the_name():
    text = repr(_ANCHORS[0])
    assert "Kjqmt7v" in text
    assert "19036" in text
    assert "2019-01-11" in text
    assert "open" in repr(_ANCHORS[1])  # 20326: no validUntil
