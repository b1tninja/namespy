"""DNSSEC record codecs: DNSKEY, DS, key tags, DS digests (RFC 4034 §2, §5, App. B).

The vectors are the RFC's own. §2.3 prints a DNSKEY for example.com; §5.4 prints a
DNSKEY *and its DS*, which pins three things at once -- the key tag (60485), the
digest (2BB183AF...2118), and the concatenation rule of §5.1.4 that produces it.
Nothing here is a value this module computed for itself and then agreed with.

Where a rule has no published number, the test says so and asserts the property
instead: the key tag is checked against a second, independent transcription of
Appendix B's reference C code, and §6.2's downcasing is checked by requiring an
upper-cased owner to hash to the same digest as a lower-cased one.
"""

import struct

import pytest

from namespy.dnssec import (
    DNSKEY_FLAG_REVOKED,
    DNSKEY_FLAG_SEP,
    DNSKEY_FLAG_ZONE_KEY,
    RSA_MD5_ALGORITHM,
    DigestType,
    canonical_owner_octets,
    decode_base64_field,
    decode_hex_field,
    ds_digest,
    encode_hex_field,
    key_tag,
    known_digest_octets,
)
from namespy.enums import DnsRClass, DnsRType
from namespy.names import DomainName
from namespy.packet import DnsRecord
from namespy.rdata import RData_DNSKEY, RData_DS, rdata_class_for
from namespy.wire import DnsPacketParseError

# RFC 4034 §5.4: the DNSKEY, its key tag, and the DS that refers to it. Written as
# the RFC's own wrapped lines, so the reader can be checked against the page.
DSKEY_OWNER = "dskey.example.com."
DSKEY_BASE64 = (
    "AQOeiiR0GOMYkDshWoSKz9Xz"
    "fwJr1AYtsmx3TGkJaNXVbfi/"
    "2pHm822aJ5iI9BMzNXxeYCmZ"
    "DRD99WYwYqUSdjMmmAphXdvx"
    "egXd/M5+X7OrzKBaMbCVdFLU"
    "Uh6DhweJBjEVv5f2wwjM9Xzc"
    "nOf+EPbtG9DMBmADjFDc2w/r"
    "ljwvFw=="
)
DSKEY_FLAGS, DSKEY_PROTOCOL, DSKEY_ALGORITHM = 256, 3, 5
DSKEY_PUBLISHED_KEY_TAG = 60485
DSKEY_PUBLISHED_SHA1 = "2BB183AF5F22588179A53B0A98631FAD1A292118"

# RFC 4034 §2.3: a second published key, for parsing and presentation.
EXAMPLE_BASE64 = (
    "AQPSKmynfzW4kyBv015MUG2DeIQ3"
    "Cbl+BBZH4b/0PY1kxkmvHjcZc8no"
    "kfzj31GajIQKY+5CptLr3buXA10h"
    "WqTkF7H6RfoRqXQeogmMHfpftf6z"
    "Mv1LyBUgia7za6ZEzOJBOztyvhjL"
    "742iU/TpPSEDhm2SNKLijfUppn1U"
    "aNvv4w=="
)


def _dskey() -> RData_DNSKEY:
    return RData_DNSKEY(DSKEY_FLAGS, DSKEY_PROTOCOL, DSKEY_ALGORITHM, DSKEY_BASE64)


# ------------------------------------------------------------------ key tag


def test_key_tag_of_the_published_example_key():
    """RFC 4034 §5.4 states the key tag of its own DNSKEY: 60485."""
    assert _dskey().key_tag == DSKEY_PUBLISHED_KEY_TAG
    assert key_tag(_dskey().to_wire()) == DSKEY_PUBLISHED_KEY_TAG


def _reference_key_tag(rdata: bytes) -> int:
    """Appendix B's reference C function, transcribed a second time.

    A checksum with no published vector is exactly the thing not to verify against
    itself, so this loop was written from the C independently of the implementation
    and the two are compared below. If someone later "simplifies" the production
    version into a ones-complement checksum, this is what notices.
    """
    total = 0
    for index in range(len(rdata)):
        total += rdata[index] if index % 2 else rdata[index] << 8
    total += (total >> 16) & 0xFFFF
    return total & 0xFFFF


@pytest.mark.parametrize(
    "public_key",
    [
        b"\x00",
        b"\x00\x01",
        b"\x00\x01\x02",
        b"\xff\xff\xff\xff",
        b"\xff\xff\x00\x00\xff",
        bytes(range(1, 64)),
        b"\x01" * 4096,
    ],
)
def test_key_tag_agrees_with_the_reference_transcription(public_key):
    """Including the odd length, where the last octet counts as a high byte."""
    rdata = bytes([DSKEY_FLAGS >> 8, DSKEY_FLAGS & 0xFF, DSKEY_PROTOCOL, 8]) + public_key
    assert key_tag(rdata) == _reference_key_tag(rdata)


def test_key_tag_is_not_reduction_modulo_65535():
    """Erratum 4552 warns that the two are "often the same ... but not always".

    Here they differ, and the C reference wins: the accumulator keeps its carries,
    the high bits are folded in once, and only a carry produced by *that* addition
    is dropped. The modulo shortcut would agree on most keys and disagree on some --
    the worst failure shape available, since the disagreement lands on a delegation.
    """
    rdata = bytes([0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01])
    # Three 16-bit groups: 0xFFFF + 0xFFFF + 0x0001 = 0x1FFFF. Folding the carry
    # gives 0x1FFFF + 1 = 0x20000, whose low 16 bits are 0 -- and the carry that the
    # fold itself produced is what §B says to discard. 0x1FFFF reduced modulo 65535
    # is 1 instead. One bit of difference, on the only input in this file chosen to
    # show it.
    assert key_tag(rdata) == _reference_key_tag(rdata)
    assert key_tag(rdata) == 0
    assert 0x1FFFF % 65535 == 1


def test_key_tag_for_rsa_md5_follows_the_corrected_reading():
    """§B.1 gives algorithm 1 a different rule, and erratum 193 fixes its wording.

    The normative phrase is "the most significant 16 bits of the least significant
    24 bits" of the modulus; the RFC's parenthetical said "4th to last and 3rd to
    last", which contradicts it, and the verified erratum corrects it to "3rd to last
    and 2nd to last". This modulus is built so the two readings differ, which pins
    the choice instead of leaving it to whoever reads the prose first.
    """
    modulus = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE])
    rdata = bytes([DSKEY_FLAGS >> 8, DSKEY_FLAGS & 0xFF, DSKEY_PROTOCOL, RSA_MD5_ALGORITHM])
    rdata += modulus
    assert key_tag(rdata) == 0xCCDD  # 3rd- and 2nd-to-last, per the erratum
    assert key_tag(rdata) != 0xBBCC  # not the 4th/3rd the original text implied


def test_key_tag_reads_its_algorithm_from_the_rdata():
    """So a caller cannot hand over bytes and an argument that disagree.

    §B defines the function over "the wire format of the RDATA portion of the DNSKEY
    RR", which is also what makes the algorithm-1 branch reachable without a second
    parameter drifting away from the first.
    """
    body = bytes([0x01, 0x02, 0x03, 0x04, 0x05])
    general = bytes([1, 0, 3, 8]) + body
    md5 = bytes([1, 0, 3, RSA_MD5_ALGORITHM]) + body
    assert key_tag(general) == _reference_key_tag(general)
    assert key_tag(md5) == 0x0304
    assert key_tag(general) != key_tag(md5)


def test_key_tag_refuses_rdata_with_no_key():
    with pytest.raises(ValueError, match="public key"):
        key_tag(bytes([1, 0, 3, 8]))
    with pytest.raises(ValueError, match="modulus"):
        key_tag(bytes([1, 0, 3, RSA_MD5_ALGORITHM, 0xFF, 0xFE]))


# ------------------------------------------------------------------- DNSKEY


def _example() -> RData_DNSKEY:
    """RFC 4034 §2.3's key for example.com: flags 256, protocol 3, algorithm 5."""
    return RData_DNSKEY(256, 3, 5, EXAMPLE_BASE64)


def test_dnskey_reads_the_rfc_4034_example():
    """The three header fields come back as printed, and the key as 130 octets."""
    key = _dskey()
    assert (key.flags, key.protocol, key.algorithm) == (
        DSKEY_FLAGS,
        DSKEY_PROTOCOL,
        DSKEY_ALGORITHM,
    )
    assert len(key.public_key) == 130
    assert key.to_wire()[:4] == bytes([1, 0, 3, 5])
    assert _example().algorithm == 5


def test_dnskey_presentation_is_one_master_file_line():
    """§2.2: decimals, then one Base64 token -- no folding, unlike §2.3's page."""
    text = _dskey().to_presentation()
    assert text.startswith("256 3 5 ")
    assert "\n" not in text
    # What §5.4 printed is what a reader should be able to paste back in.
    assert decode_base64_field(text.split(" ", 3)[3], what="public key") == _dskey().public_key


def test_dnskey_survives_a_record_round_trip():
    """Through a whole RR, because that is the only way these arrive in practice."""
    record = DnsRecord(
        DomainName("example.com."), DnsRType.DNSKEY, DnsRClass.IN, 86400, rdata=_dskey()
    )
    blob = bytes(record)
    parsed, offset = DnsRecord.parse(blob, 0)
    assert offset == len(blob)
    assert isinstance(parsed.rdata, RData_DNSKEY)
    assert parsed.rdata == _dskey()
    assert parsed.rdata.key_tag == DSKEY_PUBLISHED_KEY_TAG


def test_dnssec_codecs_are_registered_on_their_wire_numbers():
    assert rdata_class_for(int(DnsRType.DNSKEY)) is RData_DNSKEY
    assert rdata_class_for(int(DnsRType.DS)) is RData_DS


def test_dnskey_flags_are_numbered_from_the_most_significant_bit():
    """Why 256 means "zone key" and 257 means "zone key, and also a KSK".

    §2.1.1 numbers bits from the top of the 16-bit field, so bit 7 is 0x0100 and
    bit 15 is 0x0001. Getting this backwards would read every ZSK as a KSK.
    """
    assert DNSKEY_FLAG_ZONE_KEY == 0x0100
    assert DNSKEY_FLAG_SEP == 0x0001
    assert DNSKEY_FLAG_REVOKED == 0x0080

    zsk = RData_DNSKEY(256, 3, 5, b"\x01\x02")
    ksk = RData_DNSKEY(257, 3, 5, b"\x01\x02")
    revoked_ksk = RData_DNSKEY(257 + DNSKEY_FLAG_REVOKED, 3, 5, b"\x01\x02")
    assert zsk.is_zone_key
    assert not zsk.is_secure_entry_point
    assert ksk.is_zone_key
    assert ksk.is_secure_entry_point
    # 385 is what a revoked KSK actually carries in a zone file, which is the only
    # reason these numbers are worth pinning.
    assert revoked_ksk.is_revoked
    assert revoked_ksk.is_zone_key
    assert revoked_ksk.is_secure_entry_point


def test_reserved_flag_bits_are_ignored_on_receipt():
    """§2.1.1¶3: reserved bits "MUST have value 0 upon creation and MUST be ignored
    upon receipt" -- ignored, not rejected, and not silently cleared either."""
    key = RData_DNSKEY(0xFFFF, 3, 5, b"\x01\x02")
    assert key.flags == 0xFFFF
    assert key.is_zone_key
    assert key.is_secure_entry_point
    assert key.is_revoked
    # The reserved bits still reach the wire, because the codec reproduces what it
    # was given: clearing them here would change the bytes a DS hashes.
    assert key.to_wire()[0] == 0xFF


@pytest.mark.parametrize(
    ("flags", "protocol", "revoked", "expected"),
    [
        (256, 3, False, True),  # a plain ZSK
        (257, 3, False, True),  # a KSK
        (256 | DNSKEY_FLAG_REVOKED, 3, True, True),  # retired, but still a key
        (DNSKEY_FLAG_SEP, 3, False, False),  # §2.1.1¶2: SEP without the zone flag
        (0, 3, False, False),  # §2.1.1¶1: not a zone key
        (256, 4, False, False),  # §2.1.2: protocol must be 3
        (257, 0, False, False),
    ],
)
def test_may_verify_rrsets_applies_the_three_musts(flags, protocol, revoked, expected):
    key = RData_DNSKEY(flags, protocol, 5, b"\x01\x02")
    assert key.may_verify_rrsets is expected
    assert key.is_revoked is revoked


def test_dnskey_rejects_a_key_with_no_material():
    with pytest.raises(ValueError, match="empty"):
        RData_DNSKEY(256, 3, 5, b"")
    # Four octets is the header and nothing else, which §2.1 cannot describe.
    with pytest.raises(DnsPacketParseError, match="must exceed"):
        RData_DNSKEY.parse_from(bytes([1, 0, 3, 5]), 0, 4)


@pytest.mark.parametrize(
    ("flags", "protocol", "algorithm"),
    [(0x10000, 3, 5), (256, 256, 5), (256, 3, 256), (-1, 3, 5)],
)
def test_dnskey_refuses_fields_that_do_not_fit(flags, protocol, algorithm):
    """No silent masking: a 17-bit flags value is a caller bug, not a wide field."""
    with pytest.raises(ValueError, match="must be 0"):
        RData_DNSKEY(flags, protocol, algorithm, b"\x01\x02")


def test_wrapped_base64_reads_and_garbage_does_not():
    """§2.3's key is printed over five lines; a mistyped character is refused.

    The refusal matters more than the tolerance: base64 decoding without validation
    drops illegal characters, which turns a corrupt key into a different, valid-looking
    one that belongs to a key pair nobody holds.
    """
    wrapped = "AQOe iiR0 GOMY\nkDshWoSKz9Xz" + DSKEY_BASE64[24:]
    assert decode_base64_field(wrapped, what="public key") == _dskey().public_key
    with pytest.raises(ValueError, match="not valid Base64"):
        decode_base64_field("AQOe!iR0", what="public key")
    with pytest.raises(ValueError, match="not valid Base64"):
        decode_base64_field("AQOei", what="public key")  # a truncated quantum


# --------------------------------------------------------------------- DS


def test_ds_digest_matches_the_published_ds():
    """RFC 4034 §5.4: SHA-1 over "dskey.example.com." | DNSKEY RDATA.

    The one test that validates the whole construction at once -- §2.1's wire layout,
    §5.1.4's bare concatenation with no separator or length, and §6.2's downcasing.
    Neither number here came from this code.
    """
    digest = ds_digest(DSKEY_OWNER, _dskey().to_wire(), DigestType.SHA1)
    assert digest.hex().upper() == DSKEY_PUBLISHED_SHA1
    assert len(digest) == DigestType.SHA1.digest_octets == 20


def test_ds_for_dnskey_is_the_record_the_rfc_prints():
    """§5.1.1/§5.1.2: the key tag and algorithm are copied from the key it names."""
    ds = RData_DS.for_dnskey(DSKEY_OWNER, _dskey(), DigestType.SHA1)
    assert ds.key_tag == DSKEY_PUBLISHED_KEY_TAG
    assert ds.algorithm == DSKEY_ALGORITHM
    assert ds.digest_type == int(DigestType.SHA1)
    assert ds.to_presentation() == f"60485 5 1 {DSKEY_PUBLISHED_SHA1}"


def test_ds_digest_downcases_the_owner_name():
    """§6.2 item 2 -- which no published example demonstrates and every one needs.

    A DNSKEY arrives under whatever case the zone file used; its DS has to be the same
    record either way, or a delegation breaks because someone typed the name in caps.
    """
    lower = ds_digest("dskey.example.com.", _dskey().to_wire(), DigestType.SHA1)
    upper = ds_digest("DSKEY.EXAMPLE.COM.", _dskey().to_wire(), DigestType.SHA1)
    mixed = ds_digest("DsKeY.ExAmPlE.cOm.", _dskey().to_wire(), DigestType.SHA1)
    assert lower == upper == mixed == bytes.fromhex(DSKEY_PUBLISHED_SHA1)
    # The octets fed to the hash, spelled out: three labels each preceded by its
    # length, then the root terminator -- 6 + 8 + 4 + 1, and no padding, separator or
    # count anywhere. (Not 20, which is SHA-1's output length and a trap in a comment.)
    canonical = canonical_owner_octets("DSKEY.example.com.")
    assert canonical == b"\x05dskey\x07example\x03com\x00"
    assert len(canonical) == 19


def test_ds_digest_covers_the_flags_so_revocation_changes_it():
    """RFC 5011 §2.1: a revoked key "has a different fingerprint".

    The flags sit inside the hashed RDATA (§5.1.4¶5), so setting REVOKE produces a
    different DS instead of leaving the old one usable -- which is why an operator
    sets the bit before asking the parent to update, not after.
    """
    key = _dskey()
    revoked = RData_DNSKEY(
        key.flags | DNSKEY_FLAG_REVOKED, key.protocol, key.algorithm, key.public_key
    )
    original = ds_digest(DSKEY_OWNER, key.to_wire(), DigestType.SHA1)
    assert ds_digest(DSKEY_OWNER, revoked.to_wire(), DigestType.SHA1) != original

    ds = RData_DS.for_dnskey(DSKEY_OWNER, key, DigestType.SHA1)
    assert ds.refers_to(key, DSKEY_OWNER)
    assert not ds.refers_to(revoked, DSKEY_OWNER)


@pytest.mark.parametrize("name", ["dskey.example.com", "www.example", "com"])
def test_ds_digest_refuses_a_name_that_is_not_fully_qualified(name):
    """§5.1.4 asks for "the fully qualified owner name of the DNSKEY RR".

    A relative name hashes to something that matches nothing, and the failure surfaces
    as a broken delegation in somebody else's zone months later -- so the check
    belongs where the hash is taken rather than left to the operator who compares the
    records. (The root is *not* refused: it is fully qualified, and a codec is not the
    place to rule on whether a parent could publish a DS for it.)
    """
    with pytest.raises(ValueError, match="fully qualified"):
        ds_digest(name, _dskey().to_wire(), DigestType.SHA1)


@pytest.mark.parametrize(
    ("digest_type", "octets"),
    [(DigestType.SHA1, 20), (DigestType.SHA256, 32), (DigestType.SHA384, 48)],
)
def test_supported_digest_types_produce_their_hash_length(digest_type, octets):
    """RFC 4034 App. A.2 (SHA-1), RFC 4509 §2 (SHA-256), RFC 6605 §2 (SHA-384)."""
    digest = ds_digest(DSKEY_OWNER, _dskey().to_wire(), digest_type)
    assert len(digest) == octets == digest_type.digest_octets
    assert RData_DS.for_dnskey(DSKEY_OWNER, _dskey(), digest_type).digest == digest


def test_minting_an_unsupported_digest_type_says_so_by_number():
    """Reading a DS of any digest type is fine; inventing one is not."""
    with pytest.raises(ValueError, match="15 is not implemented"):
        ds_digest(DSKEY_OWNER, _dskey().to_wire(), 15)


def test_a_declared_digest_type_without_a_hasher_says_which(monkeypatch):
    """The guard in :attr:`DigestType.hasher`, exercised by manufacturing its cause.

    Reaching it needs a ``DigestType`` member with no entry in the hasher table --
    exactly what someone adding the next registry number will forget. No caller can
    produce that state today, because :func:`ds_digest` screens unknown numbers first,
    so the test deletes the entry rather than leaving the branch to be "obviously"
    right. What it must do is name the type: a bare KeyError inside a resolver is
    indistinguishable from a bug in the resolver.
    """
    import namespy.dnssec as dnssec_module

    monkeypatch.delitem(dnssec_module._HASHERS, int(DigestType.SHA384))
    # Reached through the public path, since that is where a caller would feel it.
    with pytest.raises(ValueError, match="4 is not implemented"):
        ds_digest(DSKEY_OWNER, _dskey().to_wire(), DigestType.SHA384)
    # Reading stays forgiving, in the same direction as an unknown type in a record:
    # unknown length, not an exception.
    assert known_digest_octets(int(DigestType.SHA384)) is None


def test_ds_with_an_unknown_digest_type_still_parses_and_prints():
    """The asymmetry, pinned: the registry grows and the wire does not wait.

    Digest type 15 is a delegation somebody else made. Refusing to parse it would
    turn an unfamiliar number into a SERVFAIL, a far stronger claim about the world
    than "I cannot compute this" warrants.
    """
    digest = bytes(range(32))
    ds = RData_DS(12345, 15, 15, digest)
    blob = ds.to_wire()
    parsed = RData_DS.parse_from(blob, 0, len(blob))
    assert parsed.digest_type == 15
    assert parsed.digest == digest
    assert parsed.to_presentation().startswith("12345 15 15 ")
    assert not parsed.refers_to(_dskey(), DSKEY_OWNER)


@pytest.mark.parametrize(
    ("digest_type", "digest"),
    [(int(DigestType.SHA1), bytes(32)), (int(DigestType.SHA256), bytes(20))],
)
def test_ds_rejects_a_digest_of_the_wrong_length(digest_type, digest):
    """The length is the only thing about a DS that says which hash was run.

    A record that gets it wrong cannot be repaired afterwards by guessing, so this is
    a malformed RR rather than a suspicious one. Unknown types are exempt: there is no
    length to demand of them.
    """
    blob = struct.pack("!HBB", DSKEY_PUBLISHED_KEY_TAG, DSKEY_ALGORITHM, digest_type) + digest
    with pytest.raises(DnsPacketParseError, match="must be"):
        RData_DS.parse_from(blob, 0, len(blob))


def test_ds_survives_a_record_round_trip():
    ds = RData_DS.for_dnskey(DSKEY_OWNER, _dskey(), DigestType.SHA256)
    record = DnsRecord(DomainName(DSKEY_OWNER), DnsRType.DS, DnsRClass.IN, 86400, rdata=ds)
    blob = bytes(record)
    parsed, offset = DnsRecord.parse(blob, 0)
    assert offset == len(blob)
    assert parsed.rdata == ds
    assert parsed.rdata.refers_to(_dskey(), DSKEY_OWNER)


def test_ds_accepts_a_digest_written_in_hex():
    """§5.3: case-insensitive hex with whitespace allowed -- how §5.4 shows one."""
    ds = RData_DS(DSKEY_PUBLISHED_KEY_TAG, DSKEY_ALGORITHM, 1, DSKEY_PUBLISHED_SHA1)
    assert ds.digest == bytes.fromhex(DSKEY_PUBLISHED_SHA1)
    wrapped = "2bb183af5f22588179a53b0a\n 98631fad1a292118"
    assert decode_hex_field(wrapped, what="digest") == ds.digest
    assert encode_hex_field(ds.digest) == DSKEY_PUBLISHED_SHA1
    with pytest.raises(ValueError, match="not hexadecimal"):
        RData_DS(DSKEY_PUBLISHED_KEY_TAG, DSKEY_ALGORITHM, 1, "2BB1ZZ")


def test_refers_to_needs_the_hash_and_not_just_the_tag():
    """Appendix B¶2: "Implementations MUST NOT assume that the key tag uniquely
    identifies a DNSKEY RR" -- so here is a pair that collides on purpose.

    A validator that stopped at the tag would accept the impostor as the key the
    parent delegated. The sums are 0x0100+0x0305+0x0001+0x0203 and
    0x0100+0x0305+0x0000+0x0204: equal, and not by luck.
    """
    real = RData_DNSKEY(256, 3, 5, b"\x00\x01\x02\x03")
    impostor = RData_DNSKEY(256, 3, 5, b"\x00\x00\x02\x04")
    assert real.key_tag == impostor.key_tag
    ds = RData_DS.for_dnskey("sub.example.", real, DigestType.SHA256)
    assert ds.refers_to(real, "sub.example.")
    assert not ds.refers_to(impostor, "sub.example.")
    # A mismatched algorithm is refused before any hashing, too: §5.1.2 makes it a
    # claim about the key, and §5.3.1 checks it against the covering RRSIG.
    assert not ds.refers_to(RData_DNSKEY(256, 3, 8, b"\x00\x01\x02\x03"), "sub.example.")
