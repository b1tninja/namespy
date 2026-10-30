"""The denial-of-existence records: RRSIG, NSEC, NSEC3, NSEC3PARAM (RFC 4034 §3-§4, RFC 5155).

Every number here is the RFC's own. RFC 5155 Appendix A says of itself that its hashes
"can also be used as test vectors for the hash algorithm", and prints twelve of them for a
zone signed with SHA-1, salt aabbccdd and twelve iterations -- which pins the recursion of
§5, the salt placement, the canonical name form, and (via **verified erratum 3544**) the
base32hex alphabet in one sweep. The same appendix prints NSEC3, NSEC3PARAM and RRSIG
records, so the codecs are checked against real records rather than self-consistency.

Rules with no published number are tested as properties, and the test says so: the type
bitmap's bit order is checked against the one value §4.1.2 makes derivable by hand (A alone
is 0x40), and the RRSIG validity window is checked at the 32-bit wrap because §3.1.5¶2
forbids integer comparison there.
"""

import base64
import struct
from hashlib import sha1

import pytest

from namespy.dnssec import (
    NSEC3_ITERATION_LIMITS,
    NSEC3_OPT_OUT_FLAG,
    Nsec3HashAlgorithm,
    decode_base32hex,
    decode_type_bitmap,
    encode_base32hex,
    encode_type_bitmap,
    iterations_within_limit,
    nsec3_hash,
)
from namespy.enums import DnsRType
from namespy.names import DomainName
from namespy.rdata import RData_NSEC, RData_NSEC3, RData_NSEC3PARAM, RData_RRSIG

# RFC 5155 Appendix A: the zone's NSEC3PARAM is "1 0 12 aabbccdd", so every hash below is
# SHA-1 over the canonical owner name with that salt and that iteration count.
ZONE_SALT = bytes.fromhex("aabbccdd")
ZONE_ITERATIONS = 12

#: The hashes Appendix A lists in its leading comment block, quoted verbatim.
APPENDIX_A_HASHES = {
    "example.": "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom",
    "a.example.": "35mthgpgcu1qg68fab165klnsnk3dpvl",
    "ai.example.": "gjeqe526plbf1g8mklp59enfd789njgi",
    "ns1.example.": "2t7b4g4vsa5smi47k61mv5bv1a22bojr",
    "ns2.example.": "q04jkcevqvmu85r014c7dkba38o0ji5r",
    "w.example.": "k8udemvp1j2f7eg6jebps17vp3n8i58h",
    "*.w.example.": "r53bq7cc2uvmubfu5ocmm6pers9tk9en",
    "x.w.example.": "b4um86eghhds6nea196smvmlo4ors995",
    "y.w.example.": "ji6neoaepv8b5o6k4ev33abha8ht9fgc",
    "x.y.w.example.": "2vptu5timamqttgl4luu9kg21e0aor3s",
    "xx.example.": "t644ebqk9bibcna874givr6joj62mlhv",
    # A name whose first label is itself a hash, which shows the hash runs over octets
    # and not over any interpretation of what a label means.
    "2t7b4g4vsa5smi47k61mv5bv1a22bojr.example.": "kohar7mbb8dc2ce8a9qvl8hon4k53uhi",
}


@pytest.mark.parametrize(("owner", "expected"), sorted(APPENDIX_A_HASHES.items()))
def test_nsec3_hash_reproduces_the_published_vectors(owner, expected):
    """§5's recursion, the salt, and the alphabet, against the zone the RFC publishes."""
    digest = nsec3_hash(owner, iterations=ZONE_ITERATIONS, salt=ZONE_SALT)
    assert encode_base32hex(digest).lower() == expected


def test_nsec3_iterations_count_additional_hashes():
    """§3.1.3 and §5: k is the number of *extra* rounds, so k=0 still hashes once.

    Written out by hand rather than compared against another call, so an implementation
    that hashed one time too few for every non-zero k fails here: IH(salt, x, 1) is
    H(H(x || salt) || salt), two invocations.
    """
    name = bytes(DomainName("example.")).lower()

    def h(data: bytes) -> bytes:
        # usedforsecurity is off deliberately: §5's SHA-1 is a work factor against zone
        # enumeration, not a security decision, and this only recomputes what §5 defines.
        return sha1(data, usedforsecurity=False).digest()

    assert nsec3_hash("example.", iterations=0, salt=ZONE_SALT) == h(name + ZONE_SALT)

    one = nsec3_hash("example.", iterations=1, salt=ZONE_SALT)
    assert one == h(h(name + ZONE_SALT) + ZONE_SALT)
    assert one != nsec3_hash("example.", iterations=0, salt=ZONE_SALT)
    assert len(one) == 20  # §3.1.6: the Hash Length a SHA-1 record has to carry.


def test_nsec3_hash_keeps_the_wildcard_label():
    """§5 item 3 / RFC 4034 §6.2 item 4: a wildcard hashes with its ``*`` intact.

    Appendix A lists ``*.w.example`` separately from ``w.example``, and the two names
    expand to different sets of answers, so this is the published case for refusing to
    substitute a matched label before hashing.
    """
    wildcard = nsec3_hash("*.w.example.", iterations=ZONE_ITERATIONS, salt=ZONE_SALT)
    assert encode_base32hex(wildcard).lower() == APPENDIX_A_HASHES["*.w.example."]
    assert wildcard != nsec3_hash("w.example.", iterations=ZONE_ITERATIONS, salt=ZONE_SALT)


def test_nsec3_hash_needs_a_fully_qualified_name():
    """§6.2 item 1, enforced rather than assumed: a relative name would hash wrong."""
    with pytest.raises(ValueError, match="fully qualified"):
        nsec3_hash("example", iterations=0, salt=b"")


def test_nsec3_hash_refuses_an_unknown_algorithm():
    """§11 defines SHA-1 alone, so hashing with another number has to be a refusal.

    Reading such a record stays legal (see the codec tests); inventing a hash function for
    it is not. The asymmetry is the one DigestType keeps.
    """
    assert Nsec3HashAlgorithm.SHA1 == 1
    with pytest.raises(ValueError, match="not implemented"):
        nsec3_hash("example.", iterations=0, salt=b"", hash_algorithm=2)


def test_hashed_owner_names_are_base32hex_not_base32():
    """**Verified erratum 3544**: RFC 5155's "base32" means RFC 4648 §7 base32hex.

    The alphabets share no characters below 'K', so the difference is asserted directly --
    a leading '0' means five zero bits, which the standard alphabet cannot express at all.
    """
    digest = nsec3_hash("example.", iterations=ZONE_ITERATIONS, salt=ZONE_SALT)
    text = encode_base32hex(digest)
    assert text.lower() == APPENDIX_A_HASHES["example."]
    assert text == base64.b32encode(digest).decode("ascii").rstrip("=").translate(
        str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", "0123456789ABCDEFGHIJKLMNOPQRSTUV")
    )
    assert encode_base32hex(bytes(20)) == "0" * 32
    assert decode_base32hex("0" * 32) == bytes(20)


def test_base32hex_reads_case_and_padding_without_complaint():
    """§3.3 writes unpadded and calls the digits case-insensitive; readers meet both.

    Producing follows §3.3 to the letter; consuming is what a resolver meets in the wild,
    where tools pad. Refusing padded text would cost an answer for a cosmetic difference.
    """
    digest = bytes(range(20))
    text = encode_base32hex(digest)
    assert "=" not in text
    assert decode_base32hex(text.lower()) == digest
    assert decode_base32hex(text + "=" * ((8 - len(text) % 8) % 8)) == digest
    for bad in ("", "!!!"):
        with pytest.raises(ValueError, match=r"base32hex|empty"):
            decode_base32hex(bad)


@pytest.mark.parametrize(
    ("key_bits", "iterations", "ok"),
    [
        (1024, 150, True),
        (1024, 151, False),
        (1536, 500, True),
        (1536, 501, False),
        (3072, 500, True),
        (4096, 2500, True),
        (8192, 2500, True),
        (8192, 2501, False),
    ],
)
def test_nsec3_iteration_ceiling_follows_the_key_size_table(key_bits, iterations, ok):
    """§10.3: rounded up to the nearest table row, down past the largest, any algorithm.

    A policy table rather than a computation, so there is no published number to quote;
    what is asserted is the rounding at each edge, including the 3072-bit case where the
    ceiling comes from the 2048 row rather than from the key's own size (§10.3¶3), and
    §10.3¶7's insistence that the table not be relaxed per algorithm.
    """
    assert len(NSEC3_ITERATION_LIMITS) == 3
    assert iterations_within_limit(iterations, key_bits=key_bits) is ok


# ------------------------------------------------------------ type bit maps


def test_type_bitmap_numbers_bits_from_the_most_significant_side():
    """§4.1.2¶6: "the first bit is bit 0", held in network bit order.

    A (type 1) alone is 0x40, which is the one number in this encoding that can be read
    straight off the figure: bit 1 of window 0 is the second-most-significant bit of the
    first octet. A+NS then shares an octet as 0x60, the bitmap the published NSEC records
    of a zone apex carry.
    """
    assert encode_type_bitmap([int(DnsRType.A)]) == b"\x00\x01\x40"
    assert encode_type_bitmap([int(DnsRType.A), int(DnsRType.NS)]) == b"\x00\x01\x60"
    assert decode_type_bitmap(b"\x00\x01\x60") == (1, 2)


def test_type_bitmap_omits_trailing_zero_octets_and_empty_windows():
    """§4.1.2¶8: block length is that of the largest type present, no padding.

    The block for type 51 is seven octets, not thirty-two, and a set that spans into
    window 1 emits two blocks in ascending window order (§4.1.2¶3) with the gap between
    them simply absent -- "blocks with no types present MUST NOT be included".
    """
    nsec3param = int(DnsRType.NSEC3PARAM)
    assert nsec3param == 51
    blob = encode_type_bitmap([nsec3param])
    assert blob[:2] == b"\x00\x07"
    assert len(blob) == 9

    spanning = encode_type_bitmap([1, 256, 257])
    assert spanning == b"\x00\x01\x40\x01\x01\xc0"
    assert decode_type_bitmap(spanning) == (1, 256, 257)


def test_type_bitmap_round_trips_a_published_record():
    """Appendix A's apex proof lists NS SOA MX RRSIG DNSKEY NSEC3PARAM.

    The hex is what the encoder produces for that set; the value of the round trip is that
    the decoded types come back ascending and complete, including the two above 47 that a
    one-octet bitmap could not express.
    """
    listed = [
        DnsRType.NS,
        DnsRType.SOA,
        DnsRType.MX,
        DnsRType.RRSIG,
        DnsRType.DNSKEY,
        DnsRType.NSEC3PARAM,
    ]
    blob = encode_type_bitmap(int(t) for t in listed)
    assert blob == bytes.fromhex("000722010000000290")
    assert decode_type_bitmap(blob) == tuple(sorted(int(t) for t in listed))


@pytest.mark.parametrize(
    "blob",
    [
        b"\x00",  # ends mid-header
        b"\x00\x00\x00",  # §4.1.2¶2: a block is 1..32 octets, never empty
        b"\x00\x20\x00" + bytes(31),  # §4.1.2¶8: trailing zero octet kept
        b"\x01\x01\x40\x00\x01\x40",  # §4.1.2¶3: windows out of order
        b"\x00\x04\x40",  # block promises 4 octets, RDATA has 1
    ],
)
def test_type_bitmap_refuses_to_read_a_malformed_block(blob):
    """A bitmap that cannot be parsed is refused, not shortened.

    The alternative is reading "fewer types exist at this name" out of a damaged record,
    which is a false denial -- the one thing this field exists to make trustworthy.
    """
    with pytest.raises(ValueError, match="type bitmap"):
        decode_type_bitmap(blob)


def test_type_bitmap_of_nothing_is_empty_and_reads_back_as_nothing():
    """§4.1.2 allows a record whose bitmap lists no types at all."""
    assert encode_type_bitmap([]) == b""
    assert decode_type_bitmap(b"") == ()


# ------------------------------------------------------- NSEC3 / NSEC3PARAM

# RFC 5155 Appendix A's first chain entry, at owner 0p9mhaveqvm6t7vbl5lop2u3t2rp3tom
# (the hash of "example."), written as the zone file writes it:
#     NSEC3 1 1 12 aabbccdd ( 2t7b4g4vsa5smi47k61mv5bv1a22bojr MX DNSKEY NS SOA
#                            NSEC3PARAM RRSIG )
APPENDIX_A_NSEC3 = (
    struct.pack("!BBHB", 1, 1, 12, 4)
    + bytes.fromhex("aabbccdd")
    + bytes([20])
    + decode_base32hex("2t7b4g4vsa5smi47k61mv5bv1a22bojr")
    + bytes.fromhex("000722010000000290")
)


def test_nsec3_reads_the_published_chain_entry():
    """Field order and values straight off Appendix A, including the Opt-Out flag."""
    record = RData_NSEC3.parse_from(APPENDIX_A_NSEC3)
    assert record.hash_algorithm == int(Nsec3HashAlgorithm.SHA1)
    assert record.flags == 1
    assert record.opt_out is True
    assert record.iterations == ZONE_ITERATIONS
    assert record.salt == ZONE_SALT
    assert record.types == tuple(sorted(record.types))
    assert RData_NSEC3.parse_from(bytes(record)) == record


def test_nsec3_can_hash_the_name_the_next_entry_proves():
    """The chain itself, checked with the record's own parameters (§5).

    Appendix A says this entry's successor label is the hash of ``ns1.example``, so
    recomputing it from the record is an end-to-end check that the algorithm, iterations
    and salt are read for what they are rather than ignored.
    """
    record = RData_NSEC3.parse_from(APPENDIX_A_NSEC3)
    assert record.hash_owner("ns1.example.") == record.next_hashed_owner
    assert (
        encode_base32hex(record.hash_owner("ns1.example.")).lower()
        == "2t7b4g4vsa5smi47k61mv5bv1a22bojr"
    )


def test_nsec3_presentation_drops_both_length_fields_and_hyphens_an_empty_salt():
    """§3.3: Salt Length and Hash Length are not represented; zero salt is ``-``."""
    record = RData_NSEC3.parse_from(APPENDIX_A_NSEC3)
    text = record.to_presentation()
    assert text.lower().startswith("1 1 12 aabbccdd 2t7b4g4vsa5smi47k61mv5bv1a22bojr ")
    assert text.lower().endswith("ns soa mx rrsig dnskey nsec3param")

    empty = RData_NSEC3(1, 0, 0, b"", bytes(20), [])
    assert empty.to_presentation().startswith("1 0 0 - ")
    assert RData_NSEC3.parse_from(bytes(empty)).salt == b""


def test_nsec3_refuses_a_hash_that_is_too_short_for_its_algorithm():
    """§3.1.6 allows 1..255 octets; a 7-octet SHA-1 is still a truncated proof.

    The Hash Length field is self-consistent here, so a parser that trusted only the field
    would accept it and carry a half-hash into the cache, where it would match no name and
    prove nothing at all.
    """
    truncated = (
        struct.pack("!BBHB", 1, 1, 12, 4)
        + bytes.fromhex("aabbccdd")
        + bytes([7])
        + bytes(7)
        + bytes.fromhex("000140")
    )
    with pytest.raises(ValueError, match="octet"):
        RData_NSEC3.parse_from(truncated)


def test_nsec3_reads_an_unknown_hash_algorithm_and_refuses_to_hash_with_it():
    """§11's registry is open, so receipt is not the place to enforce it (§3.1.1).

    An algorithm this package cannot compute still parses and prints -- the rest of the
    record is worth caching and showing -- but :meth:`hash_owner` refuses rather than
    picking a hash function that nothing else would agree with.
    """
    blob = struct.pack("!BBHB", 2, 0, 0, 0) + bytes([8]) + bytes(8) + bytes.fromhex("000140")
    record = RData_NSEC3.parse_from(blob)
    assert record.hash_algorithm == 2
    assert record.to_presentation().startswith("2 0 0 - ")
    with pytest.raises(ValueError, match="not implemented"):
        record.hash_owner("example.")


def test_nsec3_rejects_a_bitmap_that_does_not_fit_its_rdata():
    """A record whose last field is cut short must not read as an empty type list."""
    blob = struct.pack("!BBHB", 1, 0, 0, 0) + bytes([20]) + bytes(20) + b"\x00\x04\x40"
    with pytest.raises(ValueError, match="truncated"):
        RData_NSEC3.parse_from(blob)


def test_nsec3param_is_the_apex_line_and_carries_no_proof():
    """§4.1, and Appendix A's own ``NSEC3PARAM 1 0 12 aabbccdd``.

    Flags 0 means Opt-Out is clear (§4.1.1 reuses the NSEC3 flag), and the record's
    presence says nothing about whether the zone is signed -- §4.1¶3 notes the same
    information could be derived from the NSEC3 RRs anyway.
    """
    record = RData_NSEC3PARAM.parse_from(bytes.fromhex("0100000c04aabbccdd"))
    assert record.to_presentation() == "1 0 12 AABBCCDD"
    assert record.opt_out is False
    assert record.salt == ZONE_SALT
    assert record.iterations == ZONE_ITERATIONS
    assert RData_NSEC3PARAM.parse_from(bytes(record)) == record

    bare = RData_NSEC3PARAM(1, 1, 0, b"")
    assert bare.to_presentation() == "1 1 0 -"
    assert bare.opt_out is True
    assert bytes(bare) == bytes.fromhex("0101000000")
    assert NSEC3_OPT_OUT_FLAG == 1


def test_nsec3param_refuses_octets_after_the_salt():
    """§4.1's RDATA ends with the salt; anything past it is not a parameter to guess at."""
    with pytest.raises(ValueError, match="after the salt"):
        RData_NSEC3PARAM.parse_from(bytes.fromhex("0100000c04aabbccddff"))


# ------------------------------------------------------------------- NSEC


def test_nsec_lists_the_next_name_and_the_types_at_this_one():
    """RFC 4034 §4.1-§4.2: a name, then type mnemonics, nothing else."""
    blob = bytes(DomainName("next.example.")) + bytes.fromhex("000160")
    record = RData_NSEC.parse_from(blob)
    assert record.next_domain == DomainName("next.example.")
    assert record.types == (1, 2)
    assert record.has_type(int(DnsRType.A))
    assert not record.has_type(int(DnsRType.MX))
    assert record.to_presentation().endswith("A NS")
    assert RData_NSEC.parse_from(bytes(record)) == record


def test_nsec_bitmap_of_a_type_above_255_survives_the_round_trip():
    """Windowed types are why the field is not a plain bit mask (§4.1.2¶1)."""
    record = RData_NSEC("z.example.", [int(DnsRType.A), 257])
    assert RData_NSEC.parse_from(bytes(record)).types == (1, 257)


# ----------------------------------------------------------------- RRSIG

# RFC 5155 Appendix A, the RRSIG over the NSEC3 RRset at example.:
#     RRSIG NSEC3 7 2 3600 20150420235959 20051021000000 ( 40430 example.
#             OSgWSm26B+cS+dDL8b5QrWr/dEWhtCsKlwKLIBHYH6blRxK9rC0bMJPwQ4mLIuw8
#             5H2EY762BOCXJZMnpuwhpA== )
# The published expiring and inception moments in seconds, which §3.1.5 defines as the
# wire form and §3.2 only re-renders: 2015-04-20T23:59:59Z and 2005-10-21T00:00:00Z.
RRSIG_EXPIRATION = 1429574399
RRSIG_INCEPTION = 1129852800
RRSIG_SIGNATURE = (
    "OSgWSm26B+cS+dDL8b5QrWr/dEWhtCsKlwKLIBHYH6blRxK9rC0bMJPwQ4mLIuw85H2EY762BOCXJZMnpuwhpA=="
)


def _published_rrsig(**changes) -> RData_RRSIG:
    fields = {
        "type_covered": int(DnsRType.NSEC3),
        "algorithm": 7,
        "labels": 2,
        "original_ttl": 3600,
        "expiration": RRSIG_EXPIRATION,
        "inception": RRSIG_INCEPTION,
        "key_tag": 40430,
        "signer_name": "example.",
        "signature": RRSIG_SIGNATURE,
    }
    fields.update(changes)
    return RData_RRSIG(**fields)


def test_rrsig_reads_the_published_signature_record():
    """All nine §3.1 fields, in the order the figure gives them.

    The Key Tag and the two time fields are three consecutive integers of different
    widths, so this is the test that catches a struct format that packs 18 octets and
    reads them back shifted -- which is exactly what it did catch on the first run.
    """
    record = _published_rrsig()
    parsed = RData_RRSIG.parse_from(bytes(record))
    assert parsed.covered_type == "NSEC3"
    assert parsed.algorithm == 7
    assert parsed.labels == 2
    assert parsed.original_ttl == 3600
    assert parsed.expiration == RRSIG_EXPIRATION
    assert parsed.inception == RRSIG_INCEPTION
    assert parsed.key_tag == 40430
    assert parsed.signer_name == DomainName("example.")
    assert len(parsed.signature) == 64
    assert parsed == record


def test_rrsig_prints_times_as_calendar_dates_and_keeps_the_signature_opaque():
    """§3.2¶6-¶11: 14-digit UTC dates, the signer as a name, the signature in Base64."""
    text = _published_rrsig().to_presentation()
    assert text.startswith("NSEC3 7 2 3600 20150420235959 20051021000000 40430 example. ")
    assert "AAAA" not in text  # the signature is Base64, not hex
    unknown = _published_rrsig(type_covered=999)
    assert unknown.to_presentation().startswith("TYPE999 ")  # §3.2¶2 with RFC 3597 §5


def test_rrsig_accepts_a_signature_wrapped_across_lines():
    """§2.2 lets whitespace appear anywhere inside Base64, and zone files use it."""
    joined = RData_RRSIG.parse_from(bytes(_published_rrsig())).signature
    spaced = _published_rrsig(
        signature="\n".join(RRSIG_SIGNATURE[i : i + 56] for i in range(0, len(RRSIG_SIGNATURE), 56))
    )
    assert spaced.signature == joined


@pytest.mark.parametrize(
    ("moment", "valid"),
    [
        (RRSIG_INCEPTION, True),
        (RRSIG_INCEPTION + 1, True),
        (RRSIG_EXPIRATION, True),
        (RRSIG_EXPIRATION + 1, False),
        (RRSIG_INCEPTION - 1, False),
    ],
)
def test_rrsig_is_not_used_outside_its_validity_window(moment, valid):
    """§3.1.5¶1: "MUST NOT be used for authentication" before or after."""
    assert _published_rrsig().within_validity(moment) is valid


def test_rrsig_validity_survives_the_32_bit_wrap():
    """§3.1.5¶2 requires RFC 1982 arithmetic, because Expiration may be below Inception.

    A signature struck at 0xFFFFFFF0 expiring at 0x00000010 is legal and lasts 32
    seconds; compared as integers it would look expired forever, and the ordinary range
    check would say so too quietly to notice before 2105.
    """
    across_wrap = _published_rrsig(expiration=0x00000010, inception=0xFFFFFFF0)
    assert across_wrap.within_validity(0xFFFFFFF0) is True
    assert across_wrap.within_validity(0xFFFFFFF8) is True
    assert across_wrap.within_validity(0x00000008) is True
    assert across_wrap.within_validity(0x80000000) is False


@pytest.mark.parametrize(
    "changes",
    [
        {"labels": 256},
        {"key_tag": 65536},
        {"original_ttl": 2**32},
        {"algorithm": 256},
        {"signature": b""},
    ],
)
def test_rrsig_refuses_fields_that_do_not_fit_the_wire(changes):
    """Refusing at construction is the only place a wrapped value can be caught."""
    with pytest.raises(ValueError, match="RRSIG"):
        _published_rrsig(**changes)
