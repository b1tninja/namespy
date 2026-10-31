"""ECC key material and signature encodings: RFC 6605 §4 (ECDSA) and RFC 8080 §3-§4 (EdDSA).

Every expected value here is printed by an RFC, not computed by this code: RFC 6605 §6
supplies both ECDSA examples with their key tags and DS digests, and RFC 8080 §6 -- in its
form as corrected by verified erratum 4935, whose notes record the corrected examples
tested against independent implementations -- supplies both EdDSA curves. The erratum
matters for the signatures: as published the RRSIG examples were produced by a script
that omitted the algorithm identifier and counted the root label, so the *invalid*
originals are the ones a copy-paste would pin, and the corrected ones are the tests.

What these functions never do is arithmetic: on-curve and signature validity belong to
the backend, and the last section here says so while still asking the backend to confirm
the layout -- the published keys are accepted by it, and the published signatures
round-trip through our DER converter byte for byte.
"""

import base64
import calendar

import pytest

from namespy.crypto import (
    EC_KEY_OCTETS,
    ECDSA_ALGORITHMS,
    ECDSA_FIELD_OCTETS,
    EDDSA_ALGORITHMS,
    EDDSA_KEY_OCTETS,
    EDDSA_SIGNATURE_OCTETS,
    crypto_available,
)
from namespy.dnssec import (
    DigestType,
    EcdsaSignature,
    MalformedEcKeyError,
    ds_digest,
    ecdsa_signature_from_der,
    ecdsa_signature_from_rs,
    ecdsa_signature_octets,
    ecdsa_signature_to_der,
    eddsa_public_key_octets,
    eddsa_signature_octets,
    key_tag,
    pack_ec_public_key,
    rrsig_signed_data,
    unpack_ec_public_key,
)
from namespy.enums import DnsRType
from namespy.rdata import RData_A, RData_DNSKEY, RData_MX, RData_RRSIG


def _needs_backend() -> None:
    """Skip unless the probe itself reports a backend -- the convention in test_crypto_backend."""
    if not crypto_available():
        pytest.skip("namespy[crypto] is not installed")


# ---------------------------------------------------------------- published vectors (RFC 6605 §6)

P256_KEY = (
    "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA=="
)
P256_OWNER = "example.net."
P256_TAG = 55648
P256_DS = "b4c8c1fe2e7477127b27115656ad6256f424625bf5c1e2770ce6d6e37df61d17"
P256_SIGNATURE = (
    "qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXAyGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw=="
)

P384_KEY = (
    "xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1"
    "w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8"
    "/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40"
)
P384_TAG = 10771
P384_DS = (
    "72d7b62976ce06438e9c0bf319013cf801f09ecc84b8"
    "d7e9495f27e305c6a9b0563a9b5f4d288405c3008a94"
    "6df983d6"
)
P384_SIGNATURE = (
    "/L5hDKIvGDyI1fcARX3z65qrmPsVz73QD1Mr5CEqOiLP"
    "95hxQouuroGCeZOvzFaxsT8Glr74hbavRKayJNuydCuz"
    "WTSSPdz7wnqXL5bdcJzusdnI0RSMROxxwGipWcJm"
)

# -------------------------------------------------- published vectors (RFC 8080 §6, erratum 4935)

ED25519_KEY = "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4="
ED25519_OWNER = "example.com."
ED25519_TAG = 3613
ED25519_DS = "3aa5ab37efce57f737fc1627013fee07bdf241bd10f3b1964ab55c78e79a304b"
ED25519_SIGNATURE = (
    "oL9krJun7xfBOIWcGHi7mag5/hdZrKWw15jPGrHpjQeRAvTdszaPD+QLs3fx8A4M3e23mRZ9VrbpMngwcrqNAg=="
)
ED25519_KEY_2 = "zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs="
ED25519_TAG_2 = 35217
ED25519_DS_2 = "401781b934e392de492ec77ae2e15d70f6575a1c0bc59c5275c04ebe80c6614c"

ED448_KEY = "3kgROaDjrh0H2iuixWBrc8g2EpBBLCdGzHmn+G2MpTPhpj/OiBVHHSfPodx1FYYUcJKm1MDpJtIA"
ED448_OWNER = "example.com."
ED448_TAG = 9713
ED448_DS = "6ccf18d5bc5d7fc2fceb1d59d17321402f2aa8d368048db93dd811f5cb2b19c7"
ED448_SIGNATURE = (
    "3cPAHkmlnxcDHMyg7vFC34l0blBhuG1qpwLmjInI8w1CMB29FkEAIJUA0am"
    "xWndkmnBZ6SKiwZSAxGILn/NBtOXft0+Gj7FSvOKxE/07+4RQvE581N3Aj/"
    "JtIyaiYVdnYtyMWbSNyGEY2213WKsJlwEA"
)
ED448_KEY_2 = "kkreGWoccSDmUBGAe7+zsbG6ZAFQp+syPmYUurBRQc3tDjeMCJcVMRDmgcNLp5HlHAMy12VoISsA"
ED448_TAG_2 = 38353


def _dnskey(algorithm: int, key: str) -> RData_DNSKEY:
    return RData_DNSKEY(257, 3, algorithm, key)


# ------------------------------------------------------------------------ ECDSA keys (§4¶1)


def test_the_published_p256_key_is_two_field_elements():
    """64 octets, x then y, each exactly 32 (§4¶1-¶2), and the record round-trips it."""
    record = _dnskey(13, P256_KEY)
    key = record.require_ec_key()
    assert key.field_octets == 32
    assert len(record.public_key) == EC_KEY_OCTETS[13] == 64
    assert key.to_wire() == record.public_key
    assert 0 < key.x.bit_length() <= 256
    assert 0 < key.y.bit_length() <= 256
    assert key.uncompressed_point == b"\x04" + record.public_key


def test_the_published_p256_key_tags_and_digests_as_the_rfc_prints():
    """Key tag 55648 and the §6.1 DS digest, computed from nothing but the record octets."""
    record = _dnskey(13, P256_KEY)
    assert key_tag(bytes(record)) == P256_TAG
    assert ds_digest(P256_OWNER, bytes(record), DigestType.SHA256).hex() == P256_DS


def test_the_published_p384_key_is_two_wider_field_elements():
    """48 octets per coordinate, and §6.2's own tag and SHA-384 digest pin the octets."""
    record = _dnskey(14, P384_KEY)
    key = record.require_ec_key()
    assert key.field_octets == ECDSA_FIELD_OCTETS[14] == 48
    assert key.to_wire() == record.public_key
    assert key_tag(bytes(record)) == P384_TAG
    assert ds_digest(P256_OWNER, bytes(record), DigestType.SHA384).hex() == P384_DS


def test_coordinates_pad_to_width_not_to_magnitude():
    """x=1 is thirty-one zero octets and a one -- the opposite of the RSA rule, on purpose.

    RFC 3110 §2¶3 forbids leading zeros in an RSA modulus because minimality was the
    chosen encoding; RFC 6605 fixes each coordinate at the field width because the width
    is the curve's, not the value's. The key tag sums octets, so only one encoding of a
    point is correct, and padding is the one that always fits.
    """
    wire = pack_ec_public_key(1, 2, field_octets=32)
    assert wire == b"\x00" * 31 + b"\x01" + b"\x00" * 31 + b"\x02"
    key = unpack_ec_public_key(wire, field_octets=32)
    assert (key.x, key.y) == (1, 2)


def test_no_prefix_heuristic_is_possible_on_a_bare_bit_string():
    """A key whose x begins 0x04 is a real key, and a prefix check would eat it.

    Q carries no SEC 1 prefix byte, so the 0x04 that would introduce a compressed point
    is sometimes just the top of x. The pin against a future "helpful" rejection: same
    leading octet as the uncompressed-point prefix, and nothing happens.
    """
    blob = b"\x04" + b"\xab" * 63
    key = unpack_ec_public_key(blob, field_octets=32)
    assert key.x.to_bytes(32, "big") == blob[:32]


@pytest.mark.parametrize("length", [63, 65, 0])
def test_ecdsa_key_width_is_the_curve_talking(length: int):
    with pytest.raises(MalformedEcKeyError, match="fixes it at 2 x 32"):
        unpack_ec_public_key(b"\x01" * length, field_octets=32)


def test_the_all_zero_point_is_the_one_blob_arithmetic_cannot_need():
    with pytest.raises(MalformedEcKeyError, match="on no curve"):
        unpack_ec_public_key(b"\x00" * 64, field_octets=32)


def test_pack_refuses_coordinates_wider_than_the_field():
    with pytest.raises(MalformedEcKeyError, match="over the 32-octet field width"):
        pack_ec_public_key(1 << 256, 1, field_octets=32)


# ------------------------------------------------------------------ ECDSA signatures (§4¶2)


def test_the_published_p256_signature_is_r_then_s():
    """64 wire octets, split at the field width; DER conversion round-trips through both."""
    wire = base64.b64decode(P256_SIGNATURE)
    signature = ecdsa_signature_from_rs(wire, field_octets=32)
    assert signature.to_wire() == wire
    assert 0 < signature.r.bit_length() <= 256
    assert 0 < signature.s.bit_length() <= 256
    der = signature.to_der()
    assert der[0] == 0x30
    assert not der[1] & 0x80
    assert ecdsa_signature_from_der(der, field_octets=32) == signature


def test_the_published_p384_signature_round_trips_through_der():
    wire = base64.b64decode(P384_SIGNATURE)
    signature = ecdsa_signature_from_rs(wire, field_octets=48)
    assert ecdsa_signature_from_der(signature.to_der(), field_octets=48) == signature


def test_the_normalizer_accepts_wire_form_and_der_alike():
    """The backend signs DER, the wire carries r|s; §4¶2 makes them the same signature."""
    wire = base64.b64decode(P256_SIGNATURE)
    signature = ecdsa_signature_from_rs(wire, field_octets=32)
    assert ecdsa_signature_octets(wire, field_octets=32) == wire
    assert ecdsa_signature_octets(signature.to_der(), field_octets=32) == wire


def test_der_integers_are_minimal_and_signed_like_der_wants():
    """r=1, s=1: two 0x01 octets inside, no padding DER did not ask for.

    The second half is the sign pad: a value whose top bit is set must gain a leading
    zero or DER would read it negative -- 0x80<<248 is that case exactly, and the
    33-octet INTEGER it produces is still inside the field.
    """
    assert EcdsaSignature(1, 1, 32).to_der() == b"\x30\x06\x02\x01\x01\x02\x01\x01"
    high = 0x80 << 248
    der = EcdsaSignature(high, 1, 32).to_der()
    assert ecdsa_signature_from_der(der, field_octets=32) == EcdsaSignature(high, 1, 32)


@pytest.mark.parametrize("length", [63, 65, 96])
def test_signature_width_is_exact_with_no_padding_licence(length: int):
    """No erratum 2811 for this corner: §4¶2 fixes the width and a short one is malformed."""
    with pytest.raises(MalformedEcKeyError, match="§4¶2"):
        ecdsa_signature_from_rs(b"\x01" * length, field_octets=32)


@pytest.mark.parametrize("name", ["r", "s"])
def test_a_zero_integer_is_not_a_signature(name: str):
    zero = b"\x00" * 32
    one = b"\x00" * 31 + b"\x01"
    wire = zero + one if name == "r" else one + zero
    with pytest.raises(MalformedEcKeyError, match="zero r or s"):
        ecdsa_signature_from_rs(wire, field_octets=32)


def test_the_der_parser_refuses_every_way_a_blob_could_look_almost_right():
    """Each refusal is a crafted input hoping a lenient reader assigns it a meaning."""
    bad: list[tuple[bytes, str]] = [
        (b"\x02\x01\x01\x02\x01\x01", "not a DER SEQUENCE"),
        (b"\x30\x81\x06\x02\x01\x01\x02\x01\x01", "long-form SEQUENCE"),
        (b"\x30\x04\x02\x01\x01\x02\x01\x01\x99", "followed by"),
        (b"\x30\x08\x02\x40\x01\x02\x01\x01\x30\x00", "runs past"),
        (b"\x30\x03\x02\x01\x01", "missing its s"),
        (b"\x30\x05\x02\x00\x02\x01\x01", "empty INTEGER"),
        (b"\x30\x25\x02\x20\x81" + b"\x00" * 31 + b"\x02\x01\x01", "is negative"),
        (b"\x30\x07\x02\x02\x00\x01\x02\x01\x01", "leading zero"),
        (b"\x30\x27\x02\x22" + b"\x01" * 34 + b"\x02\x01\x01", "wider than field"),
        (b"\x30\x09\x02\x01\x01\x02\x01\x01\x02\x01\x01", "more than two"),
    ]
    for blob, message in bad:
        with pytest.raises(MalformedEcKeyError, match=message):
            ecdsa_signature_from_der(blob, field_octets=32)


def test_a_der_zero_integer_is_refused_like_a_wire_one():
    seq = b"\x30\x06\x02\x01\x00\x02\x01\x01"
    with pytest.raises(MalformedEcKeyError, match="zero r or s"):
        ecdsa_signature_from_der(seq, field_octets=32)


def test_the_encoding_side_refuses_what_only_a_direct_caller_can_supply():
    """The guards behind the parsers, for callers who build the objects themselves.

    ``to_der`` on a non-positive integer, ``pack`` of a negative coordinate, and a
    long-form INTEGER length inside an otherwise well-shaped SEQUENCE: none arrives
    through from_rs/from_der, all arrive through someone convinced their value is fine.
    """
    with pytest.raises(MalformedEcKeyError, match="must be positive"):
        EcdsaSignature(0, 1, 32).to_der()
    with pytest.raises(MalformedEcKeyError, match="is negative"):
        pack_ec_public_key(-1, 1, field_octets=32)
    with pytest.raises(MalformedEcKeyError, match="long-form INTEGER"):
        ecdsa_signature_from_der(b"\x30\x07\x02\x81\x01\x01\x02\x01\x01", field_octets=32)


def test_a_blob_that_is_neither_form_is_named_as_such():
    with pytest.raises(MalformedEcKeyError, match="neither the fixed-width"):
        ecdsa_signature_octets(b"\x11" * 63, field_octets=32)


# ------------------------------------------------------------------------- EdDSA (§3, §4)


def test_the_published_ed25519_key_tags_and_digests_as_the_rfc_prints():
    """32 octets, key tag 3613, SHA-256 digest -- the §6.1 pair from RFC 8080."""
    record = _dnskey(15, ED25519_KEY)
    key = record.require_eddsa_key()
    assert len(key) == EDDSA_KEY_OCTETS[15] == 32
    assert key == base64.b64decode(ED25519_KEY)
    assert key_tag(bytes(record)) == ED25519_TAG
    assert ds_digest(ED25519_OWNER, bytes(record), DigestType.SHA256).hex() == ED25519_DS


def test_the_published_ed25519_signature_is_sixty_four_octets():
    signature = base64.b64decode(ED25519_SIGNATURE)
    assert (
        eddsa_signature_octets(signature, signature_octets=EDDSA_SIGNATURE_OCTETS[15]) == signature
    )


def test_the_second_published_ed25519_key_agrees_too():
    record = _dnskey(15, ED25519_KEY_2)
    assert key_tag(bytes(record)) == ED25519_TAG_2
    assert ds_digest(ED25519_OWNER, bytes(record), DigestType.SHA256).hex() == ED25519_DS_2


def test_the_published_ed448_key_is_fifty_seven_octets_not_a_multiple_of_eight():
    """456 bits, octet-padded high end -- the width that breaks width heuristics.

    §6.2's tag and digest pin the exact octets, because a validator that rounded the
    width would fail every Ed448 delegation on the wire, quietly and at the child.
    """
    record = _dnskey(16, ED448_KEY)
    key = record.require_eddsa_key()
    assert len(key) == EDDSA_KEY_OCTETS[16] == 57
    assert key_tag(bytes(record)) == ED448_TAG
    assert ds_digest(ED448_OWNER, bytes(record), DigestType.SHA256).hex() == ED448_DS


def test_the_published_ed448_signature_is_114_octets():
    signature = base64.b64decode(ED448_SIGNATURE)
    assert (
        eddsa_signature_octets(signature, signature_octets=EDDSA_SIGNATURE_OCTETS[16]) == signature
    )
    assert len(_dnskey(16, ED448_KEY_2).require_eddsa_key()) == 57
    assert key_tag(bytes(_dnskey(16, ED448_KEY_2))) == ED448_TAG_2


@pytest.mark.parametrize(
    ("algorithm", "good", "wrong"),
    [(15, b"\x01" * 32, 31), (15, b"\x01" * 32, 33), (16, b"\x01" * 57, 56)],
)
def test_eddsa_key_width_is_the_whole_check(algorithm: int, good: bytes, wrong: int):
    eddsa_public_key_octets(good, key_octets=len(good))
    with pytest.raises(MalformedEcKeyError, match="RFC 8080 §3"):
        eddsa_public_key_octets(b"\x01" * wrong, key_octets=len(good))
    with pytest.raises(MalformedEcKeyError, match="all zero"):
        eddsa_public_key_octets(b"\x00" * len(good), key_octets=len(good))


def test_eddsa_signature_width_too():
    with pytest.raises(MalformedEcKeyError, match="RFC 8080 §4"):
        eddsa_signature_octets(b"\x01" * 63, signature_octets=64)


# ---------------------------------------------------------------------- record-level rules


def test_parse_never_interprets_and_the_reader_is_where_interpretation_happens():
    """A malformed ECC key still yields a record: countable, taggable, reportable.

    RData_DNSKEY holds the octets; only :meth:`RData_DNSKEY.ec_public_key` objects, and
    then with the layout error rather than a parse error. A resolver dropping records at
    parse time could not tell an operator which rule the zone broke -- the same stance
    the RSA leg took, now with a second family of reasons to be wrong.
    """
    record = RData_DNSKEY(257, 3, 13, b"\x01" * 63)
    assert bytes(record).endswith(b"\x01" * 63)  # parsed, serialized, intact
    with pytest.raises(MalformedEcKeyError, match="fixes it at 2 x 32"):
        record.ec_public_key()


def test_a_wrong_algorithm_for_the_reader_is_a_programming_error_not_a_record_problem():
    # algorithm 8 is RSA: the EC readers must refuse the record, not misread it.
    rsa = _dnskey(8, "AQEBwAAB")
    assert rsa.ec_public_key() is None
    assert rsa.eddsa_public_key() is None
    with pytest.raises(ValueError, match="RFC 6605 §4"):
        rsa.require_ec_key()
    with pytest.raises(ValueError, match="RFC 8080 §3"):
        rsa.require_eddsa_key()


def test_the_algorithm_sets_agree_with_the_registry_they_derive_from():
    assert ECDSA_ALGORITHMS == frozenset({13, 14})
    assert EDDSA_ALGORITHMS == frozenset({15, 16})
    assert ECDSA_ALGORITHMS.isdisjoint(EDDSA_ALGORITHMS)
    for algorithm, width in ECDSA_FIELD_OCTETS.items():
        assert EC_KEY_OCTETS[algorithm] == 2 * width
    assert EDDSA_KEY_OCTETS == {15: 32, 16: 57}
    assert EDDSA_SIGNATURE_OCTETS == {15: 64, 16: 114}


# ------------------------------------------------------- the backend, confirming the layout
#
# These are still encoding tests, not the verification leg: they ask the one library
# that does the arithmetic whether the octets this module hands it mean what the RFCs
# say they mean. Each published signature below is verified over its published RRset --
# the canonical-RRset rule from the earlier leg and the widths from this one composing
# into "the RFC's own example is a valid signature of the RFC's own key", which is the
# strongest pin a layout section can be given.


def _rrsig(
    type_covered: int,
    algorithm: int,
    labels: int,
    expiration: int,
    inception: int,
    tag: int,
    signer: str,
    signature: str,
) -> RData_RRSIG:
    """The RRSIG of a published example, with the fields that example prints.

    Expiration and inception are part of the signed bytes, so a rebuilt message only
    matches what was signed if they arrive exactly as printed. RFC 6605 §6 writes them
    presentation-format (20100909100439), so the test converts the printed instant
    rather than inventing an epoch for it; RFC 8080 prints epochs directly.
    """
    return RData_RRSIG(
        type_covered=type_covered,
        algorithm=algorithm,
        labels=labels,
        original_ttl=3600,
        expiration=expiration,
        inception=inception,
        key_tag=tag,
        signer_name=signer,
        signature=signature,
    )


def test_the_backend_reads_the_published_ecdsa_keys_as_points():
    """x|y split at the field width is a point the curve recognizes -- for both curves.

    ``public_key()`` validates the point, so this is as close to on-curve as a layout
    test gets without claiming to have done the arithmetic ourselves: we did not, and
    this is the honest boundary.
    """
    _needs_backend()
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    for algorithm, key_text, curve in (
        (13, P256_KEY, ec.SECP256R1()),
        (14, P384_KEY, ec.SECP384R1()),
    ):
        point = _dnskey(algorithm, key_text).require_ec_key()
        loaded = (
            ec.EllipticCurvePublicNumbers(x=point.x, y=point.y, curve=curve)
            .public_key()
            .public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        )
        assert loaded == point.uncompressed_point


def test_the_backend_verifies_the_published_p256_signature():
    """RFC 6605 §6.1's RRSIG, over §6.1's A record, with §4's split and §6.2's bytes.

    If any octet of this leg's layout were wrong -- coordinate order, width, the r|s
    split -- the curve arithmetic would reject the signature. Passing means the
    encoding and the RFC agree, which is the claim this commit makes.
    """
    _needs_backend()
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    point = _dnskey(13, P256_KEY).require_ec_key()
    key = ec.EllipticCurvePublicNumbers(x=point.x, y=point.y, curve=ec.SECP256R1()).public_key()
    signature = ecdsa_signature_from_rs(base64.b64decode(P256_SIGNATURE), field_octets=32).to_der()
    message = rrsig_signed_data(
        _rrsig(
            int(DnsRType.A),
            13,
            3,
            calendar.timegm((2010, 9, 9, 10, 4, 39)),
            calendar.timegm((2010, 8, 12, 10, 4, 39)),
            P256_TAG,
            P256_OWNER,
            P256_SIGNATURE,
        ),
        "www.example.net.",
        [RData_A("192.0.2.1")],
    )
    key.verify(signature, message, ec.ECDSA(hashes.SHA256()))


def test_the_backend_verifies_the_published_p384_signature():
    _needs_backend()
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    point = _dnskey(14, P384_KEY).require_ec_key()
    key = ec.EllipticCurvePublicNumbers(x=point.x, y=point.y, curve=ec.SECP384R1()).public_key()
    signature = ecdsa_signature_from_rs(base64.b64decode(P384_SIGNATURE), field_octets=48).to_der()
    message = rrsig_signed_data(
        _rrsig(
            int(DnsRType.A),
            14,
            3,
            calendar.timegm((2010, 9, 9, 10, 20, 25)),
            calendar.timegm((2010, 8, 12, 10, 20, 25)),
            P384_TAG,
            P256_OWNER,
            P384_SIGNATURE,
        ),
        "www.example.net.",
        [RData_A("192.0.2.1")],
    )
    key.verify(signature, message, ec.ECDSA(hashes.SHA384()))


def test_the_backend_verifies_the_erratum_corrected_ed25519_signature():
    """The corrected §6.1 signature verifies; the original one printed by the RFC does not.

    Erratum 4935 replaced the EdDSA examples after its notes recorded the generator
    script counting the root label and dropping the algorithm identifier. Pinning only
    the corrected value could still ride on a lucky copy; pinning the original's failure
    is what proves this package reads the amended document.
    """
    _needs_backend()
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    key = Ed25519PublicKey.from_public_bytes(_dnskey(15, ED25519_KEY).require_eddsa_key())
    message = rrsig_signed_data(
        _rrsig(
            int(DnsRType.MX),
            15,
            2,
            1440021600,
            1438207200,
            ED25519_TAG,
            ED25519_OWNER,
            ED25519_SIGNATURE,
        ),
        ED25519_OWNER,
        [RData_MX("mail.example.com.", 10)],
    )
    key.verify(
        eddsa_signature_octets(base64.b64decode(ED25519_SIGNATURE), signature_octets=64), message
    )
    original = base64.b64decode(
        "Edk+IB9KNNWg0HAjm7FazXyrd5m3Rk8zNZbvNpAcM+eysqcUOMIjWoevFkjH5GaMWeG96GUVZu6ECKOQmemHDg=="
    )
    with pytest.raises(InvalidSignature):
        key.verify(original, message)


def test_the_backend_verifies_the_erratum_corrected_ed448_signature():
    _needs_backend()
    from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey

    key = Ed448PublicKey.from_public_bytes(_dnskey(16, ED448_KEY).require_eddsa_key())
    message = rrsig_signed_data(
        _rrsig(
            int(DnsRType.MX),
            16,
            2,
            1440021600,
            1438207200,
            ED448_TAG,
            ED448_OWNER,
            ED448_SIGNATURE,
        ),
        ED448_OWNER,
        [RData_MX("mail.example.com.", 10)],
    )
    key.verify(base64.b64decode(ED448_SIGNATURE), message)


def test_the_converter_agrees_with_the_backend_on_freshly_signed_bytes():
    """DER in, wire r|s out, DER rebuilt: the normalizer and the signer converge exactly.

    ``cryptography`` signs ECDSA deterministically (RFC 6979), so byte equality of the
    rebuilt DER is a real expectation and not a coin flip -- and it is the round trip
    the verification leg will take on every signature the backend is handed.
    """
    _needs_backend()
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    private = ec.generate_private_key(ec.SECP256R1())
    der = private.sign(b"namespy", ec.ECDSA(hashes.SHA256()))
    wire = ecdsa_signature_octets(der, field_octets=32)
    assert len(wire) == 64
    assert ecdsa_signature_to_der(wire, field_octets=32) == der
    private.public_key().verify(der, b"namespy", ec.ECDSA(hashes.SHA256()))
