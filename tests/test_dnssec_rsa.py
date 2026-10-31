"""RSA key packing for DNSKEY (RFC 3110 §2), and the signature padding **erratum 2811** fixes.

No cryptographic operation happens here: these are the rules for turning RDATA into two integers
and back, plus the octet-count rule for an RSA signature. That means every test is exact, and none
of them needs `namespy[crypto]`.

The tests are grouped by the sentence they enforce rather than by function, because the failure
modes are not symmetric. A key that cannot be read is a malformed record; a key that is readable
but 512 bits is a policy violation; and a signature two octets short is neither -- it is what a
server that implemented RFC 3110 §3¶10's published wording sends, and the erratum says the
validator's job is to put those octets back.
"""

import pytest

from namespy.crypto import (
    MAX_RSA_KEY_BITS,
)
from namespy.dnssec import (
    MalformedRsaKeyError,
    RsaPublicKey,
    pack_rsa_public_key,
    rsa_signature_octets,
    unpack_rsa_public_key,
)
from namespy.rdata import RData_DNSKEY

EXPONENT = 65537
N512 = (1 << 511) | 3  # odd, 512 bits, top and bottom bits set as a modulus has them
N1024 = (1 << 1023) | 3
N4096 = (1 << 4095) | 3


def _dnskey(algorithm: int, key: bytes, flags: int = 257) -> RData_DNSKEY:
    return RData_DNSKEY(flags, 3, algorithm, key)


def test_a_short_exponent_uses_the_one_octet_length_form():
    """§2¶2's figure: exponent length, exponent, then the modulus to the end of the RDATA."""
    blob = pack_rsa_public_key(EXPONENT, N512)
    assert blob[0] == 3  # 65537 is three octets, so the length sits in the first octet
    assert blob[1:4] == b"\x01\x00\x01"
    assert len(blob) == 1 + 3 + 64
    assert unpack_rsa_public_key(blob) == RsaPublicKey(EXPONENT, N512)


def test_a_256_octet_exponent_switches_to_the_three_octet_form():
    """§2¶3: a zero first octet means "the length follows in two octets".

    Reachable but rare -- §4 of the same RFC recommends 65537 -- which is exactly why it needs a
    test: nothing in normal traffic would notice a regression here.
    """
    big_exponent = (1 << 2047) | 1  # 256 octets, odd
    blob = pack_rsa_public_key(big_exponent, N1024)
    assert blob[:3] == b"\x00\x01\x00"
    assert len(blob) == 3 + 256 + 128
    key = unpack_rsa_public_key(blob)
    assert key.exponent == big_exponent
    assert key.modulus == N1024


def test_packing_is_the_canonical_encoding_and_round_trips():
    """§2¶3's "is represented as" is prescriptive, so pack then unpack is the identity.

    The 255/256-octet boundary is included: writing the long form for a 3-byte exponent would give
    the same key a different key tag, and a DS matching nothing -- the encoding is only cosmetic
    until the key tag says otherwise.
    """
    for exponent, modulus in (
        (3, N512),
        (17, N1024),
        (EXPONENT, N4096),
        ((1 << 2047) | 1, N512),
    ):
        blob = pack_rsa_public_key(exponent, modulus)
        assert unpack_rsa_public_key(blob).to_wire() == blob
        assert unpack_rsa_public_key(blob).key_bits == modulus.bit_length()


@pytest.mark.parametrize(
    ("blob", "reason"),
    [
        (b"\x01", "too short"),
        (b"\x00\x01", "3-octet"),
        (b"\x00\x00\x00" + b"\x02\x03", "zero-length"),
        (b"\x02\x00\x03" + b"\x02\x03", "leading zero"),
        (b"\x01\x03" + b"\x00" + b"\x02" * 63, "leading zero"),
        (b"\x40\x01" + b"\x02" * 5, "announces a 64-octet exponent"),
    ],
)
def test_key_material_that_cannot_be_read_is_refused(blob, reason):
    """§2¶2-¶3 read strictly: each case fails a different clause, named in the message."""
    with pytest.raises(MalformedRsaKeyError, match=reason):
        unpack_rsa_public_key(blob)


def test_a_non_canonical_length_form_is_refused_rather_than_forgiven():
    """A 3-byte exponent written in the long form is the same key with a different key tag.

    Refusing is the interoperable reading of §2¶3: accepting both encodings would mean two RDATA
    strings for one key, and the DS digest runs over the octets, so a resolver accepting the odd
    one would compare a key tag no signer computed.
    """
    with pytest.raises(MalformedRsaKeyError, match="key tag"):
        unpack_rsa_public_key(b"\x00\x00\x03\x01\x00\x01" + b"\x02" * 64)


def test_packing_refuses_to_emit_a_key_the_protocol_forbids():
    """§2¶3's 4096-bit ceiling is a reason to refuse on the way out, not to warn."""
    with pytest.raises(ValueError, match="4096"):
        pack_rsa_public_key(EXPONENT, (1 << 4096) | 3)
    with pytest.raises(MalformedRsaKeyError, match="positive"):
        pack_rsa_public_key(0, N512)


# ------------------------------------------- the record keeps its leniency (RFC 4034 §2.1)


def test_a_malformed_rsa_key_still_parses_and_still_has_a_key_tag():
    """Parsing interprets nothing, so an unusable key is still a reportable record.

    RFC 4034 §2.1.2 puts these judgements at verification time, and the operational reason holds:
    an operator asking "why is this zone bogus" needs the record counted and its tag computed, not
    a parse error that hides which key broke. Only the accessor refuses.
    """
    record = _dnskey(5, b"\x40\x01")
    assert record.to_presentation().startswith("257 3 5 ")
    assert record.key_tag == RData_DNSKEY(257, 3, 5, b"\x40\x01").key_tag
    with pytest.raises(MalformedRsaKeyError, match="64-octet"):
        record.rsa_public_key()


def test_a_real_key_survives_the_record_round_trip():
    """The accessor sees exactly what was packed, through the DNSKEY codec's own octets."""
    blob = pack_rsa_public_key(EXPONENT, N1024)
    record = _dnskey(8, blob)
    parsed = RData_DNSKEY.parse_from(bytes(record))
    assert parsed.require_rsa_key() == RsaPublicKey(EXPONENT, N1024)
    assert parsed.public_key == blob


# -------------------------------------------------- signature width (erratum 2811, §3¶10)


def test_a_short_rsa_signature_is_padded_to_the_modulus_length():
    """**Erratum 2811** turns §3¶10's "permitted" into "MUST be added".

    The published sentence read as if a signer could return fewer octets than the modulus holds,
    and PKCS #1's I2OSP(s, k) says the signature is exactly k octets. Padding rather than
    rejecting is the interoperable half of that correction: such records exist on the wire, and a
    backend handed a short signature usually fails in the same way a forgery would.
    """
    padded = rsa_signature_octets(b"\x01\x02", key_bits=512)
    assert len(padded) == 64
    assert padded == b"\x00" * 62 + b"\x01\x02"

    exact = b"\xab" * 64
    assert rsa_signature_octets(exact, key_bits=512) == exact


def test_a_wider_than_the_modulus_signature_is_refused_not_trimmed():
    """A value reduced mod n cannot exceed the modulus, so this is not a padding question."""
    with pytest.raises(MalformedRsaKeyError, match="wider than"):
        rsa_signature_octets(b"\x01" * 65, key_bits=512)
    with pytest.raises(MalformedRsaKeyError, match="empty"):
        rsa_signature_octets(b"", key_bits=512)


def test_the_padding_width_follows_the_key_not_a_constant():
    """§3¶9's window is 512 to 4096 bits, so k ranges from 64 to 512 octets."""
    assert len(rsa_signature_octets(b"\x01", key_bits=512)) == 64
    assert len(rsa_signature_octets(b"\x01", key_bits=1024)) == 128
    assert len(rsa_signature_octets(b"\x01", key_bits=4096)) == MAX_RSA_KEY_BITS // 8
