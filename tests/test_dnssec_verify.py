"""The RFC 4035 §5.3.1 procedure: which conditions are checked, in what order, and what failing each one *means*.

The vectors are the same published ones `test_dnssec_ecc.py` pins -- RFC 6605 §6 and RFC
8080 §6 as corrected by erratum 4935 -- run here through the whole procedure rather than
through the encodings alone, which turns "the octets mean what the RFC says" into "the
RRset authenticates". The three-way outcome is the load-bearing part, so most of the
tests below are about its edges: a MUST NOT algorithm must come back INVALID even in an
install that cannot do arithmetic at all (the policy check runs before the backend probe,
which is what makes that testable without one), while an unreadable key must come back
UNSUPPORTED rather than INVALID, because "we could not check" and "it is forged" lead a
resolver down different roads.

The RSA leg has no published vector to pin -- RFC 3110 and RFC 5702 print keys but no
RRSIG -- so it is pinned by deterministic PKCS#1 v1.5 round-trips instead, and the
absence is stated rather than papered over.
"""

import base64
import calendar

import pytest

from namespy import crypto
from namespy.crypto import crypto_available
from namespy.dnssec import (
    ecdsa_signature_from_rs,
    ecdsa_signature_octets,
    pack_ec_public_key,
    pack_rsa_public_key,
    rrsig_signed_data,
)
from namespy.enums import DnsRType
from namespy.rdata import RData_A, RData_DNSKEY, RData_MX, RData_RRSIG
from namespy.verify import SignatureOutcome, verify_rrsig


def _needs_backend() -> None:
    """Skip unless the probe itself reports a backend -- the convention in test_crypto_backend."""
    if not crypto_available():
        pytest.skip("namespy[crypto] is not installed")


# ------------------------------------------------------ published vectors, same as test_dnssec_ecc

P256_KEY = (
    "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA=="
)
P256_OWNER = "example.net."
P256_TAG = 55648
P256_SIGNATURE = (
    "qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXAyGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw=="
)
P256_EXP = calendar.timegm((2010, 9, 9, 10, 4, 39))
P256_INC = calendar.timegm((2010, 8, 12, 10, 4, 39))
P256_NOW = (P256_INC + P256_EXP) // 2

P384_KEY = (
    "xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1"
    "w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8"
    "/uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40"
)
P384_TAG = 10771
P384_SIGNATURE = (
    "/L5hDKIvGDyI1fcARX3z65qrmPsVz73QD1Mr5CEqOiLP"
    "95hxQouuroGCeZOvzFaxsT8Glr74hbavRKayJNuydCuz"
    "WTSSPdz7wnqXL5bdcJzusdnI0RSMROxxwGipWcJm"
)
P384_EXP = calendar.timegm((2010, 9, 9, 10, 20, 25))
P384_INC = calendar.timegm((2010, 8, 12, 10, 20, 25))
P384_NOW = (P384_INC + P384_EXP) // 2

ED25519_KEY = "l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4="
ED25519_TAG = 3613
ED25519_SIGNATURE = (
    "oL9krJun7xfBOIWcGHi7mag5/hdZrKWw15jPGrHpjQeRAvTdszaPD+QLs3fx8A4M3e23mRZ9VrbpMngwcrqNAg=="
)
ED25519_KEY_2 = "zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs="
ED25519_TAG_2 = 35217
EDDSA_EXP, EDDSA_INC, EDDSA_NOW = 1440021600, 1438207200, 1440000000

ED448_KEY = "3kgROaDjrh0H2iuixWBrc8g2EpBBLCdGzHmn+G2MpTPhpj/OiBVHHSfPodx1FYYUcJKm1MDpJtIA"
ED448_TAG = 9713
ED448_SIGNATURE = (
    "3cPAHkmlnxcDHMyg7vFC34l0blBhuG1qpwLmjInI8w1CMB29FkEAIJUA0am"
    "xWndkmnBZ6SKiwZSAxGILn/NBtOXft0+Gj7FSvOKxE/07+4RQvE581N3Aj/"
    "JtIyaiYVdnYtyMWbSNyGEY2213WKsJlwEA"
)


def _dnskey(algorithm: int, key, flags: int = 257, protocol: int = 3) -> RData_DNSKEY:
    return RData_DNSKEY(flags, protocol, algorithm, key)


def _rrsig(
    type_covered: int,
    algorithm: int,
    labels: int,
    expiration: int,
    inception: int,
    tag: int,
    signer: str,
    signature,
) -> RData_RRSIG:
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


def _p256_rrsig(**over) -> RData_RRSIG:
    fields: dict = {
        "type_covered": int(DnsRType.A),
        "algorithm": 13,
        "labels": 3,
        "expiration": P256_EXP,
        "inception": P256_INC,
        "tag": P256_TAG,
        "signer": P256_OWNER,
        "signature": P256_SIGNATURE,
    }
    fields.update(over)
    return _rrsig(**fields)


def _a_rrset(ip: str = "192.0.2.1"):
    return [RData_A(ip)]


# --------------------------------------------- outcomes decided before the backend is consulted


@pytest.mark.parametrize("algorithm", [1, 3, 6])
def test_must_not_algorithms_are_invalid_not_unsupported(algorithm: int):
    """Refused by RFC 9904 before any arithmetic is even contemplated.

    INVALID rather than UNSUPPORTED is the deliberate mapping: §1.2¶3 marks these so
    resolvers "can remove support for validating it", and a signature nobody may validate
    authenticates nothing. The answer must not change with the install -- an unmodified
    default install reports the same verdict as one with the crypto extra -- which is
    what the position of this check, ahead of every backend question, guarantees.
    """
    key = _dnskey(algorithm, "AQEBwAAB")
    rrsig = _rrsig(
        int(DnsRType.A), algorithm, 3, P256_EXP, P256_INC, key.key_tag, P256_OWNER, b"\x01\x02"
    )
    verdict = verify_rrsig(rrsig, "www.example.net.", _a_rrset(), [key], now=P256_NOW)
    assert verdict.outcome is SignatureOutcome.INVALID
    assert "RFC 9904 Table 2" in verdict.reason


@pytest.mark.parametrize(("algorithm", "status"), [(12, "MAY"), (99, "UNKNOWN")])
def test_algorithms_this_package_cannot_attempt_are_unsupported(algorithm: int, status: str):
    """GOST is registered at MAY and unregistered numbers carry no pairing at all.

    Neither is bogus material -- they are checks that cannot run, RFC 9080 §3.1's
    Indeterminate -- and the reason quotes the RFC 9904 status so the operator learns
    which of the two situations they are in.
    """
    key = _dnskey(algorithm, b"\x01" * 32)
    rrsig = _rrsig(
        int(DnsRType.A), algorithm, 3, P256_EXP, P256_INC, key.key_tag, P256_OWNER, b"\x01\x02"
    )
    verdict = verify_rrsig(rrsig, "www.example.net.", _a_rrset(), [key], now=P256_NOW)
    assert verdict.outcome is SignatureOutcome.UNSUPPORTED
    assert status in verdict.reason


def test_type_covered_must_name_the_rrsets_type():
    """A DNSKEY-matched RRSIG over the wrong RR type is §5.3.1¶4, before any arithmetic."""
    key = _dnskey(13, P256_KEY)
    rrsig = _p256_rrsig(type_covered=int(DnsRType.TXT))
    verdict = verify_rrsig(rrsig, "www.example.net.", _a_rrset(), [key], now=P256_NOW)
    assert verdict.outcome is SignatureOutcome.INVALID
    assert "§5.3.1¶4" in verdict.reason


def test_an_expired_signature_never_reaches_the_backend():
    """§5.3.1¶6-¶7's window is field arithmetic; the RFC's own vectors expired in 2010.

    now=None takes the wall clock, which in any real run is past 2010 -- so this is the
    procedure refusing the same signature the encoding tests verified, for a reason that
    has nothing to do with the bytes: RFC 4034 §3.1.5¶1 says it MUST NOT be used.
    """
    key = _dnskey(13, P256_KEY)
    verdict = verify_rrsig(_p256_rrsig(), "www.example.net.", _a_rrset(), [key])
    assert verdict.outcome is SignatureOutcome.INVALID
    assert "validity window" in verdict.reason
    assert verdict.attempts == 0


def test_labels_larger_than_the_owner_is_a_broken_record_not_a_broken_zone():
    """§5.3.1¶5 / RFC 4034 §3.1.3¶3: Labels may not exceed the owner's count.

    The reconstruction refuses it, and the verdict is INVALID: this record cannot
    describe a signature anyone made, so retrying elsewhere will not find a different
    meaning.
    """
    key = _dnskey(13, P256_KEY)
    rrsig = _p256_rrsig(labels=4)
    verdict = verify_rrsig(rrsig, "www.example.net.", _a_rrset(), [key], now=P256_NOW)
    assert verdict.outcome is SignatureOutcome.INVALID
    assert "reconstructed" in verdict.reason


def test_an_empty_rrset_is_a_calling_error_not_a_verdict():
    """There is no §5.3.1 condition an empty RRset could satisfy; the caller is wrong."""
    key = _dnskey(13, P256_KEY)
    with pytest.raises(ValueError, match="needs an RRset"):
        verify_rrsig(_p256_rrsig(), "www.example.net.", [], [key], now=P256_NOW)


def test_no_dnskey_in_the_set_matches_the_tag():
    """§5.3.1¶8: the tag and algorithm must name some key here, or the answer is bogus."""
    key = _dnskey(13, P256_KEY)
    rrsig = _p256_rrsig(tag=P256_TAG + 1)
    verdict = verify_rrsig(rrsig, "www.example.net.", _a_rrset(), [key], now=P256_NOW)
    assert verdict.outcome is SignatureOutcome.INVALID
    assert "§5.3.1¶8" in verdict.reason


def test_a_matching_key_with_the_wrong_protocol_is_disqualified():
    """RFC 4034 §2.1.2 makes protocol 3 a verification rule, not a parse rule.

    The record parses fine -- which is why the reason has to come from this layer: it is
    the difference between a zone an operator can read and one they can only count.
    """
    key = _dnskey(13, P256_KEY, protocol=2)
    verdict = verify_rrsig(
        _p256_rrsig(tag=key.key_tag), "www.example.net.", _a_rrset(), [key], now=P256_NOW
    )
    assert verdict.outcome is SignatureOutcome.INVALID
    assert "protocol 2" in verdict.reason
    assert "§2.1.2" in verdict.reason


def test_a_matching_key_without_the_zone_flag_is_disqualified():
    """§5.3.1¶9: the matching DNSKEY MUST have the Zone Flag bit set."""
    key = _dnskey(13, P256_KEY, flags=1)  # SEP only, no zone bit
    verdict = verify_rrsig(
        _p256_rrsig(tag=key.key_tag), "www.example.net.", _a_rrset(), [key], now=P256_NOW
    )
    assert verdict.outcome is SignatureOutcome.INVALID
    assert "Zone Flag" in verdict.reason


def test_without_a_backend_the_answer_arrives_after_everything_else_passed(monkeypatch):
    """The install-without-the-extra case: policy, window, records, keys all pass; arithmetic cannot run.

    "install namespy[crypto]" is the whole point of the message -- the operator has to
    learn what was missing rather than that something failed -- and the verdict stays
    UNSUPPORTED, because a default install is not a validator that refused: it is one
    that never got to try.
    """
    monkeypatch.setattr(crypto, "_BACKEND", None)
    monkeypatch.setattr(crypto, "_PROBED", True)
    key = _dnskey(13, P256_KEY)
    verdict = verify_rrsig(_p256_rrsig(), "www.example.net.", _a_rrset(), [key], now=P256_NOW)
    assert verdict.outcome is SignatureOutcome.UNSUPPORTED
    assert "namespy[crypto]" in verdict.reason


# ----------------------------------------------------------------------- the arithmetic itself


def test_the_published_p256_rrset_authenticates_under_the_published_key():
    """The whole §5.3.1 walk over RFC 6605 §6.1: window open, key matched, curve accepted."""
    _needs_backend()
    key = _dnskey(13, P256_KEY)
    verdict = verify_rrsig(_p256_rrsig(), "www.example.net.", _a_rrset(), [key], now=P256_NOW)
    assert verdict.verified
    assert verdict.outcome is SignatureOutcome.VALID
    assert verdict.key_tag == P256_TAG
    assert verdict.attempts == 1
    assert "RFC 6605" in verdict.reason


def test_the_published_p384_rrset_authenticates_too():
    _needs_backend()
    key = _dnskey(14, P384_KEY)
    rrsig = _rrsig(int(DnsRType.A), 14, 3, P384_EXP, P384_INC, P384_TAG, P256_OWNER, P384_SIGNATURE)
    verdict = verify_rrsig(rrsig, "www.example.net.", _a_rrset(), [key], now=P384_NOW)
    assert verdict.verified


@pytest.mark.parametrize(
    ("algorithm", "key_text", "tag", "signature"),
    [
        (15, ED25519_KEY, ED25519_TAG, ED25519_SIGNATURE),
        (16, ED448_KEY, ED448_TAG, ED448_SIGNATURE),
    ],
)
def test_the_erratum_corrected_eddsa_rrsets_authenticate(
    algorithm: int, key_text: str, tag: int, signature: str
):
    """RFC 8080 §6 as erratum 4935 corrected it, walked end to end through the procedure."""
    _needs_backend()
    key = _dnskey(algorithm, key_text)
    rrsig = _rrsig(
        int(DnsRType.MX), algorithm, 2, EDDSA_EXP, EDDSA_INC, tag, "example.com.", signature
    )
    verdict = verify_rrsig(
        rrsig, "example.com.", [RData_MX("mail.example.com.", 10)], [key], now=EDDSA_NOW
    )
    assert verdict.verified
    assert "RFC 8080" in verdict.reason


def test_one_edited_octet_in_the_rrset_and_the_answer_is_invalid():
    """The tamper case, and the reason the arithmetic had to run to find it.

    Every §5.3.1 condition above the arithmetic still holds -- window open, tag matched,
    zone flag set -- which is the point: 192.0.2.2 differs from 192.0.2.1 by one octet
    and no field-level check can see the difference, only the curve can.
    """
    _needs_backend()
    key = _dnskey(13, P256_KEY)
    verdict = verify_rrsig(
        _p256_rrsig(), "www.example.net.", _a_rrset("192.0.2.2"), [key], now=P256_NOW
    )
    assert verdict.outcome is SignatureOutcome.INVALID
    assert verdict.attempts == 1
    assert "§5.3.1¶10" in verdict.reason


def test_a_lying_key_tag_points_the_arithmetic_at_the_wrong_key():
    """The RRSIG's tag matches the *second* published key, which did not sign this.

    §5.3.1¶8 selects candidates by the tag the RRSIG *claims*; nothing in the record
    tells the validator the claim is a lie, so the arithmetic is the only check, and it
    refuses -- INVALID with one attempt, not two: the other key was never a candidate.
    """
    _needs_backend()
    key_1 = _dnskey(15, ED25519_KEY)
    key_2 = _dnskey(15, ED25519_KEY_2)
    rrsig = _rrsig(
        int(DnsRType.MX),
        15,
        2,
        EDDSA_EXP,
        EDDSA_INC,
        ED25519_TAG_2,
        "example.com.",
        ED25519_SIGNATURE,
    )
    verdict = verify_rrsig(
        rrsig, "example.com.", [RData_MX("mail.example.com.", 10)], [key_1, key_2], now=EDDSA_NOW
    )
    assert verdict.outcome is SignatureOutcome.INVALID
    assert verdict.attempts == 1


def _rsa_rrsig(private, algorithm: int, hash_name: str, key: RData_DNSKEY):
    """A real signature over a real RRset, wrapped in the RRSIG that will carry it.

    The signed bytes exclude the Signature field (§3.1.8.1¶4), so the placeholder the
    first record carries has no effect on what gets signed -- which is what lets the
    round-trip complete in two steps instead of a chicken-and-egg.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    fields = {
        "type_covered": int(DnsRType.A),
        "algorithm": algorithm,
        "labels": 3,
        "expiration": EDDSA_EXP,
        "inception": EDDSA_INC,
        "tag": key.key_tag,
        "signer": P256_OWNER,
    }
    rrsig = _rrsig(**fields, signature=b"\x11" * 256)
    message = rrsig_signed_data(rrsig, "www.example.net.", _a_rrset())
    hasher = getattr(hashes, hash_name)()
    signature = private.sign(message, padding.PKCS1v15(), hasher)
    return _rrsig(**fields, signature=signature)


@pytest.mark.parametrize(
    ("algorithm", "hash_name", "spec"),
    [(8, "SHA256", "RFC 5702"), (5, "SHA1", "RFC 3110")],
)
def test_rsa_round_trips_through_the_procedure(algorithm: int, hash_name: str, spec: str):
    """No RFC prints an RSA RRSIG, so these round-trips stand in -- and one is RSASHA1.

    Algorithm 5 earns its place deliberately: RFC 9905 deprecates it *for signing*, but
    RFC 9904 Table 2 keeps it a MUST *for validation*, precisely because zones signed
    with it are still out there -- a validator that refused to check one would report a
    real answer as bogus, which is the failure the two-column split exists to prevent.
    """
    _needs_backend()
    from cryptography.hazmat.primitives.asymmetric import rsa

    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private.private_numbers().public_numbers
    key = _dnskey(algorithm, pack_rsa_public_key(numbers.e, numbers.n))
    verdict = verify_rrsig(
        _rsa_rrsig(private, algorithm, hash_name, key),
        "www.example.net.",
        _a_rrset(),
        [key],
        now=EDDSA_NOW,
    )
    assert verdict.verified
    assert spec in verdict.reason


def test_a_512_bit_key_under_algorithm_10_is_material_no_floor_check_can_bless():
    """RFC 5702 §2.2¶2: an RSA/SHA-512 modulus MUST NOT be under 1024 bits.

    The signature would verify fine -- a 512-bit RSA/SHA-512 key can be made, and PKCS#1
    does not care about strength -- which is exactly why the refusal is arithmetic-tier
    rather than caller policy: the downgrade surface is a zone choosing which of its keys
    the RRSIGs can be checked against, and the weakest one must not get a turn.
    """
    _needs_backend()
    small_modulus = int("f" * 128, 16)  # 512 bits, top bit set: key_bits 512 by construction
    key = _dnskey(10, pack_rsa_public_key(65537, small_modulus))
    rrsig = _rrsig(
        int(DnsRType.A), 10, 3, EDDSA_EXP, EDDSA_INC, key.key_tag, P256_OWNER, b"\x40" * 64
    )
    verdict = verify_rrsig(rrsig, "www.example.net.", _a_rrset(), [key], now=EDDSA_NOW)
    assert verdict.outcome is SignatureOutcome.UNSUPPORTED
    assert "1024-bit floor" in verdict.reason
    assert verdict.attempts == 0


def test_the_dispatch_names_the_two_ways_an_rsa_key_can_be_the_wrong_size():
    """The window the arithmetic enforces, from both edges, called directly.

    The floor test above reaches it through the full procedure; these two go straight to
    :func:`namespy.crypto.verify_dnskey_signature` because the ceiling case -- RFC 3110
    §2¶3's 4096-bit interoperability limit -- has no procedure-level story worth telling
    yet: it refuses before any backend object is built, which is the whole point.
    """
    _needs_backend()
    from namespy.crypto import SignatureMaterialError, verify_dnskey_signature

    huge = int("f" * 1026, 16)  # 4104 bits: over the ceiling, needs the raise to be seen
    material = pack_rsa_public_key(65537, huge, max_key_bits=8192)
    with pytest.raises(SignatureMaterialError, match="over the 4096-bit ceiling"):
        verify_dnskey_signature(8, material, b"\x01" * 512, b"message")
    with pytest.raises(SignatureMaterialError, match="no primitive"):
        verify_dnskey_signature(99, b"\x01" * 32, b"\x01", b"message")


def test_der_inside_an_ecdsa_rrsig_is_a_malformed_record_not_a_generous_reading():
    """The encoding leg's stance, enforced end to end: RFC 6605 §4¶2 fixes the wire form.

    The DER of the very signature that verifies in r|s form is refused as unreadable
    material -- same bytes, same integers, one reading only.
    """
    _needs_backend()
    wire = base64.b64decode(P256_SIGNATURE)
    der = ecdsa_signature_from_rs(wire, field_octets=32).to_der()
    key = _dnskey(13, P256_KEY)
    verdict = verify_rrsig(
        _p256_rrsig(signature=der), "www.example.net.", _a_rrset(), [key], now=P256_NOW
    )
    assert verdict.outcome is SignatureOutcome.UNSUPPORTED
    assert "§4¶2" in verdict.reason


def test_an_off_curve_twin_shares_the_tag_and_the_loop_moves_past_it():
    """Same tag by construction (two same-parity key bytes traded), off every curve.

    The trade is +1/-1 across two bytes of equal weight in the checksum: the key tag
    shifts alternating octets by eight, so a neighbour would have moved it by 255 -- the
    weighting RFC 4034 Appendix B gives it, which erratum 4552 is about. The §5.3.1¶10
    loop must survive a candidate the backend cannot build a key from: unreadable
    material is skipped rather than ending the attempt, the real key verifies, and
    *attempts counts only arithmetic that ran* -- one, not two.
    """
    _needs_backend()
    key_bytes = bytearray(base64.b64decode(P256_KEY))
    for index in range(len(key_bytes) - 2):
        if key_bytes[index] < 255 and key_bytes[index + 2] > 0:
            key_bytes[index] += 1
            key_bytes[index + 2] -= 1  # same weight in the tag: unchanged
            break
    twin = _dnskey(13, bytes(key_bytes))
    assert twin.key_tag == P256_TAG  # the construction held
    verdict = verify_rrsig(
        _p256_rrsig(),
        "www.example.net.",
        _a_rrset(),
        [twin, _dnskey(13, P256_KEY)],
        now=P256_NOW,
    )
    assert verdict.verified
    assert verdict.attempts == 1


def test_an_apex_dnskey_rrset_signed_by_its_own_key_verifies():
    """§5.3.1 over the DNSKEY RRset itself -- the self-signature the trust chain starts from.

    Nothing here consults a DS or an anchor (that is §5.3.1¶12-¶13, the next commit's
    question); what this pins is that the procedure handles owner == signer == apex,
    rdatas that *are* DNSKEY records, and the DNSKEY canonical form -- so the anchor
    stage can reuse this call instead of growing a special path.
    """
    _needs_backend()
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    private = ec.generate_private_key(ec.SECP256R1())
    numbers = private.public_key().public_numbers()
    key = _dnskey(13, pack_ec_public_key(numbers.x, numbers.y, field_octets=32))
    placeholder = _rrsig(
        int(DnsRType.DNSKEY), 13, 2, EDDSA_EXP, EDDSA_INC, key.key_tag, P256_OWNER, b"\x22" * 64
    )
    message = rrsig_signed_data(placeholder, P256_OWNER, [key])
    signature = private.sign(message, ec.ECDSA(hashes.SHA256()))
    wire = ecdsa_signature_octets(signature, field_octets=32)
    verdict = verify_rrsig(
        _rrsig(int(DnsRType.DNSKEY), 13, 2, EDDSA_EXP, EDDSA_INC, key.key_tag, P256_OWNER, wire),
        P256_OWNER,
        [key],
        [key],
        now=EDDSA_NOW,
    )
    assert verdict.verified
