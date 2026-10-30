"""The cryptographic boundary: namespy[crypto], the RFC 9904 policy table, no hard dep.

Two different kinds of test live here. Most assert that the *absence* of a dependency is
observable and correct, which is the state every default install is in. The last few need a
present backend: they skip in an install without one and run wherever ``namespy[crypto]`` is
installed, which is what CI's Crypto extra job exists to provide. They also say plainly what
they prove, which is plumbing: that the primitives DNSSEC needs exist at the documented paths
in the version the extra resolves to. They generate their own keys, so they cannot claim
conformance; the RFC's vectors do that in the verification leg.
"""

import importlib
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from namespy.crypto import (
    CRYPTO_EXTRA,
    IMPLEMENT_FOR_VALIDATION,
    MAX_RSA_KEY_BITS,
    MIN_RSA_KEY_BITS,
    SIGNATURE_ALGORITHMS,
    MissingCryptoError,
    SignatureAlgorithm,
    ValidationRequirement,
    backend,
    backend_supports,
    crypto_available,
    require_backend,
    validation_requirement,
)


def _needs_backend() -> None:
    """Skip unless the probe itself reports a backend.

    Deliberately not ``pytest.importorskip("cryptography")``. That answers a different
    question: an empty leftover directory -- what a partial uninstall leaves -- imports as a
    namespace package, so ``importorskip`` passes and the test then dies on a missing
    submodule. Tying the skip to :func:`crypto_available` means the test and the library agree
    on what "installed" means, which is the only version of this that is worth anything.
    """
    if not crypto_available():
        pytest.skip("namespy[crypto] is not installed")


@pytest.fixture
def no_backend(monkeypatch):
    """Force the probe to report an absent backend, then restore the real answer.

    The probe caches, so this is the honest way to reach both branches in one process:
    substitute the "no backend" state and let monkeypatch put the globals back. Deleting
    ``cryptography`` from ``sys.modules`` would test a different situation -- an import that
    has already happened -- and say nothing about a machine that never had it.
    """
    from namespy import crypto

    monkeypatch.setattr(crypto, "_PROBED", True)
    monkeypatch.setattr(crypto, "_BACKEND", None)
    return crypto


def test_importing_namespy_does_not_import_the_backend():
    """The zero-dependency promise, checked where it is actually made: a clean process.

    A test in this file cannot prove it, because by the time tests run other imports have
    happened, so this asks a fresh interpreter what ended up in ``sys.modules``.
    """
    code = (
        "import sys, namespy.crypto, namespy;"
        "print(any(m == 'cryptography' or m.startswith('cryptography.')"
        " for m in sys.modules))"
    )
    finished = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=True,
    )
    assert finished.stdout.strip().endswith("False")


def test_the_probe_answers_without_a_backend(no_backend):
    """Absence is a state rather than an error: the probe reports it and callers decide."""
    assert no_backend.backend() is None
    assert crypto_available() is False
    assert backend_supports(8) is False


def test_the_refusal_names_the_extra_to_install(no_backend):
    """An operator reading this in a log should not have to open the docs first.

    It names what was refused, that the install lacks a backend, and the exact extra --
    capability-named, so the advice stays true whichever feature asked.
    """
    with pytest.raises(MissingCryptoError, match=r"namespy\[crypto\]") as caught:
        no_backend.require_backend("verify an RRSIG")
    assert "verify an RRSIG" in str(caught.value)
    assert "cryptography" in str(caught.value)


def test_a_leftover_directory_is_not_reported_as_a_backend(tmp_path, monkeypatch):
    """An empty ``cryptography/`` on the path is not an installed backend.

    Found the hard way: a partial uninstall leaves the package directory behind, Python
    imports it happily as a namespace package, and ``import cryptography`` then succeeds
    with nothing in it. A probe that reported "backend present" on that evidence would send
    verification code into an AttributeError instead of the MissingCryptoError callers are
    built to handle -- the worse of the two failures, because it looks like a working install
    right up until it is not.

    It needs the distribution to be genuinely absent, and that is the same import-machinery
    fact being tested: an empty directory yields only a *namespace portion*, and the finder
    prefers a real package from anywhere else on ``sys.path``. So shadowing an installed
    ``cryptography`` this way cannot work, and the test says so rather than passing by
    accident in whichever configuration it happens to run.
    """
    from namespy import crypto

    if crypto_available():
        pytest.skip(
            "the shadow below is a namespace portion and would lose to the installed "
            "package; this case needs the distribution genuinely absent"
        )

    (tmp_path / "cryptography").mkdir()
    monkeypatch.setattr(sys, "path", [str(tmp_path), *sys.path])
    monkeypatch.delitem(sys.modules, "cryptography", raising=False)
    monkeypatch.setattr(crypto, "_PROBED", False)
    monkeypatch.setattr(crypto, "_BACKEND", None)

    assert crypto.backend() is None
    assert crypto.crypto_available() is False
    with pytest.raises(MissingCryptoError, match=r"namespy\[crypto\]"):
        crypto.require_backend("verify an RRSIG")


def test_the_extra_is_named_for_the_capability_not_for_dnssec():
    """``[crypto]`` exists, ``[dnssec]`` does not, and the spelling is what users type.

    A renamed extra is a silent breakage for anyone who installed the old one, so the name is
    pinned here rather than left to whoever edits pyproject next.
    """
    with (Path(__file__).resolve().parent.parent / "pyproject.toml").open("rb") as handle:
        project = tomllib.load(handle)["project"]
    extras = project["optional-dependencies"]
    assert CRYPTO_EXTRA in extras
    assert "dnssec" not in extras
    assert any(spec.startswith("cryptography") for spec in extras[CRYPTO_EXTRA])
    # The core install stays empty: the extra is the only way in.
    assert project["dependencies"] == []


def test_rfc_9904_must_implement_set_for_validation():
    """The five numbers RFC 9904 Table 2 marks MUST for a validator.

    Pinned as a set rather than as five lookups, so editing one row cannot quietly shrink what
    this package believes it owes. SHA-1-based RSA (5 and 7) being in the set is the surprising
    part, and it is why a backend cannot get by with the modern algorithms alone: RFC 9905
    retired those two for *signing*, not for *validation*.
    """
    must = {n for n, req in IMPLEMENT_FOR_VALIDATION.items() if req is ValidationRequirement.MUST}
    assert must == {5, 7, 8, 10, 13}
    recommended = {
        n for n, req in IMPLEMENT_FOR_VALIDATION.items() if req is ValidationRequirement.RECOMMENDED
    }
    assert recommended == {14, 15, 16}
    forbidden = {
        n for n, req in IMPLEMENT_FOR_VALIDATION.items() if req is ValidationRequirement.MUST_NOT
    }
    assert forbidden == {1, 3, 6}


def test_an_unregistered_number_is_unknown_not_may():
    """RFC 9904 §2.2 gives new registry entries MAY, which is not the same as no entry.

    An unregistered number has no primitive and no digest pairing, so reading it as MAY would
    invite a guess about how to verify it.
    """
    assert validation_requirement(999) is ValidationRequirement.UNKNOWN
    assert validation_requirement(255) is ValidationRequirement.UNKNOWN
    assert validation_requirement(8) is ValidationRequirement.MUST


def test_everything_we_offer_is_something_the_registry_asks_for():
    """The capability table must never contain a MUST NOT algorithm.

    RSAMD5 (1) is the number someone would add while chasing an old signed zone, and RFC 9904
    Table 2 marks it MUST NOT in every column: implementing it means offering to validate a
    digest the ecosystem has retired.
    """
    assert 1 not in SIGNATURE_ALGORITHMS
    for number in SIGNATURE_ALGORITHMS:
        assert validation_requirement(number) is not ValidationRequirement.MUST_NOT


def test_the_must_implement_algorithms_all_have_a_primitive():
    """Policy and capability checked against each other, which is why both live here.

    If a future backend cannot do one of the five MUST numbers, that is a gap to tell the user
    about rather than a zone to fail on silently, and this is the assertion that notices.
    """
    for number, requirement in IMPLEMENT_FOR_VALIDATION.items():
        if requirement is ValidationRequirement.MUST:
            assert number in SIGNATURE_ALGORITHMS, f"RFC 9904 requires {number}"


def test_signature_pairs_come_from_the_registering_documents():
    """Digest-per-number is the registry's, and a wrong pairing verifies nothing at all.

    13 and 14 are SHA-256 and SHA-384 (RFC 6605) and are not interchangeable; EdDSA carries its
    hash inside the primitive, so the None there is a fact about the scheme rather than a gap.
    """
    assert SIGNATURE_ALGORITHMS[13].digest == "sha256"
    assert SIGNATURE_ALGORITHMS[14].digest == "sha384"
    assert SIGNATURE_ALGORITHMS[8].digest == "sha256"
    assert SIGNATURE_ALGORITHMS[10].digest == "sha512"
    assert SIGNATURE_ALGORITHMS[5].digest == "sha1"
    assert SIGNATURE_ALGORITHMS[15].digest is None
    assert SIGNATURE_ALGORITHMS[15].primitive is SignatureAlgorithm.ED25519
    assert SIGNATURE_ALGORITHMS[14].primitive is SignatureAlgorithm.ECDSA_P384


def test_rsa_key_size_bounds_are_the_protocol_limits():
    """RFC 3110 §3¶9 bounds the modulus at 512 to 4096 bits, and both ends are ours.

    The upper bound is the one people remember and the one the backend will not enforce for us:
    that project documents "denial of service via parsing untrusted key material" as outside its
    security policy, so a resolver reading DNSKEYs off the wire holds the line itself. The lower
    bound matters for a different reason -- a 256-bit RSA key occupies a perfectly well-formed
    RDATA field and can be factored on a laptop, so accepting it would buy validation in name.

    Enforcement is the codec's job and is not written yet; this is the marker that moves when it
    lands, the way ``NxdomainPolicy.VALIDATED`` marks the validation work.
    """
    assert MAX_RSA_KEY_BITS == 4096
    assert MIN_RSA_KEY_BITS == 512
    assert MIN_RSA_KEY_BITS < MAX_RSA_KEY_BITS


# ------------------------------------------------------------------ with the extra
#
# These need namespy[crypto]. The ordinary suite does not install it -- that is the point of
# the extra -- so they skip locally and run in the CI job that installs it.


def test_the_backend_is_reported_when_the_extra_is_installed():
    """The probe finds the distribution, names its version, and is stable when asked twice."""
    _needs_backend()
    found = require_backend("verify an RRSIG")
    assert found is backend()
    assert found.name == "cryptography"
    assert found.version not in ("", "unknown")
    assert backend_supports(13) is True


def test_the_shapes_dnssec_needs_exist_in_the_installed_backend():
    """Proves the integration points, not DNSSEC.

    Three things the verification leg will rest on, each chosen because it is *not* this
    library's ordinary usage:

    * ECDSA signatures arrive as fixed-width r then s (RFC 6605 §4) while the library signs and
      verifies DER (RFC 3279). ``decode_dss_signature`` and ``encode_dss_signature`` are the
      bridge, so they are walked in both directions.
    * A DNSKEY holds an uncompressed point with the ``0x04`` tag stripped, and
      ``from_encoded_point`` is the constructor to use -- not building from coordinates --
      because its documented ``ValueError`` covers an off-curve point, which is exactly what a
      hostile zone can send.
    * Ed25519 public keys load from the 32 raw octets RFC 8080 §4 stores.

    A wrong signature has to raise, and a wrong *key* has to raise sooner: both directions are
    asserted, because a backend that accepted an off-curve point would leave this package's own
    security reasoning silently wrong.
    """
    # The skip guard is the probe's own answer, and it comes before anything touches the
    # library. Getting this wrong is not hypothetical: an import statement above the guard
    # raised ModuleNotFoundError instead of skipping, and failed all four Test jobs on the
    # first CI run of this file -- a failure that cannot be reproduced on a machine that has
    # the extra installed, which is exactly why the guard is a call and not an import.
    _needs_backend()

    found = require_backend("verify an RRSIG")
    assert found.module.__name__ == "cryptography"

    invalid_signature = importlib.import_module("cryptography.exceptions").InvalidSignature
    ec = importlib.import_module("cryptography.hazmat.primitives.asymmetric.ec")
    ed25519 = importlib.import_module("cryptography.hazmat.primitives.asymmetric.ed25519")
    hashes_ = importlib.import_module("cryptography.hazmat.primitives.hashes")
    asym_utils = importlib.import_module("cryptography.hazmat.primitives.asymmetric.utils")

    payload = b"the octets an RRset would have made"
    private_key = ec.generate_private_key(ec.SECP256R1())
    der = private_key.sign(payload, ec.ECDSA(hashes_.SHA256()))

    r, s = asym_utils.decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    assert len(raw) == 64
    re_dered = asym_utils.encode_dss_signature(
        int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
    )
    assert re_dered == der

    numbers = private_key.public_key().public_numbers()
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),
        b"\x04" + numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big"),
    )
    public_key.verify(der, payload, ec.ECDSA(hashes_.SHA256()))

    with pytest.raises(invalid_signature):
        public_key.verify(der, b"different payload", ec.ECDSA(hashes_.SHA256()))

    # Not a point on P-256, which is what a crafted DNSKEY would deliver. The library says
    # only "Invalid EC key", so the match is that string rather than anything more specific:
    # the guarantee being pinned is that it refuses, not how it words the refusal.
    with pytest.raises(ValueError, match="Invalid EC key"):
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + b"\x11" * 64)

    seed_key = ed25519.Ed25519PrivateKey.generate()
    raw_ed = seed_key.public_key().public_bytes_raw()
    assert len(raw_ed) == 32
    ed25519.Ed25519PublicKey.from_public_bytes(raw_ed).verify(seed_key.sign(payload), payload)
