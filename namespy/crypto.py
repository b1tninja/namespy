"""The optional cryptographic backend, and what RFC 9904 requires of a validator.

This is the boundary, not the feature. DNSSEC validation needs signature arithmetic --
RSA, ECDSA over two NIST curves, EdDSA over two Edwards curves -- that this package does
not carry, because the promise at the top of the README is a zero-dependency install and
verification code nobody has audited would be a worse trade than no verification at all.
So the arithmetic lives behind one extra (``namespy[crypto]``), one module finds it, and
nothing else in the tree is allowed to import it.

**Nothing here imports the backend at module scope.** ``import namespy`` must stay cheap
and dependency-free, so the one ``import`` of the backend is inside :func:`backend`, and
the result is cached: a process either has a backend or does not, and asking twice should
not re-import.

The tables in this module are the specification's, not the backend's. RFC 9904 Table 2
says what a validator must implement regardless of which library answers, and pinning that
here means the algorithm policy is a testable, reviewable object rather than whatever the
installed library happens to offer. When validation lands, it checks the two against each
other and says plainly which side is short.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from enum import Enum
from types import ModuleType

from .dnssec import (
    MalformedEcKeyError,
    MalformedRsaKeyError,
    ecdsa_signature_from_rs,
    eddsa_public_key_octets,
    eddsa_signature_octets,
    rsa_signature_octets,
    unpack_ec_public_key,
    unpack_rsa_public_key,
)

__all__ = [
    "CRYPTO_DISTRIBUTION",
    "CRYPTO_EXTRA",
    "ECDSA_ALGORITHMS",
    "ECDSA_FIELD_OCTETS",
    "EC_KEY_OCTETS",
    "EC_SIGNATURE_OCTETS",
    "EDDSA_ALGORITHMS",
    "EDDSA_KEY_OCTETS",
    "EDDSA_SIGNATURE_OCTETS",
    "IMPLEMENT_FOR_VALIDATION",
    "MAX_RSA_KEY_BITS",
    "MIN_RSA_KEY_BITS",
    "RSA_ALGORITHMS",
    "RSA_MIN_KEY_BITS_BY_ALGORITHM",
    "SIGNATURE_ALGORITHMS",
    "CryptoBackend",
    "MissingCryptoError",
    "SignatureAlgorithm",
    "SignatureAlgorithmSpec",
    "SignatureMaterialError",
    "ValidationRequirement",
    "backend",
    "backend_supports",
    "crypto_available",
    "minimum_rsa_key_bits",
    "require_backend",
    "validation_requirement",
    "verify_dnskey_signature",
]

#: The extra that pulls the backend in, spelled as a user would type it. It belongs in the
#: error message rather than left to be guessed from the docs.
CRYPTO_EXTRA = "crypto"

#: What to install. Separate from the extra name so the message reads as advice.
CRYPTO_DISTRIBUTION = "cryptography"

#: RFC 3110 §3¶9: the modulus "MUST be not less than 512 bits and not more than 4096 bits.
#: These are protocol limits." Both ends are ours to enforce, the upper one because the backend
#: this package will use documents "denial of service via parsing untrusted key material" as
#: outside what it treats as a security issue -- a fair line for a general-purpose library, and
#: precisely the reason a resolver that reads DNSKEYs off the wire needs a bound of its own. A
#: 1 MB DNSKEY should be refused as a malformed record before anything reaches an RSA
#: implementation.
MAX_RSA_KEY_BITS = 4096

#: The same sentence's other end. A 256-bit RSA key fits the RDATA field as happily as a
#: 2048-bit one and factors in an afternoon, so accepting it would buy validation in name only.
#: This is the floor of the floors: RFC 5702 §2.2 raises it to 1024 bits for RSA/SHA-512, so use
#: :func:`minimum_rsa_key_bits` with the algorithm number rather than this constant.
MIN_RSA_KEY_BITS = 512


class MissingCryptoError(RuntimeError):
    """A cryptographic operation was asked for on an install that cannot do it.

    A ``RuntimeError`` and not an ``ImportError``, because the import failure is not the
    caller's problem: code on this path already imported successfully and is asking for a
    capability. The distinction matters to the resolver, which will catch this and answer
    the way it answers any policy refusal -- unauthenticated, with the reason recorded --
    rather than treating it as a broken installation to propagate.
    """


@dataclass(frozen=True)
class CryptoBackend:
    """A present backend, named and versioned so a trace can say what verified what."""

    name: str
    version: str
    module: ModuleType


class ValidationRequirement(Enum):
    """The strength of an RFC 9904 "Implement for DNSSEC Validation" entry."""

    MUST = "MUST"
    RECOMMENDED = "RECOMMENDED"
    MAY = "MAY"
    MUST_NOT = "MUST NOT"
    #: Not in the registry. RFC 9904 §2.2 puts new entries at MAY, but a number nobody has
    #: registered is not the same as one registered as MAY: it has no pairing with a hash
    #: function or a primitive at all, so nothing can be assumed about it.
    UNKNOWN = "UNKNOWN"


#: RFC 9904 Table 2, "Implement for DNSSEC Validation" column. Note that RSASHA1 (5) and
#: RSASHA1-NSEC3-SHA1 (7) are MUST for validation even though RFC 9905 deprecated their use
#: for signing: a validator that refuses them cannot read the zones still signed with them,
#: which is the whole difference between "do not use this" and "do not implement this". It
#: is also why a backend has to do SHA-1 as well as SHA-2.
IMPLEMENT_FOR_VALIDATION: dict[int, ValidationRequirement] = {
    1: ValidationRequirement.MUST_NOT,  # RSAMD5
    3: ValidationRequirement.MUST_NOT,  # DSA
    5: ValidationRequirement.MUST,  # RSASHA1
    6: ValidationRequirement.MUST_NOT,  # DSA-NSEC3-SHA1
    7: ValidationRequirement.MUST,  # RSASHA1-NSEC3-SHA1
    8: ValidationRequirement.MUST,  # RSASHA256
    10: ValidationRequirement.MUST,  # RSASHA512
    12: ValidationRequirement.MAY,  # ECC-GOST
    13: ValidationRequirement.MUST,  # ECDSAP256SHA256
    14: ValidationRequirement.RECOMMENDED,  # ECDSAP384SHA384
    15: ValidationRequirement.RECOMMENDED,  # ED25519
    16: ValidationRequirement.RECOMMENDED,  # ED448
    17: ValidationRequirement.MAY,  # SM2SM3
    23: ValidationRequirement.MAY,  # ECC-GOST12
    253: ValidationRequirement.MAY,  # PRIVATEDNS
    254: ValidationRequirement.MAY,  # PRIVATEOID
}


class SignatureAlgorithm(Enum):
    """The primitive a DNSKEY algorithm number names, in this package's own vocabulary.

    Deliberately not the backend's class names. Verification code should be written
    against this and translate once, so that swapping or dropping the backend is a change
    to this module rather than a hunt through the resolver.
    """

    RSA = "rsa"
    ECDSA_P256 = "ecdsa-p256"
    ECDSA_P384 = "ecdsa-p384"
    ED25519 = "ed25519"
    ED448 = "ed448"


@dataclass(frozen=True)
class SignatureAlgorithmSpec:
    """What an RRSIG Algorithm value means: primitive, digest, and who says so."""

    primitive: SignatureAlgorithm
    digest: str | None
    spec: str


#: Algorithm number to primitive and digest, per the documents that registered each:
#: RFC 3110 §2-§4 (RSA/SHA-1, numbers 5 and 7), RFC 5702 §2-§3 (RSA/SHA-256 and RSA/SHA-512,
#: 8 and 10), RFC 6605 §3 and §5 (ECDSA over P-256 and P-384, 13 and 14), RFC 8080 §3
#: (Ed25519 and Ed448, 15 and 16). EdDSA has no separate digest -- it is part of the
#: primitive -- hence None, which is a fact about the scheme and not a gap.
#:
#: What this table does *not* settle is the octet encoding of the key and signature
#: fields -- that is layout, and layout lives in namespy.dnssec: RFC 3110 §2's
#: exponent-then-modulus packing and erratum 2811's signature width; RFC 6605 §4's x|y
#: points and r|s signatures (fixed-width field elements, never DER on the wire); RFC
#: 8080 §3-§4's bare EdDSA bit strings. What this module owns is the policy side of the
#: same question: which algorithm number carries which widths, cited to the paragraph
#: that sets them, so the codec can be handed a bound rather than invent one.
SIGNATURE_ALGORITHMS: dict[int, SignatureAlgorithmSpec] = {
    5: SignatureAlgorithmSpec(SignatureAlgorithm.RSA, "sha1", "RFC 3110"),
    7: SignatureAlgorithmSpec(SignatureAlgorithm.RSA, "sha1", "RFC 3110"),
    8: SignatureAlgorithmSpec(SignatureAlgorithm.RSA, "sha256", "RFC 5702"),
    10: SignatureAlgorithmSpec(SignatureAlgorithm.RSA, "sha512", "RFC 5702"),
    13: SignatureAlgorithmSpec(SignatureAlgorithm.ECDSA_P256, "sha256", "RFC 6605"),
    14: SignatureAlgorithmSpec(SignatureAlgorithm.ECDSA_P384, "sha384", "RFC 6605"),
    15: SignatureAlgorithmSpec(SignatureAlgorithm.ED25519, None, "RFC 8080"),
    16: SignatureAlgorithmSpec(SignatureAlgorithm.ED448, None, "RFC 8080"),
}

#: The algorithm numbers whose DNSKEY public key is RFC 3110 §2's exponent-length, exponent,
#: modulus. Derived from the table above rather than written out again, which is what keeps
#: algorithm 1 (RSA/MD5) out: RFC 3110 §2's notes moved RSA/SHA-1 onto number 5 precisely to
#: separate it from RFC 2537's RSA/MD5 keys, which carry a key-length header this reader would
#: misparse as an exponent length. RFC 9904 makes 1 a MUST NOT in any case.
RSA_ALGORITHMS: frozenset[int] = frozenset(
    number
    for number, spec in SIGNATURE_ALGORITHMS.items()
    if spec.primitive is SignatureAlgorithm.RSA
)

#: The lower bound on the modulus, per algorithm. There is not one answer: RFC 3110 §3¶9 sets 512
#: bits for RSA/SHA-1 (numbers 5 and 7) and RFC 5702 §2.1¶2 repeats it for RSA/SHA-256, but
#: **RFC 5702 §2.2¶2 sets 1024 bits for RSA/SHA-512** -- "MUST NOT be less than 1024 bits". A
#: single MIN constant therefore accepts a 512-bit RSA/SHA-512 key that RFC 5702 forbids, which is
#: the kind of hole that looks like a policy detail and is a downgrade surface: the weakest key
#: wins, because an attacker picks which key the zone's RRSIGs can be checked against.
RSA_MIN_KEY_BITS_BY_ALGORITHM: dict[int, int] = {
    5: MIN_RSA_KEY_BITS,
    7: MIN_RSA_KEY_BITS,
    8: MIN_RSA_KEY_BITS,
    10: 1024,
}


def minimum_rsa_key_bits(algorithm: int) -> int:
    """The smallest modulus RFC 5702/RFC 3110 allow for one RSA algorithm number.

    Unknown numbers fall back to :data:`MIN_RSA_KEY_BITS`, the general floor: an unregistered
    algorithm is refused later by policy, and a floor invented here would be a guess about a
    primitive this package does not implement.
    """
    return RSA_MIN_KEY_BITS_BY_ALGORITHM.get(int(algorithm), MIN_RSA_KEY_BITS)


# ------------------------------------------------------------- ECC widths (RFC 6605 §4, RFC 8080 §3-§4)

#: The numbers whose DNSKEY Public Key field holds two fixed-width curve coordinates.
#: Derived from the table above rather than written out again, the same way
#: :data:`RSA_ALGORITHMS` is.
ECDSA_ALGORITHMS: frozenset[int] = frozenset(
    number
    for number, spec in SIGNATURE_ALGORITHMS.items()
    if spec.primitive in (SignatureAlgorithm.ECDSA_P256, SignatureAlgorithm.ECDSA_P384)
)

#: The numbers whose key and signature are single fixed-width bit strings.
EDDSA_ALGORITHMS: frozenset[int] = frozenset(
    number
    for number, spec in SIGNATURE_ALGORITHMS.items()
    if spec.primitive in (SignatureAlgorithm.ED25519, SignatureAlgorithm.ED448)
)

#: Octets per field element. RFC 6605 §4¶2: "For P-256, each integer MUST be encoded as
#: 32 octets; for P-384, each integer MUST be encoded as 48 octets." The same widths serve
#: both of §4's uses of a field element: x and y in the key (§4¶1), r and s in the
#: signature (§4¶2). EdDSA needs no entry here because its key and signature are single
#: values rather than concatenations of integers, and carry their own widths below.
ECDSA_FIELD_OCTETS: dict[int, int] = {13: 32, 14: 48}

#: The Public Key field, "x | y" (§4¶1), and the Signature field, "r | s" (§4¶2). The
#: widths coincide today -- both are two field elements -- and are still kept apart,
#: because they measure different things: a key is wide because of its curve, a signature
#: because of the same curve's order, and a document could rename one without the other.
EC_KEY_OCTETS: dict[int, int] = {alg: 2 * width for alg, width in ECDSA_FIELD_OCTETS.items()}
EC_SIGNATURE_OCTETS: dict[int, int] = {alg: 2 * width for alg, width in ECDSA_FIELD_OCTETS.items()}

#: RFC 8080 §3¶1-¶2: "An Ed25519 public key consists of a 32-octet value... An Ed448
#: public key consists of a 57-octet value", and §4¶1-¶2 the signatures at 64 and 114.
#: 57 and 114 are the ones that look wrong and are not: the curves are 456 and 912 bits,
#: which octet-pad at the high end, so a validator that assumed multiples of eight would
#: reject every Ed448 key on the wire.
EDDSA_KEY_OCTETS: dict[int, int] = {15: 32, 16: 57}
EDDSA_SIGNATURE_OCTETS: dict[int, int] = {15: 64, 16: 114}


def validation_requirement(algorithm: int) -> ValidationRequirement:
    """What RFC 9904 asks of a validator for one DNSKEY algorithm number."""
    return IMPLEMENT_FOR_VALIDATION.get(int(algorithm), ValidationRequirement.UNKNOWN)


_BACKEND: CryptoBackend | None = None
_PROBED = False


def backend() -> CryptoBackend | None:
    """The installed cryptographic backend, or None if there is none.

    Cached after the first call, and deliberately forgiving: an absent distribution is the
    ordinary case for a default install rather than an error, and callers that need the
    capability ask with :func:`require_backend`. A backend that is installed but broken also
    reports None -- an ``ImportError`` out of a half-built wheel is no more useful here than
    a missing one, and this is not the layer that diagnoses it.
    """
    global _BACKEND, _PROBED
    if not _PROBED:
        _PROBED = True
        try:
            module = __import__(CRYPTO_DISTRIBUTION, fromlist=["__version__"])
        except ImportError:
            module = None
        if module is None or getattr(module, "__file__", None) is None:
            # Either absent, or present as a namespace package: a directory with nothing in
            # it -- what a partial uninstall leaves -- imports successfully and has no
            # __file__. Reporting that as a backend would be worse than reporting none,
            # because the caller would reach into a module with no primitives and fail inside
            # verification instead of at this boundary, where MissingCryptoError is expected.
            _BACKEND = None
        else:
            _BACKEND = CryptoBackend(
                name=CRYPTO_DISTRIBUTION,
                version=str(getattr(module, "__version__", "unknown")),
                module=module,
            )
    return _BACKEND


def crypto_available() -> bool:
    """Whether this install can do signature arithmetic.

    A function and not a module-level constant, because a test, an embedded interpreter, or
    a lazily-populated ``sys.path`` can change the answer inside one process, and a value
    captured at import would then be a lie for the rest of the run.
    """
    return backend() is not None


def require_backend(purpose: str) -> CryptoBackend:
    """The backend, or a :class:`MissingCryptoError` that says what to install.

    *purpose* names the operation the caller wanted, because "no backend" is a line an
    operator reads in a log or a CLI error and has to be able to act on: what was refused,
    and what would have made it possible.
    """
    found = backend()
    if found is None:
        raise MissingCryptoError(
            f"cannot {purpose}: this install has no cryptographic backend. Install "
            f"namespy[{CRYPTO_EXTRA}] (which pulls in {CRYPTO_DISTRIBUTION}), or that "
            f"distribution directly, and retry."
        )
    return found


def backend_supports(algorithm: int) -> bool:
    """Whether the present backend can, in principle, verify this algorithm number.

    Answers from the registry table rather than by attempting an operation: the question is
    whether this install has the primitive at all, and a probe would need key and signature
    material that a caller holding an unsupported algorithm number does not have. With no
    backend the answer is uniformly False -- an absent library supports nothing, however
    well-regarded the algorithm.
    """
    if backend() is None:
        return False
    return int(algorithm) in SIGNATURE_ALGORITHMS


# ------------------------------------------------------------------- the arithmetic, dispatched once


class SignatureMaterialError(ValueError):
    """Key or signature bytes the backend cannot be handed at all.

    Deliberately distinct from a verification *failure*: this is the difference between
    "the arithmetic ran and refused these bytes" and "no arithmetic ran". A signature
    that fails is evidence about the records -- bogus, in RFC 4033's word. A key that
    cannot be constructed (RFC 3110 packing that does not parse, a point off the named
    curve, a modulus outside the window its algorithm is given) is evidence about the
    record, and reporting it as a failed signature would launder "we could not check"
    into "it is forged" -- the exact confusion RFC 9080 §3.1's Indeterminate exists to
    prevent upstream.
    """


def _primitives():
    """Import the backend's primitive modules lazily, through the probed distribution.

    Named by ``backend().module.__name__`` rather than by a literal import of
    ``cryptography``, which keeps this module's one-backend-boundary promise literally
    true: even the arithmetic reaches the library through the probe, and a swapped
    distribution would be found here and nowhere else.
    """
    found = require_backend("verify a DNSSEC signature")
    root = found.module.__name__
    part = importlib.import_module
    return (
        part(f"{root}.hazmat.primitives.hashes"),
        part(f"{root}.hazmat.primitives.asymmetric.padding"),
        part(f"{root}.hazmat.primitives.asymmetric.rsa"),
        part(f"{root}.hazmat.primitives.asymmetric.ec"),
        part(f"{root}.hazmat.primitives.asymmetric.ed25519"),
        part(f"{root}.hazmat.primitives.asymmetric.ed448"),
        part(f"{root}.exceptions").InvalidSignature,
    )


def verify_dnskey_signature(algorithm: int, key_material, signature, message: bytes) -> bool:
    """Ask the backend the one arithmetic question, whatever primitive the algorithm names.

    True when the signature verifies over *message* under *key_material*, False when the
    computation ran and refused it, :class:`SignatureMaterialError` when no computation
    could run. The key and signature are the raw RDATA fields -- the dispatch owns the
    layout (namespy.dnssec) and the sizes (this module's tables), because RFC 5702 §2.1¶2
    and §2.2¶2 write their modulus floors as MUST NOTs of the arithmetic itself: a
    512-bit RSA/SHA-512 key is not a preference a caller might weigh later, and this is
    where a key that small cannot be handed to a verification call.

    The RSA signature goes through :func:`namespy.dnssec.rsa_signature_octets` first --
    erratum 2811's padding -- because signers predating it emitted short signatures and a
    backend handed those reports failure as if the RRset were forged. The ECDSA signature
    must arrive in the wire's fixed-width r‖s form (RFC 6605 §4¶2); DER inside an RRSIG is
    a malformed record, refused as material rather than quietly parsed, which is the same
    stance the encoding leg took.
    """
    spec = SIGNATURE_ALGORITHMS.get(int(algorithm))
    if spec is None:
        raise SignatureMaterialError(
            f"algorithm {int(algorithm)} has no primitive in this package's registry"
        )
    material, message = bytes(key_material), bytes(message)
    try:
        if spec.primitive is SignatureAlgorithm.RSA:
            return _verify_rsa(int(algorithm), spec, material, signature, message)
        if spec.primitive in (SignatureAlgorithm.ECDSA_P256, SignatureAlgorithm.ECDSA_P384):
            return _verify_ecdsa(int(algorithm), spec, material, signature, message)
        return _verify_eddsa(int(algorithm), spec, material, signature, message)
    except (MalformedRsaKeyError, MalformedEcKeyError) as exc:
        raise SignatureMaterialError(str(exc)) from None


def _hash(hashes, name: str):
    """Instantiate the backend's hasher this algorithm's digest names ("sha256" -> SHA256())."""
    return getattr(hashes, name.upper())()


def _verify_rsa(algorithm: int, spec, material, signature, message) -> bool:
    key = unpack_rsa_public_key(material)
    floor = minimum_rsa_key_bits(algorithm)
    if key.key_bits < floor:
        raise SignatureMaterialError(
            f"RSA modulus is {key.key_bits} bits, under the {floor}-bit floor RFC 5702 "
            f"sets for algorithm {algorithm}"
        )
    if key.key_bits > MAX_RSA_KEY_BITS:
        raise SignatureMaterialError(
            f"RSA modulus is {key.key_bits} bits, over the {MAX_RSA_KEY_BITS}-bit ceiling "
            f"of RFC 3110 §2¶3"
        )
    hashes, padding, rsa, _ec, _ed1, _ed2, invalid_signature = (
        _primitives()
    )  # the exception class, named lowercase for the unpack
    padded = rsa_signature_octets(signature, key_bits=key.key_bits)
    try:
        public = rsa.RSAPublicNumbers(key.exponent, key.modulus).public_key()
    except ValueError as exc:  # the backend's own refusal of a nonsense modulus
        raise SignatureMaterialError(f"backend refused the RSA key material: {exc}") from None
    try:
        public.verify(padded, message, padding.PKCS1v15(), _hash(hashes, spec.digest))
    except invalid_signature:
        return False
    return True


def _verify_ecdsa(algorithm: int, spec, material, signature, message) -> bool:
    field_octets = ECDSA_FIELD_OCTETS[algorithm]
    point = unpack_ec_public_key(material, field_octets=field_octets)
    der = ecdsa_signature_from_rs(signature, field_octets=field_octets).to_der()
    hashes, _padding, _rsa, ec, _ed1, _ed2, invalid_signature = (
        _primitives()
    )  # the exception class, named lowercase for the unpack
    curve = ec.SECP256R1() if spec.primitive is SignatureAlgorithm.ECDSA_P256 else ec.SECP384R1()
    try:
        public = ec.EllipticCurvePublicNumbers(x=point.x, y=point.y, curve=curve).public_key()
    except ValueError as exc:
        raise SignatureMaterialError(
            f"backend refused the ECDSA key material (off the named curve?): {exc}"
        ) from None
    try:
        public.verify(der, message, ec.ECDSA(_hash(hashes, spec.digest)))
    except invalid_signature:
        return False
    return True


def _verify_eddsa(algorithm: int, spec, material, signature, message) -> bool:
    key = eddsa_public_key_octets(material, key_octets=EDDSA_KEY_OCTETS[algorithm])
    sig = eddsa_signature_octets(signature, signature_octets=EDDSA_SIGNATURE_OCTETS[algorithm])
    _hashes, _padding, _rsa, _ec, ed25519, ed448, invalid_signature = _primitives()
    if spec.primitive is SignatureAlgorithm.ED25519:
        public_class = ed25519.Ed25519PublicKey
    else:
        public_class = ed448.Ed448PublicKey
    try:
        public = public_class.from_public_bytes(key)
    except ValueError as exc:
        raise SignatureMaterialError(
            f"backend refused the EdDSA key material (not a curve point?): {exc}"
        ) from None
    try:
        public.verify(sig, message)
    except invalid_signature:
        return False
    return True
