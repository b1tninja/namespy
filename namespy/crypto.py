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

from dataclasses import dataclass
from enum import Enum
from types import ModuleType

__all__ = [
    "CRYPTO_DISTRIBUTION",
    "CRYPTO_EXTRA",
    "IMPLEMENT_FOR_VALIDATION",
    "MAX_RSA_KEY_BITS",
    "MIN_RSA_KEY_BITS",
    "SIGNATURE_ALGORITHMS",
    "CryptoBackend",
    "MissingCryptoError",
    "SignatureAlgorithm",
    "SignatureAlgorithmSpec",
    "ValidationRequirement",
    "backend",
    "backend_supports",
    "crypto_available",
    "require_backend",
    "validation_requirement",
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
#: What this table does *not* settle is the octet encoding of the key and signature fields:
#: RFC 6605 §4 gives ECDSA signatures as fixed-width r then s rather than DER, RFC 8080 §3
#: likewise for EdDSA, and RFC 3110 §2's exponent-then-modulus packing plus its leading-zero
#: rule has its own history. Those belong to the codec and verification leg, where they can
#: be written against vectors, and are listed as its homework rather than guessed at here.
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
