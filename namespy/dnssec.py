"""The DNSSEC records that need no cryptography: DNSKEY, DS, key tags, digests.

RFC 4034 defines four new records, and two of them are pure data structures. A
DNSKEY carries a public key that it never interprets; a DS carries a hash that it
never checks; the key tag that ties either to an RRSIG is a 16-bit checksum
(RFC 4034 Appendix B); and the digest a DS is made of is one :mod:`hashlib` call
over octets this module already holds. None of that needs a third-party
dependency, which is why these codecs ship now: they are the part of DNSSEC
compatible with this package's zero-dependency promise, and they are the substrate
the trust-anchor and signature-verification work of RFC 4035 will sit on -- RSA,
ECDSA and EdDSA arithmetic being a genuine dependency decision rather than an
oversight.

Deliberately absent: signature verification, NSEC/NSEC3 authenticated denial,
proof generation, and trust-anchor storage. ``NxdomainPolicy.VALIDATED``
(:mod:`namespy.resolver`) stays refused until the first of those exists.
"""

from __future__ import annotations

import base64
import binascii
import struct
from collections.abc import Iterable
from enum import IntEnum
from hashlib import sha1, sha256, sha384
from itertools import pairwise
from typing import NamedTuple

from .enums import DnsRType
from .names import DomainName

__all__ = [
    "CANONICAL_DOWNCASE_TYPES",
    "DNSKEY_FLAG_REVOKED",
    "DNSKEY_FLAG_SEP",
    "DNSKEY_FLAG_ZONE_KEY",
    "DNSKEY_HEAD_OCTETS",
    "DNSKEY_PROTOCOL_VALUE",
    "DNSSEC_SECURITY_TYPES",
    "NSEC3_ITERATION_LIMITS",
    "NSEC3_OPT_OUT_FLAG",
    "RSA_MD5_ALGORITHM",
    "TYPE_WINDOW_OCTETS",
    "CanonicalizationError",
    "DigestType",
    "DuplicateRecordError",
    "MalformedRsaKeyError",
    "Nsec3HashAlgorithm",
    "RsaPublicKey",
    "canonical_owner_octets",
    "canonical_rdata_octets",
    "canonical_rr_bytes",
    "canonical_rrset_bytes",
    "canonical_rrset_rdatas",
    "decode_base32hex",
    "decode_base64_field",
    "decode_hex_field",
    "decode_type_bitmap",
    "digest_material",
    "ds_digest",
    "encode_base32hex",
    "encode_base64_field",
    "encode_hex_field",
    "encode_type_bitmap",
    "iterations_within_limit",
    "key_material",
    "key_tag",
    "known_digest_octets",
    "nsec3_hash",
    "pack_rsa_public_key",
    "rrsig_label_count",
    "rrsig_signed_data",
    "rsa_signature_octets",
    "signed_owner_name",
    "unpack_rsa_public_key",
    "unsigned_field",
]

#: RFC 4034 §2.1.2: "The Protocol Field MUST have value 3, and the DNSKEY RR MUST be
#: treated as invalid during signature verification if it is found to be some value
#: other than 3." Invalid at verification, not unparseable: a resolver that dropped
#: the record on receipt could not report why a zone failed to authenticate.
DNSKEY_PROTOCOL_VALUE = 3

#: RFC 4034 §2.1.1: "Bit 7 of the Flags field is the Zone Key flag." Bits are
#: numbered from the most significant end, so bit 7 is 0x0100 -- which is why the
#: common flags value 256 means "zone key" and 257 means "zone key plus SEP".
DNSKEY_FLAG_ZONE_KEY = 0x0100

#: RFC 4034 §2.1.1: "Bit 15 of the Flags field is the Secure Entry Point flag", a
#: hint only: "validators MUST NOT alter their behavior during the signature
#: validation process in any way based on the setting of this bit".
DNSKEY_FLAG_SEP = 0x0001

#: RFC 5011 §3: "Bit 8 of the DNSKEY Flags field is designated as the 'REVOKE'
#: flag." RFC 5011 §2.1 makes it decisive once seen on a self-signed RRset, and
#: warns that "A DNSKEY with the REVOKE bit set has a different fingerprint" -- so
#: this bit is part of what a DS hashes, not metadata beside it.
DNSKEY_FLAG_REVOKED = 0x0080

#: RFC 4034 Appendix B.1: the one algorithm whose key tag is not the checksum.
RSA_MD5_ALGORITHM = 1

#: Flags (2) + Protocol (1) + Algorithm (1), ahead of the public key.
DNSKEY_HEAD_OCTETS = 4


def key_tag(dnskey_rdata: bytes) -> int:
    """The DNSSEC key tag of a DNSKEY RR, computed from its RDATA (RFC 4034 App. B).

    The input is the whole RDATA -- flags, protocol, algorithm, public key --
    because that is what §Appendix B specifies ("The input is the wire format of
    the RDATA portion of the DNSKEY RR"), and because it lets the algorithm be read
    from octet 3 instead of trusted from an argument: §B.1 gives algorithm 1
    (RSA/MD5) an entirely different rule, and a tag computed with the wrong rule
    points at a key that is not the signer's.

    Two verified errata shape the result, and both change numbers:

    * **4552** corrects §B's prose "added together, ignoring any carry bits". The
      accumulation keeps its carries at 32-bit precision, the high bits are folded
      in once, and only a carry produced *by that addition* is discarded -- which is
      what the reference C code does, and why it is transcribed rather than
      paraphrased. The erratum adds that the value is "often the same as reduction
      modulo 65535, but not always", so the tempting shortcut is not used.
    * **193** corrects §B.1's parenthetical to "the 3rd to last and 2nd to last
      octets", the reading the normative phrase always implied: "the most
      significant 16 bits of the least significant 24 bits".

    §Appendix B¶2 bounds what any caller may conclude: "Implementations MUST NOT
    assume that the key tag uniquely identifies a DNSKEY RR." It narrows the
    candidate set; it is never an identity.
    """
    data = bytes(dnskey_rdata)
    if len(data) <= DNSKEY_HEAD_OCTETS:
        raise ValueError(f"key tag needs DNSKEY RDATA with a public key, got {len(data)} octet(s)")
    algorithm = data[3]
    public_key = data[DNSKEY_HEAD_OCTETS:]

    if algorithm == RSA_MD5_ALGORITHM:
        # §B.1, as corrected by erratum 193: the top 16 bits of the bottom 24.
        if len(public_key) < 3:
            raise ValueError(
                f"RSA/MD5 key tag needs at least 3 octets of modulus, got {len(public_key)}"
            )
        return (public_key[-3] << 8) | public_key[-2]

    # Appendix B's reference implementation, transcribed: big-endian pairs of
    # octets into a 32-bit accumulator, one fold of the carries, low 16 bits out.
    # An odd final octet arrives as the high byte of its pair, exactly as the C
    # loop's ``key[i] << 8`` on an even index does.
    total = 0
    for index, octet in enumerate(data):
        total += octet if index & 1 else octet << 8
    total += (total >> 16) & 0xFFFF
    return total & 0xFFFF


class DigestType(IntEnum):
    """The DS digest algorithms this package can compute.

    RFC 4034 Appendix A.2 had one row -- "1 SHA-1 MANDATORY" -- and the registry has
    grown since: RFC 4509 §2 assigns SHA-256 the number 2, and RFC 6605 §2 assigns
    SHA-384 the number 4 ("the digest value is 48 bytes long, and the digest type
    code is 4"). All three are a plain hash of the RFC 4034 §5.1.4 input, so
    :mod:`hashlib` covers them and no dependency is needed to produce or check one.

    Anything past these is refused *by name* rather than approximated. A digest
    computed with the wrong construction is not a visibly broken record: it is a
    delegation that stops authenticating quietly, at the child, far from wherever
    the mistake was made. Note the asymmetry this leaves intact -- a DS whose digest
    type is unknown still parses, round-trips and prints, because reading a
    delegation somebody else made is not the same job as minting one.
    """

    SHA1 = 1
    SHA256 = 2
    SHA384 = 4

    @property
    def hasher(self):
        """The :mod:`hashlib` constructor this digest type means."""
        try:
            return _HASHERS[int(self)]
        except KeyError:
            known = ", ".join(str(int(member)) for member in DigestType)
            raise ValueError(
                f"DS digest type {int(self)} is not implemented; known types are {known}"
            ) from None

    @property
    def digest_octets(self) -> int:
        """The digest length this type always produces -- what a DS must carry."""
        return self.hasher().digest_size


_HASHERS = {1: sha1, 2: sha256, 4: sha384}


def known_digest_octets(digest_type: int) -> int | None:
    """The digest length a DS of ``digest_type`` must carry, or ``None`` if unknown.

    ``None`` means "this package has no hasher for that number", which is a different
    statement from "no such digest type exists" -- and it is why an unknown type is
    exempt from the length check on the way in: the registry grows, and a resolver
    that refuses to parse a delegation because it has not heard of the algorithm has
    turned its own ignorance into SERVFAIL for someone else's zone.
    """
    try:
        return DigestType(int(digest_type)).digest_octets
    except ValueError:
        return None


def canonical_owner_octets(name) -> bytes:
    """The canonical *owner name* of RFC 4034 §6.2, as wire octets.

    Two records hash this and nothing else -- a DS over the owner name plus a DNSKEY
    (RFC 4034 §5.1.4) and an NSEC3 hash over the owner name plus salt (RFC 5155 §5, whose
    ¶12 says the form "is as defined in Section 6.2 of [RFC4034]") -- so both call this
    rather than each growing a downcasing routine.

    Three of §6.2's five items bear on an owner name:

    * item 1 (¶2), every name "fully expanded (no DNS name compression) and fully
      qualified" -- enforced below;
    * item 2 (¶3), "all uppercase US-ASCII letters in the owner name ... replaced by the
      corresponding lowercase US-ASCII letters";
    * item 4 (¶5), a wildcard owner name stays "in its original unexpanded form, including
      the ``*`` label", which is why RFC 5155's Appendix A lists a hash of ``*.w.example``
      separate from the names expanded from it. Substituting the matched label here would
      produce a hash that exists in no zone.

    Items 3 and 5 are about RDATA and TTL and so cannot apply to a name on its own. Item 3 does
    matter when whole RRs are canonicalised, and **verified errata 1062 and 1063** are two halves
    of one correction: each names the incompleteness of the other document's list, RFC 4034 §6.2
    omitting types RFC 3597 §7¶4 has and RFC 3597 §7¶4 omitting the RRSIG and NSEC that RFC 4034
    adds. The reconciled set is :data:`CANONICAL_DOWNCASE_TYPES`, and it is not simply "every type
    with a name in it" -- RFC 3597 §7¶5 says types defined after it do not downcase at all, which
    is why NSEC3 (no embedded name in the first place) and SVCB (a real one) are both absent.

    Lowercasing the assembled octets is exactly item 2 and nothing more: the only bytes that
    can land in A-Z are label contents, since a length octet is at most 63 and a fully
    expanded name carries no pointer.

    :meth:`namespy.names.DomainName.canonical_text` is deliberately not used: it folds to
    *upper* case, which is right for a map key and backwards for a digest.
    """
    parsed = DomainName(name)
    if not parsed.is_absolute:
        raise ValueError(
            f"canonical owner name must be fully qualified (RFC 4034 §6.2 item 1), got {parsed}"
        )
    return bytes(parsed).lower()


def ds_digest(owner, dnskey_rdata: bytes, digest_type: DigestType | int) -> bytes:
    """The digest a DS record carries for a DNSKEY RR (RFC 4034 §5.1.4).

    §5.1.4¶3::

        digest = digest_algorithm( DNSKEY owner name | DNSKEY RDATA );

    where "DNSKEY RDATA = Flags | Protocol | Algorithm | Public Key" (§5.1.4¶5). The
    two parts are simply concatenated: the owner name carries no length prefix and no
    padding, ends in its root terminator, and is followed immediately by the RDATA.
    Every one of those details changes the answer, which is why the input is
    assembled here once rather than at each call site.

    The owner name is canonicalised by :func:`canonical_owner_octets`; the RDATA is
    used as it arrives. Note that the flags are inside the hash, so RFC 5011's
    REVOKE bit -- which §2.1 warns gives "a different fingerprint" -- is expected to
    change a DS rather than leave it standing.
    """
    digest_type = int(digest_type)
    try:
        kind = DigestType(digest_type)
    except ValueError:
        # Not "invalid": the registry has numbers this package has no hasher for, and
        # a caller reading "not a valid digest type" would go looking for a typo in
        # their zone file instead of the missing implementation here.
        supported = ", ".join(f"{int(member)} ({member.name})" for member in DigestType)
        raise ValueError(
            f"DS digest type {digest_type} is not implemented here; this package "
            f"computes {supported}"
        ) from None
    hasher = kind.hasher()
    hasher.update(canonical_owner_octets(owner))
    hasher.update(bytes(dnskey_rdata))
    return hasher.digest()


def decode_base64_field(text: str, *, what: str) -> bytes:
    """Read a master-file Base64 field, which may be wrapped across lines.

    RFC 4034 §2.3 and §5.4 both print a public key over several lines, so embedded
    whitespace has to be tolerated. ``validate`` is on deliberately: the default
    decoder silently *discards* characters outside the alphabet, which would turn a
    mistyped key into a valid-looking key belonging to a different key pair -- the
    kind of error that surfaces as a signature that will not verify, elsewhere,
    later.
    """
    compact = "".join(text.split())
    try:
        return base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{what} is not valid Base64: {exc}") from None


def encode_base64_field(octets: bytes) -> str:
    """Render a public key or signature as one Base64 token (RFC 4034 §2.2)."""
    return base64.b64encode(bytes(octets)).decode("ascii")


def key_material(value, *, what: str = "public key") -> bytes:
    """DNSSEC key material, from octets or from the Base64 text a master file uses.

    Both are ordinary inputs. A parser hands over octets; a zone file, RFC 4034
    §2.3's example, and every key-generation tool speak Base64, which is what §2.2
    specifies for the field. Text is decoded, anything buffer-like is taken as it
    arrives. The form is decided by which field this is called for, so there is no
    guesswork between Base64 and hex the way a single "parse this text" entry point
    would have it.
    """
    if isinstance(value, str):
        return decode_base64_field(value, what=what)
    return bytes(value)


def digest_material(value, *, what: str = "digest") -> bytes:
    """A DS digest, from octets or from the hexadecimal text §5.3 specifies.

    §5.3: "The Digest MUST be represented as a sequence of case-insensitive
    hexadecimal digits. Whitespace is allowed within the hexadecimal text." Which is
    how §5.4 prints one, and a caller who has only ever met DS records in a zone file
    has that, not octets.
    """
    if isinstance(value, str):
        return decode_hex_field(value, what=what)
    return bytes(value)


def encode_hex_field(octets: bytes) -> str:
    """A DS digest in master-file form: uppercase hex, unbroken (RFC 4034 §5.3).

    §5.3 permits "a sequence of case-insensitive hexadecimal digits" with
    "whitespace ... allowed within the hexadecimal text", so one run is legal, and
    its case matches §5.4's example.
    """
    return bytes(octets).hex().upper()


def decode_hex_field(text: str, *, what: str) -> bytes:
    """Read a hexadecimal field that may be broken across lines (§5.3 again)."""
    compact = "".join(text.split())
    try:
        return bytes.fromhex(compact)
    except ValueError as exc:
        raise ValueError(f"{what} is not hexadecimal: {exc}") from None


def unsigned_field(value: int, *, bits: int, name: str) -> int:
    """Coerce to an unsigned field of ``bits`` width, refusing to wrap quietly.

    An ``& 0xFFFF`` here would be generous in the wrong direction: a caller that
    passed a 24-bit key tag has a bug, and the record it produces carries a tag no
    RRSIG will ever name. Shared by the DNSSEC codecs in :mod:`namespy.rdata`.
    """
    number = int(value)
    limit = (1 << bits) - 1
    if not 0 <= number <= limit:
        raise ValueError(f"{name} must be 0..{limit} ({bits} bits), got {number}")
    return number


# ------------------------------------------------------- type bit maps
#
# RFC 4034 §4.1.2 defines the encoding and RFC 5155 §3.1.8 reuses it for NSEC3, so one
# pair of functions serves both records. Getting it wrong is not cosmetic: the bitmap is
# what a validator reads as "this name has no other types", and a bitmap that decodes
# too generously turns a NODATA proof into a false negative answer.


#: RFC 4034 §4.1.2: "The RR type space is split into 256 window blocks, each
#: representing the low-order 8 bits of the 16-bit RR type space."
TYPE_WINDOW_OCTETS = 32


def encode_type_bitmap(types: Iterable[int]) -> bytes:
    """The Type Bit Maps field for a set of RR types (RFC 4034 §4.1.2).

    Three rules are load-bearing and each gets its own test: blocks are "present in the
    NSEC RR RDATA in increasing numerical order" (¶3); "blocks with no types present
    MUST NOT be included" and "trailing zero octets in the bitmap MUST be omitted", the
    latter fixing each block's length at that of its largest type (¶8). Skip the
    trailing-zero rule and the bitmap still parses -- but no other implementation would
    have produced those bytes, so a byte-for-byte comparison against a signed zone fails
    somewhere else in the world.

    Bit numbering follows ¶6: the bit for type N inside its window is ``N % 256``, held
    in network bit order, so A (1) is the second-most-significant bit of the first octet
    and A+NS come out as ``0x60``.
    """
    windows: dict[int, int] = {}
    for value in types:
        rtype = unsigned_field(value, bits=16, name="RR type")
        window, bit = divmod(rtype, 256)
        windows[window] = windows.get(window, 0) | (1 << (255 - bit))

    out = bytearray()
    for window in sorted(windows):
        bitmap = windows[window].to_bytes(TYPE_WINDOW_OCTETS, "big").rstrip(b"\x00")
        if not bitmap:
            # Unreachable by construction: a window exists only because some type set a
            # bit in it, and the largest set bit always survives the rstrip. Guarded
            # because a window header with a zero length would be a malformed record.
            continue
        out += bytes([window, len(bitmap)]) + bitmap
    return bytes(out)


def decode_type_bitmap(blob: bytes) -> tuple[int, ...]:
    """The RR types a Type Bit Maps field lists, ascending (RFC 4034 §4.1.2).

    Malformed blocks raise rather than being skipped: reading a truncated bitmap as
    "fewer types exist here" produces exactly the false denial this record exists to
    prevent, and it is the kind of error that must not be survivable.

    §4.1.2¶7 asks that pseudo-type bits be clear and, if encountered, "ignored upon
    being read". This returns what the record says, unchanged: knowing which numbers are
    pseudo-types needs the IANA registry rather than this document, and dropping one here
    would hide from a validator the anomaly it should be reporting. The rule belongs with
    the existence check that will read this, and is recorded as such on the roadmap.
    """
    data = bytes(blob)
    found: list[int] = []
    cursor = 0
    previous_window = -1
    while cursor < len(data):
        if len(data) - cursor < 2:
            raise ValueError(f"type bitmap ends mid-header at octet {cursor}")
        window, length = data[cursor], data[cursor + 1]
        if length < 1 or length > TYPE_WINDOW_OCTETS:
            raise ValueError(
                f"type bitmap window {window} claims {length} octet(s), must be "
                f"1..{TYPE_WINDOW_OCTETS} (§4.1.2¶2)"
            )
        if window <= previous_window:
            raise ValueError(
                f"type bitmap windows are not in increasing numerical order "
                f"({previous_window} then {window}, §4.1.2¶3)"
            )
        bits = data[cursor + 2 : cursor + 2 + length]
        if len(bits) < length:
            raise ValueError(f"type bitmap window {window} is truncated")
        if bits[-1] == 0:
            raise ValueError(f"type bitmap window {window} keeps a trailing zero octet (§4.1.2¶8)")
        for index, octet in enumerate(bits):
            for bit in range(8):
                if octet & (1 << (7 - bit)):
                    found.append(window * 256 + index * 8 + bit)
        previous_window = window
        cursor += 2 + length
    return tuple(found)


# ------------------------------------------------------------- NSEC3
#
# RFC 5155. Two things here are easy to get wrong and both fail quietly: the base32
# alphabet, and the iteration recursion.

#: RFC 5155 §3.1.2.1: the Opt-Out flag, "the least significant bit in the Flags field".
NSEC3_OPT_OUT_FLAG = 0x01


class Nsec3HashAlgorithm(IntEnum):
    """The NSEC3 hash algorithm registry (RFC 5155 §11), as far as this package runs.

    §11 defines SHA-1 and nothing else, and it is what every signed zone in operation
    uses. An unknown number in a record still parses -- see
    :class:`namespy.rdata.RData_NSEC3` -- but no hash can be computed with it, the same
    read/write asymmetry as :class:`DigestType`.
    """

    SHA1 = 1

    @property
    def hasher(self):
        """The :mod:`hashlib` constructor this algorithm number means."""
        return _NSEC3_HASHERS[int(self)]


_NSEC3_HASHERS = {1: sha1}

#: RFC 4648 §6 and §7 alphabets. Python's ``b32encode`` emits the first; DNSSEC's hashed
#: owner names use the second.
_B32_STD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_B32_HEX_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
_B32_TO_HEX = str.maketrans(_B32_STD_ALPHABET, _B32_HEX_ALPHABET)
_B32_FROM_HEX = str.maketrans(_B32_HEX_ALPHABET, _B32_STD_ALPHABET)


def encode_base32hex(octets: bytes) -> str:
    """Base32hex, unpadded (RFC 4648 §7) -- the alphabet DNSSEC actually uses.

    **Verified erratum 3544** is what makes this a function rather than ``b32encode``:
    RFC 5155 §3.3 printed "base32" where RFC 4648 §7 warns the encoding "should not be
    regarded as the same as the 'base32' encoding". The alphabets disagree on every digit
    and the first ten letters, so a hash written with the wrong one decodes to different
    octets -- every hashed owner label in the record would be wrong, and it would look
    like a zone with no NSEC3 chain rather than an encoding bug.

    Padding is dropped, as §3.3 requires ("unpadded ... without whitespace"). Case is
    upper, which §3.3 leaves free by calling the digits case-insensitive.
    """
    padded = base64.b32encode(bytes(octets)).decode("ascii")
    return padded.rstrip("=").translate(_B32_TO_HEX)


def decode_base32hex(text: str, *, what: str = "hashed owner name") -> bytes:
    """Read a base32hex label: case-insensitive and unpadded per §3.3, padding tolerated.

    Tolerating ``=`` is a deliberate asymmetry. Producing follows the specification;
    consuming meets hand-edited zone files and tools that pad, and refusing those would
    cost a resolver an answer its predecessor took without complaint.
    """
    compact = "".join(text.split()).upper().translate(_B32_FROM_HEX)
    if not compact:
        raise ValueError(f"{what} is empty")
    compact += "=" * ((8 - len(compact) % 8) % 8)
    try:
        return base64.b32decode(compact)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{what} is not base32hex: {exc}") from None


def nsec3_hash(owner, *, iterations: int, salt=b"", hash_algorithm=1) -> bytes:
    """The NSEC3 hash of an owner name (RFC 5155 §5).

    §5 defines it recursively::

        IH(salt, x, 0) = H(x || salt)
        IH(salt, x, k) = H(IH(salt, x, k-1) || salt)    for k > 0

    so *iterations* counts **additional** hashes: the name is hashed once whatever the
    field says, and k more follow, each re-appending the salt. Read §3.1.3's "number of
    additional times" as a total and every non-zero k comes out one SHA-1 short -- a hash
    that matches nothing in the zone, with no error anywhere, just a denial that can never
    be proved. Appendix A says of its own hashes that they "can also be used as test
    vectors for the hash algorithm" at iterations 12 and salt ``aabbccdd``, which is what
    pins that off-by-one to the document's numbers rather than to this implementation.

    The input is §5¶8-¶12's canonical owner name: fully expanded, fully qualified,
    downcased, and -- item 3 -- a wildcard left in its original unexpanded form with the
    ``*`` label intact. That clause is why Appendix A gives ``*.w.example`` a hash of its
    own instead of sharing the one for the names expanded from it.
    """
    if isinstance(salt, str):
        salt = decode_hex_field(salt, what="NSEC3 salt")
    salt = bytes(salt)
    iterations = unsigned_field(iterations, bits=16, name="NSEC3 iterations")
    hasher = _NSEC3_HASHERS.get(int(hash_algorithm))
    if hasher is None:
        known = ", ".join(str(int(member)) for member in Nsec3HashAlgorithm)
        raise ValueError(
            f"NSEC3 hash algorithm {int(hash_algorithm)} is not implemented here; this "
            f"package computes {known}"
        )

    value = hasher(canonical_owner_octets(owner) + salt).digest()
    for _ in range(iterations):
        value = hasher(value + salt).digest()
    return value


#: RFC 5155 §10.3¶4's table: zone key size in bits against the maximum iterations.
NSEC3_ITERATION_LIMITS: tuple[tuple[int, int], ...] = ((1024, 150), (2048, 500), (4096, 2500))


def iterations_within_limit(iterations: int, *, key_bits: int) -> bool:
    """Whether an NSEC3 iteration count is inside RFC 5155 §10.3's ceiling.

    The table is keyed on the signing key's size, "rounded up to the nearest table value
    (or rounded down if the key is larger than the largest table value)" (§10.3¶3), so a
    3072-bit key is held to 500 and an 8192-bit one to 2500. §10.3¶7 adds that the values
    apply "independent of the key algorithm", however tempting it is to relax them for
    ECDSA on the grounds that SHA-1 is cheap next to an ECDSA verification.

    The prohibition falls on the zone owner ("A zone owner MUST NOT use a value higher
    than shown"), and §10.3¶4 lets a resolver treat an exceeding value as insecure *after*
    verifying the signature over the NSEC3 RR -- hence a predicate rather than a
    parse-time refusal, and hence the verification half being out of scope here.
    """
    ceiling = NSEC3_ITERATION_LIMITS[-1][1]
    for bits, limit in NSEC3_ITERATION_LIMITS:
        if int(key_bits) <= bits:
            ceiling = limit
            break
    return int(iterations) <= ceiling


# ------------------------------------------- canonical form (RFC 4034 §6, §3.1.8.1)
#
# This is what a signature actually covers, so the two rules that look cosmetic are not:
# which types get their embedded names downcased, and how RDATA sorts.


class CanonicalizationError(ValueError):
    """A record whose canonical form this package cannot compute.

    Raised rather than answered with the raw octets. Guessing here means hashing bytes the
    signer did not hash, and the only symptom would be a valid signature that fails --
    indistinguishable from an attack, which is the worst possible confusion to introduce into
    a validator. The remedy is a codec for the type, and the message says so.
    """


class DuplicateRecordError(ValueError):
    """An RRset holding two RRs with identical RDATA (RFC 4034 §6.3¶2, RFC 2181 §4.1.3).

    §6.3¶2 makes this "a protocol error" that an implementation "MUST treat as such", and only
    permits leniency on the condition that all but one copy be dropped for the canonical form.
    Both halves are honoured here: raise by default, deduplicate on request. Silently sorting
    two identical members would produce a signed string with an extra RR in it, which is a
    false negative on somebody else's correctly signed zone.
    """


#: RFC 4034 §6.2 item 3: the types whose canonical form downcases the domain names *inside*
#: their RDATA. Two verified errata shape this list, and they point at each other -- **1062**
#: against RFC 4034 §6.2 and **1063** against RFC 3597 §7, each noting that the other
#: document's set is incomplete. Read together, RFC 4034's is the superset: RFC 3597 §7¶4's
#: pre-2003 types plus RRSIG and NSEC, which RFC 4034 §6.2 item 3 adds by name.
#:
#: What the pair does *not* license is growing the list. RFC 3597 §7¶5 says that for types
#: defined after it, "the canonical form is such that no downcasing of embedded domain names
#: takes place" -- so SVCB and HTTPS (RFC 9460, 2023) keep the case of their target-name even
#: though it is a domain name and RFC 9460 says nothing about canonical form, and NSEC3 has no
#: name to downcase at all since its hashed owner name is opaque octets. Adding a type here on
#: the theory that it "has a name in it" changes the bytes a signature covers.
#:
#: HINFO appears in both lists and has no domain name; item 3 speaks only of "the DNS names
#: contained within the RDATA", so its presence changes nothing. That is worth stating because
#: an implementation that downcased HINFO's CPU and OS strings in the spirit of the list would
#: corrupt the record it was trying to canonicalise.
#: Built from the registry rather than from typed-out numbers, so the list reads against the
#: RFC's sentence and cannot gain a digit by accident. A6 here is 38, the number the IANA
#: registry carries; RFC 2874 assigned 3847 first, which is why sources disagree.
#: The RR types that exist only to authenticate other records.
#:
#: RFC 4035 §3.1 introduces three of them ("a security-aware authoritative name server for a signed
#: zone MUST include additional RRSIG, NSEC, and DS RRs" is §3.1¶1 telling the server where they go)
#: and RFC 5155 adds NSEC3 and NSEC3PARAM, which its §11 registers in IANA's "DNS SECURITY RR Type"
#: registry alongside the first three. This is the set RFC 4035 §3.2.1 makes conditional on the
#: client: if the initiating query's DO bit is clear, "the name server side MUST strip any
#: authenticating DNSSEC RRs from the response but MUST NOT strip any DNSSEC RR types that the
#: initiating query explicitly requested".
#:
#: DS is deliberately *not* here, though §3.1¶1 lists it among what a signed zone adds to a
#: DO=1 response. A DS is data a client asks for by name, and withdrawing one from a referral would
#: break the walk rather than hide anything: the strip exists to spare non-DNSSEC clients records it
#: cannot parse (RFC 3225 §2¶3 reports such resolvers failing outright), not to withhold a resource
#: record. DNSKEY is included even though it only ever appears when queried directly, because the
#: query-matches-type exception below is what protects it in that case.
DNSSEC_SECURITY_TYPES: frozenset[int] = frozenset(
    {
        int(DnsRType.RRSIG),
        int(DnsRType.DNSKEY),
        int(DnsRType.NSEC),
        int(DnsRType.NSEC3),
        int(DnsRType.NSEC3PARAM),
    }
)

CANONICAL_DOWNCASE_TYPES: frozenset[int] = frozenset(
    int(DnsRType[name])
    for name in (
        "NS",
        "MD",
        "MF",
        "CNAME",
        "SOA",
        "MB",
        "MG",
        "MR",
        "PTR",
        "HINFO",
        "MINFO",
        "MX",
        "RP",
        "AFSDB",
        "RT",
        "SIG",
        "PX",
        "NXT",
        "NAPTR",
        "KX",
        "SRV",
        "DNAME",
        "A6",
        "RRSIG",
        "NSEC",
    )
)


def canonical_rdata_octets(rtype: int, rdata) -> bytes:
    """RDATA in canonical form (§6.2 items 1 and 3, RFC 3597 §7).

    Two transformations, and only one is conditional. Expansion always applies: the codecs here
    re-encode names from parsed state instead of copying received octets, so a name that arrived
    through a compression pointer leaves this function fully expanded, which is what §6.2 item 1
    requires. Downcasing the names *inside* RDATA applies only to the types in
    CANONICAL_DOWNCASE_TYPES, per RFC 3597 §7¶5.

    A listed type with no codec here raises rather than returning raw octets: without knowing
    where the names sit, a byte-level downcase would corrupt the record (item 3 speaks of "the
    DNS names contained within the RDATA", not of the RDATA), and something that merely looks
    canonical is how a valid signature starts failing.
    """
    blob = bytes(rdata)
    number = int(rtype)
    if number not in CANONICAL_DOWNCASE_TYPES:
        return blob
    from .rdata import rdata_class_for  # deferred: namespy.rdata imports this module

    codec = rdata_class_for(number)
    if codec is None:
        raise CanonicalizationError(
            f"RR type {number} has embedded domain names that canonicalisation must downcase "
            f"(RFC 4034 §6.2 item 3) but no codec here to say where they are; add a codec "
            f"rather than hashing the raw octets"
        )
    return codec.parse_from(blob).canonical_wire()


def canonical_rr_bytes(owner, rtype: int, rclass: int, ttl: int, rdata) -> bytes:
    """One RR as a signature covers it: owner | type | class | TTL | RDLENGTH | RDATA.

    That is §3.1.8.1¶5 verbatim, including the detail easy to miss: every RR repeats the owner
    name, type and class rather than the RRset stating them once. Omitting that costs ten octets
    per record and fails every signature.
    """
    canonical = canonical_rdata_octets(rtype, rdata)
    return (
        canonical_owner_octets(owner)
        + struct.pack("!HHIH", int(rtype), int(rclass), int(ttl) & 0xFFFFFFFF, len(canonical))
        + canonical
    )


def canonical_rrset_rdatas(
    rtype: int, rdatas: Iterable, *, tolerate_duplicates: bool = False
) -> tuple[bytes, ...]:
    """The canonical RDATA of an RRset, in canonical order (RFC 4034 §6.3¶1-¶2).

    §6.3¶1's order is "a left-justified unsigned octet sequence in which the absence of an octet
    sorts before a zero octet" -- which is how Python compares bytes, so this sorts rather than
    inventing a comparator. What that sentence rules out is a length-prefixed or numeric
    comparison, either of which yields a different order and therefore a different signature.

    Identical RDATA twice is DuplicateRecordError by default; its docstring gives the two readings
    §6.3¶2 permits.
    """
    canonical = sorted(canonical_rdata_octets(rtype, rdata) for rdata in rdatas)
    duplicates = {a for a, b in pairwise(canonical) if a == b}
    if duplicates:
        if not tolerate_duplicates:
            raise DuplicateRecordError(
                f"RRset of type {int(rtype)} holds {len(duplicates)} duplicated RDATA value(s); "
                f"RFC 4034 §6.3¶2 makes this a protocol error"
            )
        unique: list[bytes] = []
        for value in canonical:
            if not unique or unique[-1] != value:
                unique.append(value)
        canonical = unique
    return tuple(canonical)


def canonical_rrset_bytes(
    owner,
    rtype: int,
    rclass: int,
    original_ttl: int,
    rdatas: Iterable,
    *,
    tolerate_duplicates: bool = False,
) -> bytes:
    """Every RR of a set, canonical and canonically ordered, concatenated (§3.1.8.1, §6.3).

    The TTL is the caller's to supply and should be the RRSIG's Original TTL rather than whatever
    the records arrived carrying: §3.1.8.1¶10 says each RR "MUST have the TTL listed in the RRSIG
    Original TTL Field", which is also why a cached RRset whose TTL has decayed still verifies.
    """
    head = canonical_owner_octets(owner) + struct.pack(
        "!HHI", int(rtype), int(rclass), int(original_ttl) & 0xFFFFFFFF
    )
    out = bytearray()
    for canonical in canonical_rrset_rdatas(rtype, rdatas, tolerate_duplicates=tolerate_duplicates):
        out += head + struct.pack("!H", len(canonical)) + canonical
    return bytes(out)


def rrsig_label_count(owner) -> int:
    """The Labels value a signer would write for this owner name (§3.1.3¶3).

    Neither the root label nor a wildcard counts. The section gives its own examples --
    "www.example.com." is 3, "*.example.com." is 2, root is 0 -- and all three are in the test,
    because a count off by one looks exactly like a wrong wildcard decision.
    """
    labels = [label for label in DomainName(owner).labels() if label]
    if labels and labels[0] == b"*":
        return len(labels) - 1
    return len(labels)


def signed_owner_name(owner, labels: int):
    """The owner name the signature covers, and whether it came from a wildcard (§3.1.3).

    An answer synthesised from ``*.example.com.`` reaches the client with the expanded owner name,
    so a validator has to undo the expansion before it can rebuild the signed bytes; Labels is
    what says whether that happened. Where the count is lower than the owner has labels, the
    difference is the run of labels the wildcard stood for, and replacing that run with one ``*``
    recovers the signed name: "www.example.com." with Labels 2 becomes ``*.example.com.``, and so
    does "a.b.example.com.".

    §3.1.3¶3 requires Labels be "less than or equal to the number of labels in the RRSIG owner
    name", so a larger value is refused rather than clamped -- it cannot mean anything, and
    clamping would validate a signature against a name nobody signed.

    Per §3.1.3¶4 the wildcard label is part of the owner name when the signature is computed, so
    the reconstructed name is used whole: the ``*`` is hashed, not stripped.
    """
    parsed = DomainName(owner)
    present = [label for label in parsed.labels() if label]
    already_wildcard = bool(present) and present[0] == b"*"
    counted = rrsig_label_count(parsed)
    want = int(labels)
    if want > counted:
        raise ValueError(
            f"RRSIG Labels {want} exceeds the {counted} label(s) of owner name {parsed} "
            f"(RFC 4034 §3.1.3¶3)"
        )
    if want == counted:
        return parsed, already_wildcard
    tail = present[1:] if already_wildcard else present
    kept = tail[len(tail) - want :] if want else []
    text = "*." + ".".join(label.decode("latin-1") for label in kept)
    return DomainName(text if not kept else f"{text}."), True


def rrsig_signed_data(rrsig, owner, rdatas, *, rclass: int = 1) -> bytes:
    """The exact octets an RRSIG's signature covers (§3.1.8.1).

    ``RRSIG_RDATA | RR(1) | RR(2) | ...``, with RRSIG_RDATA the record's own fields, Signature
    excluded and the Signer's Name canonical (§3.1.8.1¶4) -- downcased, because RRSIG is one of
    the types item 3 lists. The owner name goes through :func:`signed_owner_name`, so a
    wildcard-expanded RRset verifies against the name that was signed rather than the one served.

    This is the one place a validator and this package could agree on every byte and still
    disagree with a signer, which is why the parts live apart and are tested apart: the ordering,
    the duplicate rule, the downcase set, and the label arithmetic.
    """
    signed_for, _ = signed_owner_name(owner, rrsig.labels)
    return rrsig.signed_data_prefix() + canonical_rrset_bytes(
        signed_for,
        rrsig.type_covered,
        rclass,
        rrsig.original_ttl,
        rdatas,
    )


# ------------------------------------------------------- RSA key material (RFC 3110 §2-§3)
#
# Layout only. Which algorithms use this layout, and how large a key each allows, is algorithm
# policy and lives in namespy.crypto; nothing here imports it, so a caller supplies the bounds it
# means to enforce and the dependency direction stays one-way.


class MalformedRsaKeyError(ValueError):
    """RDATA that cannot be read as an RSA public key, or a signature that cannot be one.

    Distinct from a key that is readable but too small or too weak -- that is a size decision the
    caller makes with :mod:`namespy.crypto`'s bounds, not a reading failure, and an operator needs
    to be told which of the two happened.
    """


class RsaPublicKey(NamedTuple):
    """A decoded RSA public key: the exponent and the modulus, as integers."""

    exponent: int
    modulus: int

    @property
    def key_bits(self) -> int:
        """The bit length of the modulus -- RFC 3110 §3¶9's "size of n, including most and least
        significant bits (which will be 1)", which is the quantity the limits in that section and
        in RFC 5702 §2.1/§2.2 are written against."""
        return self.modulus.bit_length()

    def to_wire(self) -> bytes:
        """RFC 3110 §2 RDATA, i.e. :func:`pack_rsa_public_key` of these two numbers."""
        return pack_rsa_public_key(self.exponent, self.modulus)


def _minimal_octets(value: int, *, what: str) -> bytes:
    """Big-endian octets with no leading zero, which is what §2¶3's prohibition demands."""
    length = (value.bit_length() + 7) // 8
    if not length:
        raise MalformedRsaKeyError(f"RSA {what} must be a positive integer, got {value}")
    return value.to_bytes(length, "big")


def pack_rsa_public_key(exponent: int, modulus: int, *, max_key_bits: int = 4096) -> bytes:
    """Encode an RSA key into DNSKEY RDATA (RFC 3110 §2¶2-¶3).

    The exponent's octet count is written as one octet when it is 1-255 and as a zero octet plus
    two more when longer. §2¶3's phrasing ("is represented as") is prescriptive, so the short form
    is always chosen when available, and that is not cosmetics: a key tag sums the RDATA octets,
    so a key encoded the other way has a different tag and therefore a DS matching nothing.

    `max_key_bits` defaults to §2¶3's interoperability ceiling ("the exponent and modulus are each
    limited to 4096 bits") and is refused rather than silently emitted, since an oversized key is
    a record no validator may accept. The floor is deliberately *not* applied here because it is
    per-algorithm: RFC 5702 §2.2 sets 1024 bits for RSA/SHA-512 against 512 elsewhere.
    """
    exponent_octets = _minimal_octets(int(exponent), what="exponent")
    modulus_octets = _minimal_octets(int(modulus), what="modulus")
    for name, octets in (("exponent", exponent_octets), ("modulus", modulus_octets)):
        if len(octets) * 8 > int(max_key_bits):
            raise ValueError(
                f"RSA {name} is {len(octets) * 8} bits, over the {max_key_bits}-bit limit of "
                f"RFC 3110 §2¶3"
            )
    if len(exponent_octets) <= 255:
        header = bytes([len(exponent_octets)])
    else:
        header = b"\x00" + len(exponent_octets).to_bytes(2, "big")
    return header + exponent_octets + modulus_octets


def unpack_rsa_public_key(blob) -> RsaPublicKey:
    """Read DNSKEY RDATA as an RSA key, strictly (RFC 3110 §2¶2-¶3).

    Every rule here has a failure mode worth the strictness:

    * A zero first octet selects the 3-octet length form, so a zero-length exponent is
      unrepresentable in the 1-octet form -- and a 3-octet form announcing zero octets leaves no
      exponent to read. No MUST says so, so this is read off §2¶2's figure rather than quoted: an
      exponent of no octets is not a public exponent.
    * The short form is required whenever the length fits one octet, for the key-tag reason on
      :func:`pack_rsa_public_key`.
    * "Leading zero octets are prohibited in the exponent and modulus" (§2¶3), checked on both.
      The modulus half matters beyond tidiness: the same key with a leading zero has a different
      key tag, and a key whose tag does not match its DS is unusable while every bit of it is
      correct.
    * Lengths are bounds-checked against the RDATA, because this arrives from the network.

    Nothing here judges key size or whether the modulus is a product of two primes.
    :meth:`namespy.rdata.RData_DNSKEY.require_rsa_key` adds the protocol's size window; primality
    is the backend's, and `cryptography` refuses a nonsense modulus when it builds the key object.
    """
    octets = bytes(blob)
    if len(octets) < 2:
        raise MalformedRsaKeyError(
            f"RSA public key is {len(octets)} octet(s), too short for a length field and a key"
        )
    if octets[0]:
        exponent_len = octets[0]
        header_len = 1
    else:
        if len(octets) < 3:
            raise MalformedRsaKeyError(
                "RSA public key announces the 3-octet exponent length form but holds only "
                f"{len(octets)} octet(s)"
            )
        (exponent_len,) = struct.unpack("!H", octets[1:3])
        header_len = 3
        if exponent_len == 0:
            raise MalformedRsaKeyError("RSA public key has a zero-length public exponent")
        if exponent_len <= 255:
            raise MalformedRsaKeyError(
                f"RSA exponent of {exponent_len} octet(s) must use the 1-octet length form "
                f"(RFC 3110 §2¶3); as written this key has different RDATA, and so a different "
                f"key tag, from the same key encoded correctly"
            )
    end = header_len + exponent_len
    if len(octets) <= end:
        raise MalformedRsaKeyError(
            f"RSA public key announces a {exponent_len}-octet exponent but holds only "
            f"{len(octets) - header_len} octet(s) before the modulus"
        )
    exponent_octets = octets[header_len:end]
    modulus_octets = octets[end:]
    if exponent_octets[0] == 0 or modulus_octets[0] == 0:
        raise MalformedRsaKeyError(
            "RSA public key carries a leading zero octet, which RFC 3110 §2¶3 prohibits"
        )
    return RsaPublicKey(
        exponent=int.from_bytes(exponent_octets, "big"),
        modulus=int.from_bytes(modulus_octets, "big"),
    )


def rsa_signature_octets(signature, *, key_bits: int) -> bytes:
    """Zero-pad an RSA signature to the modulus length, as **erratum 2811** requires.

    RFC 3110 §3¶10 as published read "leading zero bytes are permitted", which suggests a signer
    may hand back fewer octets than the modulus holds. The verified technical erratum changes
    "permitted" to "MUST be added ... so that the signature size in bytes is equal to the size of
    n", citing PKCS #1's I2OSP(s, k): the signature is an octet string of exactly k octets, so the
    short form was never legal -- the text was.

    That history is why this pads rather than rejects. Records already on the wire, and servers
    that implemented the published sentence, do send short signatures; refusing them would enforce
    a rule the erratum exists to clarify. A signature *longer* than the modulus is another matter:
    a value reduced mod n cannot be that wide, so it is refused rather than trimmed. A backend
    handed the unpadded form usually fails outright, and that failure looks exactly like a forged
    RRset.
    """
    octets = bytes(signature)
    length = (int(key_bits) + 7) // 8
    if not octets:
        raise MalformedRsaKeyError("RSA signature is empty")
    if len(octets) > length:
        raise MalformedRsaKeyError(
            f"RSA signature is {len(octets)} octet(s), wider than the {key_bits}-bit modulus "
            f"({length} octet(s)); no signature reduced mod n can be this long"
        )
    return octets.rjust(length, b"\x00")
