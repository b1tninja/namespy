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
from enum import IntEnum
from hashlib import sha1, sha256, sha384

from .names import DomainName

__all__ = [
    "DNSKEY_FLAG_REVOKED",
    "DNSKEY_FLAG_SEP",
    "DNSKEY_FLAG_ZONE_KEY",
    "DNSKEY_HEAD_OCTETS",
    "DNSKEY_PROTOCOL_VALUE",
    "RSA_MD5_ALGORITHM",
    "DigestType",
    "canonical_owner_octets",
    "decode_base64_field",
    "decode_hex_field",
    "digest_material",
    "ds_digest",
    "encode_base64_field",
    "encode_hex_field",
    "key_material",
    "key_tag",
    "known_digest_octets",
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
    """The DS's hash input for an owner name: wire form, fully qualified, lowercase.

    RFC 4034 §6.2 defines the canonical form of an RR as its wire format where,
    among other rules, names are "fully expanded (no DNS name compression) and fully
    qualified" (item 1) and "all uppercase US-ASCII letters in the owner name of the
    RR are replaced by the corresponding lowercase US-ASCII letters" (item 2). Item
    3 -- downcasing names *inside* RDATA -- does not apply to what a DS hashes,
    because that RDATA is a DNSKEY's, and DNSKEY is not in item 3's list and holds
    no domain names at all.

    Lowercasing the assembled wire octets is exactly item 2 and nothing more: the
    only bytes that can land in A-Z are label contents, since a length octet is at
    most 63 and a fully expanded name carries no pointer.

    :meth:`namespy.names.DomainName.canonical_text` is deliberately not used: it
    folds to *upper* case, which is right for a map key and backwards for a digest.
    """
    parsed = DomainName(name)
    if not parsed.is_absolute:
        raise ValueError(
            f"DS digest input must be a fully qualified owner name (§5.1.4), got {parsed}"
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
