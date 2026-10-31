"""Trust anchors: where a chain of trust starts, and how the root's are published.

A DNSSEC chain cannot bootstrap from signatures alone -- every signature needs a key,
every key needs a parent, and the walk stops somewhere by definition. RFC 4033 §2 names
that stopping place: *a configured DNSKEY RR or DS RR hash of a DNSKEY RR*. This module
holds the DS form -- which is what IANA publishes for the root -- reads the RFC 9718 XML
document, fetches it over the transport RFC 9718 §3 says to use, and answers the one
arithmetic-free question the chain needs at each boundary: does this DNSKEY match that DS
(RFC 4034 §5.1.4's digest, §5.2's zone-key rule).

Two documents' history is worth keeping in view, because it is the reason this module
exists rather than a constant. RFC 7958 once governed root-anchor publication and offered
PGP-signed and CSR forms; RFC 9718 obsoleted it and removed both (§3.3), on the grounds
that they "mix out-of-band trust of authentication keys with out-of-band trust of the
DNSSEC root keys" -- and the surviving model says the assurance on *this* file's content
and origin comes from TLS itself (§3.2¶4), with IANA's detached CMS signature (§3.2¶3)
optional for those who hold the ICANN CA key out of band. So the honest implementation
fetches over HTTPS, checks the document against its schema, and does not pretend to
authenticate the file any harder than the transport does.

What an anchor buys is a *starting point*, and RFC 4035 §5.2¶3 is the matching half: the
DS at a zone cut must itself have been authenticated by the parent's keys before it means
anything. Anchors are where that recursion bottoms out. Nothing here walks the chain --
that is :func:`namespy.verify.authenticate_dnskey_rrset` -- and nothing here rolls a key
that has been compromised or replaced: RFC 9718 §2.2¶7's validity windows say when a
published anchor *may* be used, and RFC 8509's rollover model is still roadmap work.
"""

from __future__ import annotations

import datetime as _datetime
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING
from xml.etree import ElementTree

from .dnssec import (
    decode_base64_field,
    decode_hex_field,
    ds_digest,
    known_digest_octets,
    unsigned_field,
)

if TYPE_CHECKING:  # pragma: no cover - typing only; rdata arrives duck-typed at the boundary
    from .rdata import RData_DNSKEY, RData_DS

__all__ = [
    "IANA_ROOT_ANCHORS_URL",
    "TrustAnchor",
    "TrustAnchorFetchError",
    "TrustAnchorFormatError",
    "active_anchors",
    "fetch_root_anchors",
    "parse_root_anchors",
]

#: RFC 9718 §3.1¶3, the published location of the root trust anchors. The scheme is the
#: point: §3.1¶2 allows HTTP only for operators who cannot use HTTPS, and §3.2¶4 says
#: HTTPS "SHOULD be used" when the relying party trusts the Web PKI -- on this file's
#: model the transport *is* the origin assurance.
IANA_ROOT_ANCHORS_URL = "https://data.iana.org/root-anchors/root-anchors.xml"


class TrustAnchorError(ValueError):
    """Something went wrong between an operator and a trust anchor.

    Two kinds, because the operator's next action differs: a *format* problem means the
    file at the other end is not what RFC 9718 describes -- replace or report it -- and a
    *fetch* problem means it could not be reached at all, which is network or policy
    territory rather than anything to fix in the document.
    """


class TrustAnchorFormatError(TrustAnchorError):
    """XML that does not satisfy the RFC 9718 §2.1 schema or its §2.2 semantics."""


class TrustAnchorFetchError(TrustAnchorError):
    """The document could not be retrieved or read from the URL asked for."""


@dataclass(frozen=True)
class TrustAnchor:
    """One ``KeyDigest`` element: RFC 9718 §2.2 in object form.

    The fields are the DS fields a parent would publish -- key tag, algorithm, digest
    type, digest (RFC 4034 §5.1.1-§5.1.4) -- plus the bookkeeping the XML carries: the
    opaque ``id`` (§2.2¶6, "no particular semantics", but it is how operators name keys
    and is preserved rather than dropped), the validity window (§2.2¶7), and the
    optional PublicKey/Flags pair (§2.2¶12, new in RFC 9718, useful "when IANA has a
    trust anchor that has not yet been published in the DNS").
    """

    zone: str
    key_tag: int
    algorithm: int
    digest_type: int
    digest: bytes
    key_id: str | None = None
    valid_from: _datetime.datetime | None = None
    valid_until: _datetime.datetime | None = None
    public_key: bytes | None = None
    flags: int | None = None

    def active(self, moment: _datetime.datetime | None = None) -> bool:
        """Whether this anchor may be used as a trust anchor at *moment* (§2.2¶7).

        §2.2¶7 says the attributes "specify the range of times that the KeyDigest element
        *can be used* as a trust anchor" -- a permission window, not a property of the
        key: an anchor past validUntil stops being usable exactly as of its ceremony,
        and one before validFrom is IANA pre-publishing the next KSK. An implementation
        that ignores the window is not broken today; it is broken at the next rollover,
        which is when this code will most need to be right.
        """
        if moment is None:
            moment = _datetime.datetime.now(_datetime.UTC)
        return (self.valid_from is None or moment >= self.valid_from) and (
            self.valid_until is None or moment < self.valid_until
        )

    @property
    def comparable(self) -> bool:
        """Whether this package can compute the anchor's digest at all.

        An anchor with an unimplemented digest type is not false-of-everything: it is
        uncheckable, and a caller that treats "cannot compare" as "does not match" has
        silently converted an unknown algorithm into a bogus zone -- RFC 4035 §5.2¶8's
        situation, which the spec routes to "treat as unsigned" (§5.2¶10), not to forgery.
        """
        return known_digest_octets(self.digest_type) is not None

    def ds_record(self) -> RData_DS:
        """The same fact in wire form: the DS record this anchor *is* (RFC 4033 §2)."""
        from .rdata import RData_DS  # deferred: nothing in the tree needs it until asked

        return RData_DS(self.key_tag, self.algorithm, self.digest_type, self.digest)

    def matches_dnskey(self, dnskey: RData_DNSKEY) -> bool:
        """The RFC 4035 §5.2¶4 match, with RFC 4034 §5.2's zone-key proviso.

        Three conjuncts, each added because the previous ones were not enough: the key
        tag and algorithm must equal the anchor's (§5.1.1-§5.1.2 say the DS *copies*
        them, so disagreement is a non-match, never a clue); the key must carry Flags
        bit 7, because §5.2¶1 says a DS pointing at a non-zone-key -- "and the DNSKEY RR
        it references" -- MUST NOT be used in validation; and the digest over canonical
        owner name plus RDATA (§5.1.4) must equal the anchor's, which is the only
        binding that survives a collision search on the 16-bit tag.

        False whenever :attr:`comparable` is False -- the absence of a hash function
        reports as *no match here*, and the chain layer, which sees every anchor at once,
        is where "nothing matched" and "nothing could match" get told apart.
        """
        if not self.comparable:
            return False
        if int(dnskey.key_tag) != self.key_tag or int(dnskey.algorithm) != self.algorithm:
            return False
        if not dnskey.is_zone_key:  # RFC 4034 §5.2¶1: bit 7 or the pair is unusable
            return False
        return ds_digest(self.zone, bytes(dnskey), self.digest_type) == self.digest

    def __repr__(self) -> str:
        window = "always"
        if self.valid_from is not None or self.valid_until is not None:
            window = f"{self.valid_from or '-'} .. {self.valid_until or 'open'}"
        return (
            f"<TrustAnchor {self.zone} {self.key_id or '?'} tag={self.key_tag} "
            f"alg={self.algorithm} digest-type={self.digest_type} [{window}]>"
        )


# ------------------------------------------------------------------------------ RFC 9718 §2 XML


def _tag(element: ElementTree.Element) -> str:
    """The element name with any namespace URI stripped.

    The §2.1 schema declares no namespace, and the live IANA document carries none, but
    XML readers that reserialize the file -- mirrors, packaging tools -- sometimes add
    one, and refusing a byte-for-byte-correct anchor set because a tool wrapped it in a
    namespace would be ceremony over substance.
    """
    _, _, local = element.tag.rpartition("}")
    return local


def _text(element: ElementTree.Element, path: str) -> str:
    body = (element.text or "").strip()
    if not body:
        raise TrustAnchorFormatError(f"{path} is empty")
    return body


def _number(element: ElementTree.Element, path: str, *, bits: int, name: str) -> int:
    raw = _text(element, path)
    try:
        value = int(raw)
    except ValueError:
        raise TrustAnchorFormatError(f"{path} is not an integer: {raw!r}") from None
    if value < 0:
        raise TrustAnchorFormatError(f"{path} is negative ({value}); the schema says non-negative")
    try:
        return unsigned_field(value, bits=bits, name=name)
    except ValueError as exc:
        # unsigned_field's message carries the range in words, which is the whole report.
        raise TrustAnchorFormatError(f"{path}: {exc}") from None


def _moment(raw: str, path: str, *, attribute: str) -> _datetime.datetime:
    try:
        parsed = _datetime.datetime.fromisoformat(raw.strip().replace("Z", "+00:00"))
    except ValueError:
        raise TrustAnchorFormatError(
            f"{path} {attribute} is not an xsd:dateTime: {raw!r}"
        ) from None
    if parsed.tzinfo is None:
        # xsd:dateTime without an offset is ambiguous, not UTC-guaranteed; RFC 9718's own
        # file always writes +00:00, and guessing the operator's local zone for a
        # rollover window would make the same file mean different things in different
        # offices. Naive input is read as UTC, which is the only reading that is the
        # same answer everywhere.
        parsed = parsed.replace(tzinfo=_datetime.UTC)
    return parsed


def _child(parent: ElementTree.Element, name: str, path: str) -> ElementTree.Element:
    for element in parent:
        if _tag(element) == name:
            return element
    raise TrustAnchorFormatError(f"{path} is missing its {name} element (RFC 9718 §2.1)")


_SCHEMA_PARTS = {"KeyTag", "Algorithm", "DigestType", "Digest", "PublicKey", "Flags"}


def parse_root_anchors(document: str | bytes) -> list[TrustAnchor]:
    """Read an RFC 9718 trust anchor document into :class:`TrustAnchor` objects.

    The validation follows the §2.1 schema literally, because this document is the
    input to a trust decision and a lenient reader silently widens what can be trusted:
    ``validFrom`` is required (the schema gives it no ``?``), ``KeyTag`` tops out at
    65535, ``Algorithm`` and ``DigestType`` at 255, ``PublicKey`` and ``Flags`` are a
    pair (§2.1's named pattern: neither alone), and a digest whose type this package
    knows must have exactly the length that type produces -- the same rule
    :class:`namespy.rdata.RData_DS` applies on the wire.

    The file's *time* is not consulted: anchors come back with their windows attached
    and the caller answers "usable now?" with :meth:`TrustAnchor.active`, so parsing a
    year-old file and asking it today is the supported way to notice it is stale.
    """
    try:
        # ElementTree refuses external entities by default, the input is a schema-checked
        # anchor document rather than arbitrary peer data, and defusedxml is not a
        # dependency this package will add for it -- the parse error path is the defence.
        root = ElementTree.fromstring(document)  # noqa: S314
    except ElementTree.ParseError as exc:
        raise TrustAnchorFormatError(f"not well-formed XML: {exc}") from None
    if _tag(root) != "TrustAnchor":
        raise TrustAnchorFormatError(
            f"document root is <{_tag(root)}>, not the RFC 9718 §2.1 <TrustAnchor>"
        )
    zone = _text(_child(root, "Zone", "TrustAnchor"), "TrustAnchor/Zone")
    digests = [element for element in root if _tag(element) == "KeyDigest"]
    if not digests:
        raise TrustAnchorFormatError(
            "TrustAnchor holds no KeyDigest element; the schema allows neither zero nor none"
        )
    anchors: list[TrustAnchor] = []
    for element in digests:
        path = f"KeyDigest[{element.get('id') or len(anchors)}]"
        valid_from = element.get("validFrom")
        if valid_from is None:
            raise TrustAnchorFormatError(f"{path} has no validFrom attribute (RFC 9718 §2.1)")
        valid_until = element.get("validUntil")
        body: dict[str, ElementTree.Element] = {}
        for part in element:
            name = _tag(part)
            if name in body:
                raise TrustAnchorFormatError(f"{path} repeats its {name} element")
            body[name] = part
        unknown = sorted(name for name in body if name not in _SCHEMA_PARTS)
        if unknown:
            raise TrustAnchorFormatError(f"{path} holds element(s) outside the schema: {unknown}")
        try:
            digest = decode_hex_field(
                _text(_child(element, "Digest", path), f"{path}/Digest"), what=f"{path} digest"
            )
        except ValueError as exc:
            raise TrustAnchorFormatError(f"{path}: {exc}") from None
        digest_type = _number(
            _child(element, "DigestType", path),
            f"{path}/DigestType",
            bits=8,
            name="DS digest type",
        )
        expected = known_digest_octets(digest_type)
        if expected is not None and len(digest) != expected:
            raise TrustAnchorFormatError(
                f"{path}: digest of type {digest_type} is {len(digest)} octet(s), "
                f"must be {expected}"
            )
        public_key: bytes | None = None
        flags: int | None = None
        if ("PublicKey" in body) != ("Flags" in body):
            raise TrustAnchorFormatError(
                f"{path} carries one of PublicKey/Flags; §2.1's publickeyinfo is both or neither"
            )
        if "PublicKey" in body:
            try:
                public_key = decode_base64_field(
                    _text(body["PublicKey"], f"{path}/PublicKey"), what=f"{path} public key"
                )
            except ValueError as exc:
                raise TrustAnchorFormatError(f"{path}: {exc}") from None
            flags = _number(body["Flags"], f"{path}/Flags", bits=16, name="DNSKEY flags")
        anchors.append(
            TrustAnchor(
                zone=zone,
                key_tag=_number(
                    _child(element, "KeyTag", path), f"{path}/KeyTag", bits=16, name="DS key tag"
                ),
                algorithm=_number(
                    _child(element, "Algorithm", path),
                    f"{path}/Algorithm",
                    bits=8,
                    name="DS algorithm",
                ),
                digest_type=digest_type,
                digest=digest,
                key_id=element.get("id"),
                valid_from=_moment(valid_from, path, attribute="validFrom"),
                valid_until=(
                    None
                    if valid_until is None
                    else _moment(valid_until, path, attribute="validUntil")
                ),
                public_key=public_key,
                flags=flags,
            )
        )
    return anchors


def active_anchors(
    anchors: Iterable[TrustAnchor], *, moment: _datetime.datetime | None = None
) -> list[TrustAnchor]:
    """The anchors usable as trust points at *moment* (RFC 9718 §2.2¶7's window)."""
    return [anchor for anchor in anchors if anchor.active(moment)]


def _https_get(url: str, timeout: float) -> bytes:
    """The default transport: urllib over the platform TLS store, no extra dependency.

    urllib is chosen over namespy's own resolver for the obvious reason -- this is not
    a DNS query -- and the import lives inside the function so that ``import namespy``
    never reaches for a network module it may not need. The scheme is not validated
    here: RFC 9718 §3.1¶2 sanctions http for operators who cannot do https, so the URL
    is the operator's declaration, and this module's part is to default to the good one.
    """
    from urllib.error import URLError
    from urllib.request import Request, urlopen

    # The URL is the operator's own declaration (default: RFC 9718 §3.1¶3 over https),
    # not peer data, so the scheme audit's refusal of exotic schemes is the wanted
    # behaviour and no file: surprise exists to protect against.
    request = Request(url, headers={"accept": "application/xml"})  # noqa: S310
    try:
        with urlopen(request, timeout=timeout) as response:  # noqa: S310
            return response.read()
    except (URLError, OSError) as exc:
        raise TrustAnchorFetchError(f"could not retrieve {url}: {exc}") from None


def fetch_root_anchors(
    url: str = IANA_ROOT_ANCHORS_URL,
    *,
    opener: Callable[[str, float], bytes] | None = None,
    timeout: float = 30.0,
) -> list[TrustAnchor]:
    """Retrieve and parse the RFC 9718 document at *url* -- the root anchors by default.

    The transport is injectable because this is where the module touches the world, and
    an operator behind a proxy, a test, and a cache-replayer should all be able to hand
    over bytes without the parsing path noticing. RFC 9718 §3.2 is explicit that in this
    model the *transport* carries content-and-origin assurance (the Web PKI, or the
    detached CMS signature for operators who hold the ICANN CA key out of band), so
    there is no signature check here to promise; there is TLS and a schema.

    Fetching is not trusting: the caller still asks :meth:`TrustAnchor.active`, and a
    file that parses cleanly is exactly as stale as whatever it replaced -- which is the
    rollover gap RFC 8509 exists to close and this package has not closed yet.
    """
    getter = _https_get if opener is None else opener
    try:
        body = getter(url, timeout)
    except OSError as exc:  # URLError, HTTPError, socket trouble -- injected openers included
        raise TrustAnchorFetchError(f"could not retrieve {url}: {exc}") from None
    try:
        text = body.decode("utf-8") if isinstance(body, (bytes, bytearray)) else str(body)
    except UnicodeDecodeError as exc:
        raise TrustAnchorFetchError(
            f"{url} returned content that is not UTF-8 XML: {exc}"
        ) from None
    return parse_root_anchors(text)
