"""DNS domain names: presentation form, wire encoding, and wire parsing.

.. rubric:: What a label is allowed to contain

RFC 1035 :rfc:`3.5 <1035#section-3.5>` describes the ARPANET *host name*
grammar (letters, digits, hyphen; start with a letter, end with a letter or
digit). That grammar constrains **host names**, not DNS labels. RFC 2181
section 11 is explicit:

    The DNS itself places only one restriction on the particular labels that
    can be used to identify resource records. That one restriction relates to
    the length of the label and the full name. [...] Those restrictions aside,
    any binary string whatever can be used as the label of any resource
    record. [...] Implementations of the DNS protocols must not place any
    restrictions on the labels that can be used.

Real traffic proves the point constantly: ``_dmarc.example.org`` and
``_svc._https.example.org`` (BCP 222 underscored/scoped names), ``*.example``
wildcards (RFC 4592), ``1.0.0.127.in-addr.arpa`` reverse names, and non-ASCII
``A-label`` forms (RFC 5891). A parser that enforces LDH on the wire rejects
all of them, so :meth:`DomainName.parse_from` validates only *length and
structure* and preserves the label's octets exactly.

Where a caller genuinely needs host-name syntax, that is an explicit decision:
:attr:`DomainName.is_hostname`.

.. rubric:: Presentation form

:class:`DomainName` stores its name as a ``str``, so arbitrary label octets are
kept using the master-file escaping of RFC 1035 section 5.1: a byte that is not
a letter, digit, ``-``, ``_`` or ``*`` is written as a three-digit decimal
escape. This keeps the attribute a plain string, keeps the form round-trip
lossless, and stops a label containing a dot from being re-split into two
labels. Use :func:`escape_label` / :func:`unescape_label` to convert.

.. rubric:: References

* RFC 1034 sections 3.1, 3.5 (names, label rules)
* RFC 1035 sections 3.1 (wire form), 3.5, 4.1.4 (compression), 5.1 (escaping)
* RFC 2181 section 11 (name syntax -- no label restrictions)
* RFC 8552 / BCP 222 (underscored, scoped node names)
* RFC 9267 sections 2, 4 (pointer loops, name-buffer limits)
"""

from __future__ import annotations

from .wire import (
    MAX_LABEL_OCTETS,
    MAX_NAME_OCTETS,
    MAX_POINTER_HOPS,
    DnsNameParseError,
    DnsPacketParseError,
    is_compression_pointer,
    is_reserved_label_type,
    pointer_target,
    read_octets,
)

# Bytes that survive presentation form unescaped. Everything else is written
# as a three-digit decimal escape (RFC 1035 section 5.1). Underscore and
# asterisk stay readable because BCP 222 and RFC 4592 make them common.
_PLAIN_BYTES = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_*")

# RFC 1035 section 3.5 / RFC 1123 section 2.1 host-name grammar, used only by
# DomainName.is_hostname. Iterating bytes yields ints, so these hold ints.
_HOST_LETTER_DIGIT = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
_HOST_INNER = _HOST_LETTER_DIGIT | frozenset(b"-")


class DomainNameError(ValueError):
    """A name cannot be encoded to the wire (invalid label or too long)."""


def escape_label(raw: bytes) -> str:
    r"""Render one raw label octet string as escaped presentation text."""
    out = []
    for byte in raw:
        if byte in _PLAIN_BYTES:
            out.append(chr(byte))
        else:
            out.append(f"\\{byte:03d}")
    return "".join(out)


def unescape_label(text: str) -> bytes:
    r"""Convert escaped presentation text back to raw label octets.

    Accepts both ``\DDD`` decimal escapes and ``\c`` single-character escapes,
    per RFC 1035 section 5.1.
    """
    out = bytearray()
    i = 0
    length = len(text)
    while i < length:
        ch = text[i]
        if ch != "\\":
            out.extend(ch.encode("latin-1"))
            i += 1
            continue
        i += 1
        if i >= length:
            raise DomainNameError("trailing backslash in presentation label")
        nxt = text[i]
        if nxt.isdigit():
            digits = text[i : i + 3]
            if len(digits) < 3 or not digits.isdigit():
                raise DomainNameError(f"escape needs exactly three decimal digits, got {digits!r}")
            value = int(digits)
            if value > 255:
                raise DomainNameError(f"escape value {value} is not an octet")
            out.append(value)
            i += 3
        else:
            out.extend(nxt.encode("latin-1"))
            i += 1
    return bytes(out)


def split_presentation(name: str) -> list[str]:
    r"""Split presentation form into labels on *unescaped* dots.

    A dot that belongs to a label is stored escaped (``\046``), so a plain dot
    is always a separator and this split is unambiguous.
    """
    labels: list[str] = []
    current: list[str] = []
    i = 0
    length = len(name)
    while i < length:
        ch = name[i]
        if ch == "\\":
            current.append(ch)
            if i + 1 < length:
                current.append(name[i + 1])
            i += 2
            continue
        if ch == ".":
            labels.append("".join(current))
            current = []
            i += 1
            continue
        current.append(ch)
        i += 1
    labels.append("".join(current))
    return labels


class DomainName:
    r"""A DNS domain name in presentation form.

    ``name`` is stored essentially as supplied, so ``"example.com"``,
    ``"EXAMPLE.com."`` and ``"\095dmarc.example.com."`` are all valid inputs.
    Equality and hashing are wire-form based -- labels case-folded, root
    terminator insignificant -- so those spellings collide as the DNS requires
    (RFC 1035 section 3.1: "no significance is attached to the case").

    The trailing ``.`` in *presentation* form is the root terminator: it marks
    the name absolute and tells a resolver not to assume a search suffix. See
    :attr:`is_absolute` and :meth:`qualify`.

    :param name: presentation-form name; arbitrary label octets are permitted
        via ``\DDD`` escaping (see the module docs).
    :param buffer: the datagram the name was parsed from, if any.
    :param offset: the octet offset of the name within ``buffer``, if any.
    """

    def __init__(self, name, buffer: bytes | None = None, offset: int | None = None):
        text: str
        if isinstance(name, DomainName):
            text = name.name
        elif isinstance(name, bytes):
            # Raw octets: treat as a single label rather than guessing at dots.
            text = escape_label(name)
        elif not isinstance(name, str):
            raise TypeError(f"DomainName requires str, got {type(name).__name__}")
        else:
            text = name
        self.name = text
        self.buffer = buffer
        self.offset = offset

    # ---------------------------------------------------------------- identity

    def labels(self) -> list[bytes]:
        """The name's labels as raw octet strings, most significant first."""
        parts = split_presentation((self.name or "").strip())
        if parts and parts[-1] == "":
            parts = parts[:-1]  # trailing dot is the root terminator, not a label
        return [unescape_label(p) for p in parts if p != ""]

    def _labels(self) -> tuple[bytes, ...]:
        """Raw, ASCII-case-folded label octets -- the name's true identity.

        Compared as octets rather than text because a label may hold any byte
        string at all (RFC 2181 section 11). Case folding is ASCII-only to
        match the DNS's own behaviour, so a non-ASCII byte is never folded.
        The root is ``()``.
        """
        return tuple(label.upper() for label in self.labels())

    @property
    def canonical_text(self) -> str:
        """Case-folded, escaped, absolute presentation -- safe as a map key."""
        return ".".join(escape_label(label) for label in self._labels()) + "."

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            other = DomainName(other)
        if not isinstance(other, DomainName):
            return NotImplemented
        return self._labels() == other._labels()

    def __hash__(self) -> int:
        return hash(self._labels())

    def __str__(self) -> str:
        return str(self.name)

    def __repr__(self) -> str:
        return repr(self.name)

    # --------------------------------------------------------------- structure

    @property
    def is_absolute(self) -> bool:
        """Whether this name carries the root terminator (a trailing ``.``).

        On the wire every name is absolute (terminated by the zero-length root
        label). In presentation form a trailing ``.`` explicitly anchors the
        name at the root and prevents a DNS suffix from being assumed; a name
        without it is relative and may be promoted via :meth:`qualify`. The
        bare root (``"."`` or ``""``) is absolute.
        """
        s = self.name or ""
        return s == "" or s.endswith(".")

    @property
    def terminated(self) -> bool:
        """Alias of :attr:`is_absolute`, reading as "has a root terminator"."""
        return self.is_absolute

    @property
    def is_hostname(self) -> bool:
        """Whether every label satisfies the ARPANET host-name grammar.

        RFC 1035 section 3.5 as relaxed by RFC 1123 section 6.1.3.5: 1-63
        octets, begins and ends with a letter or digit, letters/digits/hyphen
        internally. This is *not* a DNS validity requirement (RFC 2181 section
        11) -- it is a check a caller opts into when treating a name as a host
        name. The root (no labels) is vacuously conforming.
        """
        for label in self._labels():
            if len(label) > MAX_LABEL_OCTETS:
                return False
            if label[0] not in _HOST_LETTER_DIGIT:
                return False
            if label[-1] not in _HOST_LETTER_DIGIT:
                return False
            for byte in label[1:-1]:
                if byte not in _HOST_INNER:
                    return False
        return True

    @property
    def is_wildcard(self) -> bool:
        """Whether the leftmost label is ``*`` (RFC 4592 wildcard owner name)."""
        labels = self._labels()
        return bool(labels) and labels[0] == b"*"

    def hierarchy(self) -> list[DomainName]:
        """This name and each of its ancestors, root first, shortest next.

        ``"a.b.example.com."`` yields ``[".", "com.", "example.com.",
        "b.example.com.", "a.b.example.com."]`` -- the order a resolver walks
        when descending from the root, and the order to scan when finding the
        enclosing wildcard (RFC 4592 section 4) or a zone cut.

        Built from raw labels and re-escaped, so a label that contains a dot
        cannot fabricate extra ancestors, and the root terminator cannot emit
        an empty label.
        """
        raw = self.labels()
        out = [self.root_label()]
        for i in range(1, len(raw) + 1):
            tail = raw[len(raw) - i :]
            out.append(self.__class__(".".join(escape_label(label) for label in tail) + "."))
        return out

    @classmethod
    def from_labels(cls, labels) -> DomainName:
        """Build an absolute name from raw label octets.

        Composition is needed wherever a name is *derived* rather than written
        down: DNAME target synthesis (RFC 6672 section 2.3) prepends the part of
        QNAME below the owner to the DNAME's target, and a resolver's search-list
        walk rebuilds names constantly. Each label passes through
        :func:`escape_label`, so a label containing a dot or a backslash cannot
        fabricate extra labels on the way back in.
        """
        return cls(".".join(escape_label(label) for label in labels) + ".")

    def is_subdomain_of(self, other, *, include_self: bool = True) -> bool:
        """Whether this name lies within *other*, compared label-wise from the root.

        RFC 1034 section 3.1: "if Y is a domain and X is a label, then X.Y is a
        subdomain of Y", and every domain is a subdomain of itself. That reflexive
        reading is what zone-cut and bailiwick tests want (RFC 5625 section 2.5);
        a DNAME needs the strict form, because it redirects only names *below* its
        owner and never the owner itself (RFC 6672 section 2.1).

        Case-insensitive and terminator-insensitive like all other name
        comparison here, and a name is always within the root.
        """
        mine = self._labels()
        theirs = (
            other._labels() if isinstance(other, DomainName) else self.__class__(other)._labels()
        )
        needed = len(theirs) + (0 if include_self else 1)
        if len(mine) < needed:
            return False
        return mine[len(mine) - len(theirs) :] == theirs

    def qualify(self, dns_suffix=None) -> DomainName:
        """Return an absolute :class:`DomainName`, applying a DNS suffix if needed.

        If this name is already absolute, ``self`` is returned unchanged -- the
        trailing root terminator on the wire prevents any suffix from being
        assumed. Otherwise the result is this name's labels, then
        ``dns_suffix`` if one is supplied, then the root terminator. With no
        ``dns_suffix``, the relative name is simply anchored at the root.

        The decision of *which* suffix to assume for a relative name is the
        resolver's responsibility (see ``Resolver.dns_suffix``);
        :class:`DomainName` itself is suffix-agnostic.
        """
        if self.is_absolute:
            return self
        own = [escape_label(label) for label in self.labels()]
        suffix: list[str] = []
        if dns_suffix is not None:
            text = str(dns_suffix)
            suffix = [escape_label(label) for label in self.__class__(text).labels()]
        combined = own + suffix
        return self.__class__(".".join(combined) + "." if combined else ".")

    # ---------------------------------------------------------------- encoding

    def __bytes__(self) -> bytes:
        """Encode to wire form: length-prefixed labels then the root label.

        RFC 1035 section 3.1. The trailing ``.`` of presentation form *is* the
        root terminator and is not itself a label, so it must not emit a
        zero-length label ahead of the real terminator -- that one-byte shift
        is what root servers see as a malformed QTYPE/QCLASS pair.

        Raises :class:`DomainNameError` rather than emitting an invalid
        message. A label over 63 octets cannot be encoded at all, because the
        two high bits of the length octet carry the pointer/reserved tags;
        writing ``0b11000000 | len`` as a workaround would emit a compression
        pointer into unrelated octets.
        """
        raw_labels = self.labels()
        if not raw_labels:
            return b"\x00"

        total = 1  # root terminator counts against the 255-octet budget
        out = bytearray()
        for label in raw_labels:
            if not label:
                raise DomainNameError("empty label in name (RFC 1035 section 3.1)")
            if len(label) > MAX_LABEL_OCTETS:
                raise DomainNameError(
                    f"label of {len(label)} octets exceeds the {MAX_LABEL_OCTETS}-octet limit"
                )
            total += len(label) + 1
            if total > MAX_NAME_OCTETS:
                raise DomainNameError(
                    f"encoded name of {total} octets exceeds the {MAX_NAME_OCTETS}-octet limit"
                )
            out.append(len(label))
            out.extend(label)
        out.append(0)
        return bytes(out)

    # ----------------------------------------------------------------- decoding

    @classmethod
    def root_label(cls) -> DomainName:
        """The root domain: the empty, terminated name ``"."``."""
        return cls(".")

    @classmethod
    def parse_from(cls, buffer: bytes, offset: int = 0) -> tuple[DomainName, int]:
        r"""Read a wire-format name; return ``(name, octet after the name)``.

        The second element is where the *enclosing record* continues. When the
        name ends in a compression pointer, that is the offset just past the
        pointer's two octets -- not the end of the expanded name -- because the
        pointer is the name's last element on the wire (RFC 1035 section 4.1.4:
        "a sequence of labels ending with a pointer").

        Validation is structural only, and every failure is a
        :class:`DnsNameParseError` (never an :keyword:`assert`):

        * pointers are recognised with ``(octet & 0xC0) == 0xC0``, so an octet
          with only *one* of the two tag bits set -- ``0x41``, say, which a
          truthiness test would happily reinterpret as a pointer -- is reported
          as the invalid label type it is (RFC 9267 section 2);
        * the reserved ``01``/``10`` label types are rejected outright
          (RFC 1035 section 4.1.4 leaves them unassigned);
        * a pointer must reference an offset *before* itself. RFC 1035 section
          4.1.4 defines a pointer as pointing at "an earlier occurrence" of a
          name, so requiring the offset to decrease makes termination
          mathematical rather than arguable, and removes pointer loops without
          needing an unbounded set of seen offsets (RFC 9267 section 2);
        * a pointer whose target is another pointer is followed (legitimate wire
          form that a single-hop implementation rejects), up to
          :data:`~aiodns.wire.MAX_POINTER_HOPS` hops;
        * the 63-octet label and 255-octet name budgets are enforced against
          the expanded name, counting length octets and the root terminator
          (RFC 1035 section 3.1, RFC 2181 section 11);
        * label octets are kept verbatim -- no LDH screening here, because
          ``_dmarc``, ``_svc._https``, ``*`` and non-ASCII labels are all valid
          (RFC 2181 section 11, BCP 222, RFC 4592).
        """
        if offset < 0:
            raise DnsNameParseError(f"negative name offset {offset}", data=buffer, offset=offset)

        labels: list[bytes] = []
        budget = 0
        hops = 0
        resume_at: int | None = None
        seen: set[int] = set()

        while True:
            if offset >= len(buffer):
                raise DnsNameParseError(
                    f"name extends past end of message at offset {offset} "
                    f"({len(buffer)} octets available)",
                    data=buffer,
                    offset=offset,
                )
            if offset in seen:
                raise DnsNameParseError(
                    f"label offset {offset} revisited (pointer loop)",
                    data=buffer,
                    offset=offset,
                )
            seen.add(offset)

            octet = buffer[offset]

            if is_compression_pointer(octet):
                if offset + 1 >= len(buffer):
                    raise DnsNameParseError(
                        f"truncated compression pointer at offset {offset}",
                        data=buffer,
                        offset=offset,
                    )
                target = pointer_target(octet, buffer[offset + 1])
                if resume_at is None:
                    resume_at = offset + 2
                if target >= len(buffer):
                    raise DnsNameParseError(
                        f"compression pointer at offset {offset} targets "
                        f"{target}, past end of message ({len(buffer)})",
                        data=buffer,
                        offset=offset,
                    )
                if target >= offset:
                    raise DnsNameParseError(
                        f"compression pointer at offset {offset} targets "
                        f"{target}, which is not an earlier offset "
                        f"(RFC 1035 section 4.1.4, RFC 9267 section 2)",
                        data=buffer,
                        offset=offset,
                    )
                hops += 1
                if hops > MAX_POINTER_HOPS:
                    raise DnsNameParseError(
                        f"more than {MAX_POINTER_HOPS} chained compression pointers",
                        data=buffer,
                        offset=offset,
                    )
                budget += 2
                offset = target
                continue

            if is_reserved_label_type(octet):
                raise DnsNameParseError(
                    f"reserved label type 0b{octet >> 6:02b} at offset {offset} "
                    f"(RFC 1035 section 4.1.4)",
                    data=buffer,
                    offset=offset,
                )

            length = octet
            if length == 0:
                budget += 1
                if budget > MAX_NAME_OCTETS:
                    raise DnsNameParseError(
                        f"expanded name exceeds {MAX_NAME_OCTETS} octets",
                        data=buffer,
                        offset=offset,
                    )
                offset += 1
                break

            if length > MAX_LABEL_OCTETS:
                raise DnsNameParseError(
                    f"label length {length} at offset {offset} exceeds "
                    f"{MAX_LABEL_OCTETS} (RFC 1035 section 3.1)",
                    data=buffer,
                    offset=offset,
                )
            budget += length + 1
            if budget > MAX_NAME_OCTETS:
                raise DnsNameParseError(
                    f"expanded name exceeds {MAX_NAME_OCTETS} octets at offset "
                    f"{offset} (RFC 1035 section 3.1)",
                    data=buffer,
                    offset=offset,
                )
            try:
                label = read_octets(buffer, offset + 1, length, what="label")
            except DnsPacketParseError as exc:
                raise DnsNameParseError(str(exc), data=buffer, offset=offset) from None
            labels.append(label)
            offset += 1 + length

        if not labels:
            presentation = "."
        else:
            presentation = ".".join(escape_label(label) for label in labels) + "."
        end = resume_at if resume_at is not None else offset
        return cls(presentation, buffer, resume_at), end
