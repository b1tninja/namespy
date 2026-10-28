from namespy.names import DomainName
from namespy.rdata import RData_NS


def test_domain_name_roundtrip_bytes_parse_from() -> None:
    original = DomainName("example.com")
    encoded = bytes(original)
    parsed, offset = DomainName.parse_from(encoded, 0)

    assert offset == len(encoded)
    # Wire form is always absolute; presentation form reflects the root terminator.
    assert str(parsed) == "example.com."
    assert parsed.is_absolute


def test_domain_name_eq_case_trailing_fqdn() -> None:
    a = DomainName("example.com")
    b = DomainName("EXAMPLE.COM.")
    c = "example.com."
    # Wire-form / FQDN equality: trailing root terminator is not significant
    # for ``==``; it only tells the resolver whether to assume a DNS suffix.
    assert a == b == c
    assert {a, b} == {a}  # same :class:`DomainName` hash
    # Equal presentation strings are not :func:`hash`-compatible with :class:`DomainName`.
    assert len({a, c}) == 2
    assert DomainName(".") == DomainName.root_label()
    assert DomainName("com") == "com."


def test_domain_name_is_absolute_tracks_root_terminator() -> None:
    assert DomainName("example.com.").is_absolute
    assert DomainName(".").is_absolute
    assert DomainName("").is_absolute
    assert not DomainName("example.com").is_absolute
    assert DomainName("example.com.").terminated  # alias


def test_domain_name_qualify_anchors_relative_at_root() -> None:
    relative = DomainName("example.com")
    qualified = relative.qualify()
    assert qualified.is_absolute
    assert str(qualified) == "example.com."
    assert qualified == relative  # equality is FQDN-based, so still equal


def test_domain_name_qualify_with_explicit_suffix() -> None:
    relative = DomainName("host")
    qualified = relative.qualify("corp.example.com")
    assert qualified.is_absolute
    assert str(qualified) == "host.corp.example.com."
    # Suffix may itself carry a root terminator — the result is the same.
    assert str(relative.qualify("corp.example.com.")) == "host.corp.example.com."
    # Suffix may be another :class:`DomainName`.
    assert str(relative.qualify(DomainName("corp.example.com."))) == "host.corp.example.com."


def test_domain_name_qualify_is_noop_on_absolute() -> None:
    absolute = DomainName("example.com.")
    # Trailing root terminator on the wire prevents any suffix from being assumed.
    assert absolute.qualify("corp.example.com") is absolute


def test_domain_name_bytes_wire_format_no_double_null() -> None:
    # RFC 1035 §3.1: the wire form is the sequence of length-prefixed labels
    # terminated by a single zero-length root label. The trailing ``.`` in
    # presentation form is the root terminator, not a label, and must not
    # produce a second ``\x00`` in the wire encoding — that one-byte shift
    # is what root servers see as a malformed QTYPE/QCLASS pair.
    assert bytes(DomainName("example.com.")) == b"\x07example\x03com\x00"
    assert bytes(DomainName("example.com")) == b"\x07example\x03com\x00"
    # The bare root encodes to just the zero-length terminator.
    assert bytes(DomainName(".")) == b"\x00"
    assert bytes(DomainName("")) == b"\x00"
    # Trailing-dot and non-trailing-dot forms encode identically.
    assert bytes(DomainName("example.com.")) == bytes(DomainName("example.com"))


def test_domain_name_eq_rdata_single_name() -> None:
    d = DomainName("ns1.example.com")
    r = RData_NS("ns1.example.com")
    assert d == r
    assert r == d
    assert hash(d) == hash(r)
