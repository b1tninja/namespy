"""The package's public surface must be importable and complete.

Two distinct failures this guards, both of which are invisible until someone
installs the wheel:

1. ``__all__`` naming something that was never imported. ``from namespy import *``
   then raises AttributeError, and a static checker flags it but nothing in a
   test-only suite would.
2. The circular import between ``namespy/__init__.py`` and ``namespy.resolver``.
   Both the resolver and the server do ``from . import enable_path_mtu_discovery``
   while ``__init__`` re-exports them, so the re-export block has to sit *below*
   that function's definition. Move it up and the package fails to import at all.

``importlib.reload`` is the point: a test that merely imports ``namespy`` proves
nothing about rebuild order, because the module object is cached from the first
test that touched it.
"""

from __future__ import annotations

import importlib
import pkgutil
import sys

import pytest

import namespy


def test_all_names_resolve():
    missing = [name for name in namespy.__all__ if not hasattr(namespy, name)]
    assert missing == []


def test_all_has_no_duplicates():
    # Ordering is left to ruff's RUF022, which sorts __all__ isort-style: SCREAMING
    # constants first, then CamelCase classes, then dunders and lowercase names.
    # Asserting `__all__ == sorted(__all__)` here would fight that rule, since
    # plain string sort puts "__author__" and "IP_MTU" somewhere ruff rejects.
    assert len(namespy.__all__) == len(set(namespy.__all__))


def test_star_import_yields_the_declared_surface():
    namespace: dict[str, object] = {}
    exec("from namespy import *", namespace)  # noqa: S102
    delivered = {name for name in namespace if not name.startswith("__")}
    declared = set(namespy.__all__) - {"__author__", "__version__"}
    assert delivered == declared


def test_package_reimports_cleanly():
    """Reload the whole package, exercising the __init__/resolver import order.

    The assertion that matters is the last one: the resolver holds its own
    reference to ``enable_path_mtu_discovery``, taken from the package while the
    package was still executing. If the re-export block ever moves above that
    function's definition, the binding is missing at that moment and this is where
    it surfaces -- not as a clean ImportError at the top of ``__init__``.
    """
    saved = dict(sys.modules)
    try:
        for module in [m for m in sys.modules if m.split(".")[0] == "namespy"]:
            del sys.modules[module]
        package = importlib.import_module("namespy")
        resolver = importlib.import_module("namespy.resolver")
        server = importlib.import_module("namespy.server")
        assert package.__version__
        assert issubclass(package.RecursiveResolver, package.Resolver)
        assert package.RecursiveResolver is not package.Resolver
        assert resolver.enable_path_mtu_discovery is package.enable_path_mtu_discovery
        assert server.enable_path_mtu_discovery is package.enable_path_mtu_discovery
    finally:
        sys.modules.clear()
        sys.modules.update(saved)


def test_every_submodule_imports_alone():
    """Each submodule must import standalone, not only as a side effect of __init__."""
    for info in pkgutil.iter_modules(namespy.__path__):
        importlib.import_module(f"namespy.{info.name}")


@pytest.mark.parametrize("name", ["Resolver", "RecursiveResolver", "DomainName", "DnsPacket"])
def test_headline_names_are_reachable(name):
    assert getattr(namespy, name) is not None
