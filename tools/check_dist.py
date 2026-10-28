#!/usr/bin/env python3
"""Assert that a built distribution actually contains what the code needs.

Run after ``python -m build``:

    python tools/check_dist.py dist/

Unit tests cannot cover this. ``aiodns/named.root`` is read through
:func:`importlib.resources.files`, so it is invisible to anything that imports
the source tree -- a wheel missing it installs cleanly, imports cleanly, passes
every test, and then fails on the first lookup with no starting point. It is
also named in ``.gitignore``, which is the file hatchling consults for default
excludes, so the omission is one config edit away at any time. The packaging
config therefore pins it as an artifact, and this script is what notices if that
pin is ever dropped.

Exits non-zero on the first problem so CI fails with a legible message.
"""

from __future__ import annotations

import glob
import os
import sys
import tarfile
import zipfile

#: Must appear in the wheel, because the resolver cannot start without them.
REQUIRED_IN_WHEEL = (
    "aiodns/__init__.py",
    "aiodns/named.root",
    "aiodns/py.typed",
)

#: Must appear in the sdist, or a build-from-source cannot reproduce them. The
#: root hints are the sharp edge here: they are gitignored, so the default
#: exclude list would otherwise drop them from the tarball too.
REQUIRED_IN_SDIST = (
    "aiodns/named.root",
    "aiodns/py.typed",
    "pyproject.toml",
    "README.md",
    "LICENSE",
)


def wheel_names(path: str) -> set[str]:
    """Paths inside a wheel, relative to its root."""
    with zipfile.ZipFile(path) as archive:
        return set(archive.namelist())


def sdist_names(path: str) -> set[str]:
    """Paths inside an sdist tarball, with the ``<name>-<version>/`` prefix gone.

    The prefix is stripped so the same probe strings work for both archive kinds;
    a tar member is otherwise never equal to the package-relative path anyone
    would write in a requirement.
    """
    with tarfile.open(path) as archive:
        out = set()
        for member in archive.getmembers():
            if not member.isfile():
                continue
            parts = member.name.split("/", 1)
            out.add(parts[1] if len(parts) == 2 else member.name)
        return out


def only(dist_dir: str, pattern: str, kind: str) -> str:
    """The single file in *dist_dir* matching *pattern*, or exit with a message."""
    found = sorted(glob.glob(os.path.join(dist_dir, pattern)))
    if len(found) != 1:
        fail(
            f"expected exactly one {kind} matching {pattern!r} in {dist_dir}, "
            f"found {len(found)}: {[os.path.basename(f) for f in found]}"
        )
    return found[0]


def fail(message: str) -> None:
    print(f"FAIL: {message}")
    sys.exit(1)


def main(argv: list[str]) -> int:
    dist_dir = argv[1] if len(argv) > 1 else "dist"
    if not os.path.isdir(dist_dir):
        fail(f"{dist_dir} is not a directory -- run `python -m build` first")

    wheel = only(dist_dir, "*.whl", "wheel")
    sdist = only(dist_dir, "*.tar.gz", "sdist")
    problems = 0

    wheel_files = wheel_names(wheel)
    for required in REQUIRED_IN_WHEEL:
        if required in wheel_files:
            print(f"  wheel  {required}")
        else:
            problems += 1
            print(f"  wheel  MISSING {required}")

    # A wheel without license text while the metadata declares a license is a
    # claim with nothing behind it; PEP 639 puts it under *.dist-info/licenses/.
    if any("LICENSE" in name.upper() for name in wheel_files):
        print("  wheel  license text present")
    else:
        problems += 1
        print("  wheel  MISSING license text (metadata declares one)")

    sdist_files = sdist_names(sdist)
    for required in REQUIRED_IN_SDIST:
        if required in sdist_files:
            print(f"  sdist  {required}")
        else:
            problems += 1
            print(f"  sdist  MISSING {required}")

    # The reverse check: a working tree that happens to hold build junk or a
    # generated .coverage file must not be swept into a release.
    for junk in (".coverage", "last_resolution.md", "dns.sql"):
        if junk in sdist_files or junk in wheel_files:
            problems += 1
            print(f"  both   LEAKED {junk}")

    if problems:
        fail(f"{problems} packaging problem(s) in {os.path.basename(wheel)}")
    print(f"OK: {os.path.basename(wheel)} and {os.path.basename(sdist)} are complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
