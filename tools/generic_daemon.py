#!/usr/bin/env python3
"""Which KMIs a daemon carries, and the feed entry that offers it.

A pair's daemon embeds exactly the module built for its own target, so it is served to that one
device. That is the right default. The KernelSU half is also the only part of a payload that does
not have to be device-specific: `ksud` picks its kernel module from its own asset directory by KMI
at run time - `format!("{kmi}_kernelsu.ko")` - so a daemon carrying one module per KMI serves every
device whose KMI is in that set. The hand-built `ksud-samsung-*` bundles already work this way
(`ksud-samsung-android12-5.10-kdp` carries three KMIs), and this is the tool that reads that set
back out of a binary instead of trusting a name that only mentions one of them.

Two things are read, and neither is guessed at:

- **The asset table.** The loader indexes it by KMI, and it is a contiguous run of
  `<kmi>_kernelsu.ko` names in rodata. It is the only evidence that a daemon carries a module
  rather than having been built beside one - which is why the size of a daemon is not a proxy for
  it, and why a name like `ksud-samsung-android12-5.10-kdp` cannot be parsed for the set.
- **The version** the daemon was stamped with, from `pairs.daemon_version`, which is `ksud -V`'s own
  answer (`3.3.0 (uapi: 4)`). A generic daemon is rebuilt when a KernelSU release moves, so this is
  what a client needs to offer the manager that matches the kernel the run loads.

The feed this writes is a separate file, `support/kernelsu-generic.json`, and that is deliberate:
`support/targets-v3.json` is a released client contract that is rewritten in place by span edits,
and a device's entry in it has to keep naming exactly the artifact that device was tested with. A
generic daemon is a tier of its own, so it gets a file of its own, and the entries that are working
today are not touched by any of this.

The version is the one thing a generic daemon cannot always be asked for. The three hand-built
bundles already in this repository - `ksud-s25u-kdp` and its two siblings - predate the version
string `ksud -V` answers with, and read back as nothing at all; the self-test below pins that,
because it is the reason `--version` comes from the run's tag rather than from the binary. A daemon
built by the workflow below is stamped, so the two agree - but a publish that *needed* the binary
to answer would silently drop the field on an entry the app needs it for.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pairs import FLAVOURS, daemon_version  # noqa: E402

# `<kmi>_kernelsu.ko`, which is the name the loader builds for itself.
#
# Anchored on the name alone rather than on a path, because the asset table is a run of bare names.
# The pattern deliberately cannot match the neighbours that sit in the same table - `busybox`,
# `bootctl`, and `reboot_kernelsu.ko`, which has the `_kernelsu.ko` ending and no `-<major>.<minor>`
# before it - so the set read back is the module set and not everything in the directory.
ASSET = re.compile(rb"(?P<kmi>android\d+-\d+\.\d+(?:\.\d+)?)_kernelsu\.ko")

# The file the generic tier is served from. One name, imported by nothing else, so a run that writes
# it cannot be confused with a run that edits the released feed.
GENERIC_FEED = "support/kernelsu-generic.json"

# The KMIs each checked-in daemon carries, and the version it answers with, which is what the
# self-test holds the reader to. Both are read off the artifacts rather than from
# `kernelsu/README.md`, which describes the 5.10 bundle as embedding "the 5.10 module" while the
# binary carries three.
#
# `None` is a fact and not a gap in the fixture: the three hand-built bundles were built before the
# version string existed, so they answer with nothing. That is what makes the workflow pass
# `--version` from its tag instead of reading the entry's version out of the artifact, and a rebuilt
# generic daemon is expected to fill this in.
SELF_TEST = {
    "ksud-samsung-android12-5.10-kdp": (["android12-5.10", "android14-6.1", "android15-6.6"], None),
    "ksud-samsung-android14-6.1-kdp": (["android14-6.1", "android15-6.6"], None),
    "ksud-s25u-kdp": (["android15-6.6"], None),
    "ksud-next-pa3q-S938USQSCCZF9-kdp": (["android15-6.6"], "3.4.0"),
    "ksud-rsksu-pa3q-S938USQSCCZF9-kdp": (["android15-6.6"], "4.2.0-rc3"),
}


def carried(path: str) -> list[str]:
    """The KMIs a daemon's asset table offers, sorted. Empty when it carries no module of its own."""
    with open(path, "rb") as handle:
        data = handle.read()
    return sorted({match.group("kmi").decode() for match in ASSET.finditer(data)})


def _digest(path: str) -> tuple[int, str]:
    size = os.path.getsize(path)
    hash_ = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            hash_.update(block)
    return size, hash_.hexdigest()


def _as_list(text: str) -> list[str]:
    """A KMI set given either as JSON or as a comma-separated list, in the order written."""
    text = text.strip()
    if not text:
        return []
    if text.startswith("["):
        parsed = json.loads(text)
        if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
            raise SystemExit(f"not a KMI array: {text}")
        return parsed
    return [part.strip() for part in text.split(",") if part.strip()]


def verify(path: str, daemon: str, expect: list[str]) -> list[str]:
    """The KMI set, having checked it is the set the run built. Refuses rather than reports."""
    if not os.path.isfile(path):
        raise SystemExit(f"no daemon at {path}")

    kmis = carried(path)
    if not kmis:
        raise SystemExit(
            f"{daemon} carries no <kmi>_kernelsu.ko asset, so it cannot serve any device as a "
            "generic daemon. A daemon built with no module staged beside it has nothing to load."
        )
    if sorted(expect) != kmis:
        raise SystemExit(
            f"{daemon} carries {kmis}, but this run built {sorted(expect)}. The two are the same "
            "list or the entry would offer a device a KMI the daemon has no module for."
        )
    return kmis


def entry_for(
    repo: str,
    daemon: str,
    artifact: str,
    flavour: str,
    expect: list[str],
    url_prefix: str | None,
    version: str | None,
) -> dict:
    """The feed entry for one daemon, built from what the artifact itself says.

    Everything here is read rather than passed in where it can be, for the reason the pair jobs do
    the same: the KMI set is the daemon's own asset table, the version is the one it was stamped
    with, and the size and digest are of the file being published. A caller that disagrees with the
    binary is refused instead of overwriting the difference.
    """
    path = os.path.join(repo, artifact)
    kmis = verify(path, daemon, expect)

    # The tag the run built at first, the binary second, and normalised to the form the feed's
    # `version` field carries - `v3.4.0` and `3.4.0` are the same release and only the second is what
    # the app compares a manager's own version against. The pair publish reads the ref the same way
    # and for the same reason: a hand-built or older daemon often carries nothing readable, and an
    # entry that declares no version leaves the app falling back to the flavour's own release for the
    # manager it offers - which is only correct while the two happen to be the same number.
    stamped = (version or daemon_version(path) or "").lstrip("vV")
    if not stamped:
        raise SystemExit(
            f"{daemon} carries no readable version and none was given. A generic daemon is offered to "
            "devices that have no target entry of their own, so the manager the app installs cannot "
            "fall back to an entry's own release - the daemon or the run has to say what it was built "
            "from. Pass --version $(the run's tag)."
        )

    # A URL is never invented from scratch where one already exists: an entry that is already served
    # keeps its own prefix, which is what satisfies the client's allowed-repository rule.
    previous = _existing(repo, flavour)
    if url_prefix is None and previous is not None:
        url_prefix = previous["daemon"]["url"].rsplit("/", 1)[0]
    if url_prefix is None:
        raise SystemExit(
            "no --url-prefix and no entry to take one from. The first publish of a flavour has to "
            "name the repository its artifacts are served from."
        )

    size, sha256 = _digest(path)
    return {
        "flavor": flavour,
        "kmis": kmis,
        "daemon": {
            "url": f"{url_prefix.rstrip('/')}/kernelsu/{daemon}",
            "size": size,
            "sha256": sha256,
            "version": stamped,
        },
    }


def _read_feed(repo: str) -> dict:
    path = os.path.join(repo, GENERIC_FEED)
    if not os.path.isfile(path):
        return {"schemaVersion": 1, "generic": []}
    with open(path, encoding="utf-8") as handle:
        manifest = json.load(handle)
    manifest.setdefault("schemaVersion", 1)
    manifest.setdefault("generic", [])
    return manifest


def _existing(repo: str, flavour: str) -> dict | None:
    for entry in _read_feed(repo)["generic"]:
        if entry.get("flavor") == flavour:
            return entry
    return None


def publish(repo: str, entry: dict, dry_run: bool) -> str:
    """Replace this flavour's entry, keeping the file's order otherwise. Returns what changed."""
    manifest = _read_feed(repo)
    entries = manifest["generic"]
    flavours = [item.get("flavor") for item in entries]
    if entry["flavor"] in flavours:
        index = flavours.index(entry["flavor"])
        action = "republished" if entries[index] != entry else "unchanged"
        entries[index] = entry
    else:
        entries.append(entry)
        action = "added"

    # The order is the flavour table's, so a diff after a rebuild reads as the one entry that moved
    # rather than as the file being rewritten.
    order = list(FLAVOURS.values())
    entries.sort(key=lambda item: order.index(item["flavor"]) if item["flavor"] in order else len(order))

    text = json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
    path = os.path.join(repo, GENERIC_FEED)
    if not dry_run:
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
    return action


def self_test(repo: str = ".") -> int:
    """The reader, against the artifacts this checkout already carries."""
    failures = 0
    checks = 0
    artifacts = os.path.join(repo, "kernelsu")
    for daemon, (expected, expected_version) in SELF_TEST.items():
        path = os.path.join(artifacts, daemon)
        if not os.path.isfile(path):
            print(f"FAIL {daemon}: not in this checkout")
            failures += 1
            checks += 2
            continue

        checks += 1
        found = carried(path)
        if found == expected:
            print(f"ok   {daemon}: carries {', '.join(found)}")
        else:
            print(f"FAIL {daemon}: carries {found}, self-test says {expected}")
            failures += 1

        # Also the thing the feed needs and cannot invent. A daemon that answers with nothing is
        # publishable only because the run names the version; one that answers with something else is
        # a rebuild the entry would be pointing at the wrong manager for.
        checks += 1
        stamped = daemon_version(path)
        if stamped == expected_version:
            print(f"ok   {daemon}: version {stamped or '<none>'}")
        else:
            print(f"FAIL {daemon}: version {stamped or '<none>'}, self-test says {expected_version or '<none>'}")
            failures += 1

    # The names that share the asset table with the modules are not KMIs, and reading one as a KMI
    # would put a module in the entry that no device has.
    for name in (b"reboot_kernelsu.ko", b"busybox", b"bootctl"):
        checks += 1
        if ASSET.search(name):
            print(f"FAIL the asset pattern matches {name.decode()}")
            failures += 1

    if failures:
        print(f"self-test: {failures} of {checks} check(s) failed")
        return 1
    print(f"self-test: {len(SELF_TEST)} daemon(s), {checks} check(s), no non-module name matched")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--self-test", action="store_true", help="read the checked-in daemons and stop")
    parser.add_argument(
        "--check",
        action="store_true",
        help="only check that a built daemon carries the set this run built, and write no feed",
    )
    parser.add_argument("--repo", default=".", help="payload repository root")
    parser.add_argument("--daemon", help="file name the daemon is published under")
    parser.add_argument("--artifact", help="path to the built daemon")
    parser.add_argument(
        "--flavor",
        default="kernelsu",
        choices=sorted(FLAVOURS.values()),
        help="which project's KernelSU the daemon is",
    )
    parser.add_argument("--expect", default="", help="the KMI set the run built, as JSON or as a list")
    parser.add_argument("--version", help="the KernelSU ref or release, e.g. v3.4.0; taken from the binary when absent")
    parser.add_argument("--url-prefix", help="repository raw-URL prefix this run publishes under")
    parser.add_argument("--dry-run", action="store_true")
    arguments = parser.parse_args()

    if arguments.self_test:
        return self_test(arguments.repo)
    if not arguments.daemon or not arguments.artifact:
        parser.error("give --daemon and --artifact, or --self-test")

    if arguments.check:
        kmis = verify(os.path.join(arguments.repo, arguments.artifact), arguments.daemon, _as_list(arguments.expect))
        print(f"ok   {arguments.daemon}: carries {', '.join(kmis)}")
        return 0

    entry = entry_for(
        arguments.repo,
        arguments.daemon,
        arguments.artifact,
        arguments.flavor,
        _as_list(arguments.expect),
        arguments.url_prefix,
        arguments.version,
    )
    action = publish(arguments.repo, entry, arguments.dry_run)
    print(f"{action}: {entry['flavor']} carries {', '.join(entry['kmis'])} (version {entry['daemon']['version']})")
    print(f"  {entry['daemon']['url']} ({entry['daemon']['size']} bytes)")
    if arguments.dry_run:
        print("  (dry run: nothing written)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
