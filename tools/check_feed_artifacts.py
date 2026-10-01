#!/usr/bin/env python3
"""What a feed entry promises about an artifact, checked against the artifact itself.

Every entry in `support/targets-v3.json` and `support/kernelsu-generic.json` makes two promises a
device enforces after downloading: the byte `size`, and where one is declared, the `sha256`. A
client that finds either wrong refuses the artifact and roots nothing - which is the correct
behaviour and also the least legible place for the mismatch to surface. Nothing checked this
before the phone did.

Three failures this catches here rather than there:

- **The file behind a URL is gone or renamed.** The feed is rewritten by span edits and the
  artifacts move when a payload is republished; a URL that outlives its file is a download that
  404s at the moment of a root. An entry is checked by resolving the URL's repository path back
  into this checkout and reading that file.
- **The size drifted.** A rebuilt artifact with a feed that was not rewritten is the exact shape of
  every "it worked until the republish" report: the device validates the old size against the new
  bytes and refuses them.
- **The sha256 drifted.** Same story, one level stricter - and the level the entries rebuilt by CI
  actually declare. A digest that disagrees with the bytes is a wrong artifact at the URL, not a
  cosmetic problem.

What this deliberately does not do is decide which artifact a device *should* get. Matching model
and kernel version against `targets-v3.json` is the app's job and needs the device's own answers;
this only says that whatever an entry names is really there, and is really what the entry claims.

Only `raw.githubusercontent.com` URLs pointing at this repository's `main` branch resolve to a path
here. An entry naming a file in another repository is reported as unverifiable rather than passed:
silently skipping it would make the check look green over exactly the artifacts nobody can see.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass

# A URL the client fetches and this tool can read back out of the checkout: this repository's own
# `main` branch, resolved to the path underneath it. The owner is deliberately not fixed - the feed
# legitimately names three forks of the payload repository across its entries - but the repository
# name is, because a URL naming a different project cannot be read out of this checkout at all.
REPOSITORY = "Root-My-Galaxy-Payloads"
RAW_MAIN = re.compile(
    rf"^https://raw\.githubusercontent\.com/[^/]+/{REPOSITORY}/main/(?P<path>.+)$"
)

EXIT_OK = 0
EXIT_MISMATCH = 1
EXIT_BAD_INPUT = 2


@dataclass
class Finding:
    """One entry's artifact, and what is wrong with it if anything."""

    where: str
    artifact: str
    problem: str | None

    @property
    def ok(self) -> bool:
        return self.problem is None


def repo_path(url: str) -> str | None:
    """The checkout-relative path a feed URL names, or None when it names another repository."""

    match = RAW_MAIN.match(url)
    return match.group("path") if match else None


def sha256_of(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def check_artifact(root: str, where: str, kind: str, artifact: dict) -> Finding:
    """One artifact's declared size and digest, against the file its URL names."""

    name = f"{where}:{kind}"
    url = artifact.get("url", "")
    path = repo_path(url)
    if path is None:
        return Finding(name, url, "URL is not a main-branch file of this repository")

    full = os.path.join(root, path)
    if not os.path.isfile(full):
        return Finding(name, url, f"no file at {path}")

    size = os.path.getsize(full)
    declared = artifact.get("size")
    if declared is not None and size != declared:
        return Finding(name, url, f"size declared {declared}, file is {size}")

    declared_sha = artifact.get("sha256")
    if declared_sha is not None:
        actual = sha256_of(full)
        if actual != declared_sha:
            return Finding(
                name, url, f"sha256 declared {declared_sha[:16]}..., file is {actual[:16]}..."
            )

    return Finding(name, url, None)


def artifacts_of(entry: dict) -> list[tuple[str, dict]]:
    """The (kind, artifact) pairs one feed entry can carry."""

    found = []
    for kind in ("exploit", "kernelsu", "daemon"):
        artifact = entry.get(kind)
        if isinstance(artifact, dict):
            found.append((kind, artifact))
    return found


def check_feed(root: str, feed: str) -> list[Finding]:
    """Every artifact of every entry in one feed file."""

    with open(os.path.join(root, feed), encoding="utf-8") as handle:
        document = json.load(handle)

    findings: list[Finding] = []
    for entry in document.get("payloads") or document.get("generic") or []:
        where = entry.get("payloadId") or entry.get("flavor") or feed
        for kind, artifact in artifacts_of(entry):
            findings.append(check_artifact(root, where, kind, artifact))
    return findings


FEEDS = ("support/targets-v3.json", "support/kernelsu-generic.json")


def self_test() -> int:
    """The four ways an entry can be wrong, each caught, and a correct feed that is not."""

    import tempfile

    failures = 0

    def expect(label: str, finding: Finding, want_ok: bool, needle: str) -> None:
        nonlocal failures
        good = finding.ok == want_ok and (want_ok or needle in (finding.problem or ""))
        print(f"self-test: {label} {'ok' if good else 'FAILED'}")
        if not good:
            failures += 1

    with tempfile.TemporaryDirectory() as root:
        os.makedirs(os.path.join(root, "artifacts"), exist_ok=True)
        os.makedirs(os.path.join(root, "support"), exist_ok=True)

        body = b"\x7fELF" + b"\x00" * 60
        with open(os.path.join(root, "artifacts", "daemon"), "wb") as handle:
            handle.write(body)
        good_sha = hashlib.sha256(body).hexdigest()
        url = (
            "https://raw.githubusercontent.com/any-owner/"
            f"{REPOSITORY}/main/artifacts/daemon"
        )

        def feed_with(entry: dict) -> str:
            path = os.path.join(root, "support", "targets-v3.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"schemaVersion": 3, "payloads": [entry]}, handle)
            return "support/targets-v3.json"

        # A correct entry: right size, right digest, file where the URL says.
        feed = feed_with(
            {
                "payloadId": "ok",
                "models": ["SM-S931U"],
                "kernelVersions": ["6.6.98"],
                "kernelsu": {"url": url, "size": len(body), "sha256": good_sha},
            }
        )
        expect("correct entry passes", check_feed(root, feed)[0], True, "")

        # The file behind the URL is gone.
        feed = feed_with(
            {"payloadId": "gone", "kernelsu": {"url": url + "-moved", "size": len(body)}}
        )
        expect("missing file refused", check_feed(root, feed)[0], False, "no file at")

        # The size drifted - a rebuilt artifact with a stale feed entry.
        feed = feed_with({"payloadId": "drifted", "kernelsu": {"url": url, "size": 1}})
        expect("size drift refused", check_feed(root, feed)[0], False, "size declared 1")

        # The digest drifted.
        feed = feed_with(
            {
                "payloadId": "wrong-bytes",
                "kernelsu": {"url": url, "size": len(body), "sha256": "0" * 64},
            }
        )
        expect("sha256 drift refused", check_feed(root, feed)[0], False, "sha256 declared")

        # An artifact this checkout cannot read back is not silently passed.
        feed = feed_with(
            {
                "payloadId": "elsewhere",
                "kernelsu": {
                    "url": "https://raw.githubusercontent.com/someone/some-other-repo/main/ksud",
                    "size": 12,
                },
            }
        )
        expect(
            "foreign repository reported",
            check_feed(root, feed)[0],
            False,
            "not a main-branch file",
        )

    print(f"self-test: 5 case(s), {failures} failure(s)")
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        help="the payload repository checkout to read artifacts from",
    )
    parser.add_argument("--self-test", action="store_true", help="run the fixtures and exit")
    arguments = parser.parse_args()

    if arguments.self_test:
        return self_test()

    status = EXIT_OK
    for feed in FEEDS:
        if not os.path.isfile(os.path.join(arguments.root, feed)):
            print(f"error: no feed at {feed}", file=sys.stderr)
            return EXIT_BAD_INPUT
        findings = check_feed(arguments.root, feed)
        for finding in findings:
            if finding.ok:
                continue
            print(f"error: {finding.where} {finding.problem} ({finding.artifact})")
            status = EXIT_MISMATCH
        checked = sum(1 for finding in findings if finding.ok)
        print(f"{feed}: {checked}/{len(findings)} artifact(s) match their entry")
    return status


if __name__ == "__main__":
    sys.exit(main())
