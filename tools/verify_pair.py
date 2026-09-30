#!/usr/bin/env python3
"""What a pair has to be, checked once more immediately before it is published.

Two things, both of which a device's loader will decide again for itself, and both of which are
worth failing here instead of on somebody's phone:

- **The module names the target's release.** `vermagic` is what the loader compares, and these
  kernels run `CONFIG_MODULE_FORCE_LOAD=n`, so a module naming anything else is refused rather
  than merely discouraged. The pair job substitutes the release before building and asserts the
  result; this re-reads the file that is about to be committed.
- **The daemon has a complete ELF64 little-endian AArch64 executable header.** It is what the app
  downloads and runs on the device, so a wrong architecture or malformed header is worth catching
  here, where the message is legible. This checks the header, not every segment or section.

What is deliberately *not* checked is that the module appears verbatim inside the daemon. It does
not: the daemon carries it as a build asset rather than as a blob. The pairs running on devices
today fail that check too, which is how this was found.
"""

from __future__ import annotations

import argparse
import struct

ELF_MAGIC = b"\x7fELF"
EM_AARCH64 = 0xB7
ELF64_HEADER_SIZE = 64
ET_EXEC = 2
ET_DYN = 3


def vermagic(module: str) -> str:
    """The release a module claims, from the `vermagic=` string it carries."""
    with open(module, "rb") as handle:
        blob = handle.read()
    marker = b"vermagic="
    start = blob.find(marker)
    if start < 0:
        return ""
    return blob[start + len(marker):].split(b" ")[0].decode("ascii", "replace")


def is_aarch64_elf(path: str) -> bool:
    """Accept a complete ELF64 LE executable header, without executing the artifact.

    ET_DYN is valid for Android PIE executables. ET_REL is a module/object, not a daemon.
    Check the encoding before unpacking fields: treating an ELF32 or big-endian header as
    little-endian ELF64 can otherwise accept unrelated bytes as the architecture.
    """
    with open(path, "rb") as handle:
        head = handle.read(ELF64_HEADER_SIZE)
    if len(head) != ELF64_HEADER_SIZE or head[:4] != ELF_MAGIC:
        return False
    # EI_CLASS = ELFCLASS64, EI_DATA = ELFDATA2LSB, EI_VERSION = EV_CURRENT.
    if head[4:7] != b"\x02\x01\x01":
        return False
    elf_type, machine, version = struct.unpack_from("<HHI", head, 16)
    header_size = struct.unpack_from("<H", head, 52)[0]
    return (
        elf_type in (ET_EXEC, ET_DYN)
        and machine == EM_AARCH64
        and version == 1
        and header_size == ELF64_HEADER_SIZE
    )


def self_test() -> int:
    """Header regressions, using in-memory fixtures and no device or toolchain."""
    import unittest
    from unittest.mock import mock_open, patch

    def header(elf_type: int = ET_DYN) -> bytes:
        head = bytearray(ELF64_HEADER_SIZE)
        head[:7] = ELF_MAGIC + b"\x02\x01\x01"
        struct.pack_into("<HHI", head, 16, elf_type, EM_AARCH64, 1)
        struct.pack_into("<H", head, 52, ELF64_HEADER_SIZE)
        return bytes(head)

    class HeaderTests(unittest.TestCase):
        def check(self, blob: bytes, expected: bool) -> None:
            with patch("builtins.open", mock_open(read_data=blob)):
                self.assertEqual(is_aarch64_elf("fixture"), expected)

        def test_executable_types(self) -> None:
            for elf_type in (ET_EXEC, ET_DYN):
                with self.subTest(elf_type=elf_type):
                    self.check(header(elf_type), True)
            # A daemon has data after its header; do not reject that data as an oversized header.
            self.check(header() + b"payload", True)
            for elf_type in (0, 1, 4, 0xFFFF):
                with self.subTest(elf_type=elf_type):
                    self.check(header(elf_type), False)

        def test_truncation(self) -> None:
            for size in range(ELF64_HEADER_SIZE):
                with self.subTest(size=size):
                    self.check(header()[:size], False)

        def test_invalid_identification(self) -> None:
            for offset, value in ((0, 0), (4, 0), (4, 1), (5, 0), (5, 2), (6, 0), (6, 2)):
                with self.subTest(offset=offset, value=value):
                    head = bytearray(header())
                    head[offset] = value
                    self.check(bytes(head), False)

        def test_invalid_fields(self) -> None:
            for offset, encoding, value in (
                (18, "<H", 0), (18, "<H", 62),  # Missing machine, or x86-64.
                (20, "<I", 0), (20, "<I", 2),  # Unsupported ELF version.
                (52, "<H", 0), (52, "<H", 52), (52, "<H", 65),
            ):
                with self.subTest(offset=offset, value=value):
                    head = bytearray(header())
                    struct.pack_into(encoding, head, offset, value)
                    self.check(bytes(head), False)

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(HeaderTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module")
    parser.add_argument("--daemon")
    parser.add_argument("--release")
    parser.add_argument("--self-test", action="store_true", help="test ELF header validation in memory")
    arguments = parser.parse_args()
    if arguments.self_test:
        return self_test()
    if not all((arguments.module, arguments.daemon, arguments.release)):
        parser.error("--module, --daemon and --release are required unless --self-test is used")

    found = vermagic(arguments.module)
    print(f"module vermagic: {found or '(none)'}")
    if not found.startswith(arguments.release):
        raise SystemExit(f"the module claims {found!r}, which does not start with {arguments.release!r}")

    if not is_aarch64_elf(arguments.daemon):
        raise SystemExit(f"{arguments.daemon} has no valid ELF64 little-endian AArch64 executable header")

    print("daemon: a valid ELF64 little-endian AArch64 executable header")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
