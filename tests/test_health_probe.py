from __future__ import annotations

import struct
import unittest

from common import ContractError
from health_probe import PT_INTERP, PT_LOAD, validate_static_amd64_elf


def elf_with_program_type(program_type: int) -> bytes:
    payload = bytearray(128)
    payload[:4] = b"\x7fELF"
    payload[4] = 2
    payload[5] = 1
    struct.pack_into("<H", payload, 16, 3)
    struct.pack_into("<H", payload, 18, 62)
    struct.pack_into("<I", payload, 20, 1)
    struct.pack_into("<Q", payload, 32, 64)
    struct.pack_into("<H", payload, 54, 56)
    struct.pack_into("<H", payload, 56, 1)
    struct.pack_into("<I", payload, 64, program_type)
    return bytes(payload)


class HealthProbeTests(unittest.TestCase):
    def test_static_amd64_probe_is_accepted(self) -> None:
        validate_static_amd64_elf(elf_with_program_type(PT_LOAD))

    def test_dynamic_probe_is_rejected(self) -> None:
        with self.assertRaisesRegex(ContractError, "statically linked"):
            validate_static_amd64_elf(elf_with_program_type(PT_INTERP))

    def test_probe_without_load_segment_is_rejected(self) -> None:
        with self.assertRaisesRegex(ContractError, "no loadable"):
            validate_static_amd64_elf(elf_with_program_type(4))


if __name__ == "__main__":
    unittest.main()
