from __future__ import annotations

import struct
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def _strip_comment(line: str) -> str:
    return line.split(';', 1)[0].strip()


def _parse_db_operands(text: str) -> list[int]:
    values: list[int] = []
    i = 0
    length = len(text)
    while i < length:
        ch = text[i]
        if ch in {',', ' ', '\t'}:
            i += 1
            continue
        if ch == "'":
            end = text.find("'", i + 1)
            if end == -1:
                raise ValueError("Unterminated string literal in DB directive")
            for char in text[i + 1:end]:
                values.append(ord(char))
            i = end + 1
            continue
        start = i
        while i < length and text[i] not in {',', ' ', '\t'}:
            i += 1
        token = text[start:i]
        value = int(token, 0)
        if not 0 <= value <= 0xFF:
            raise ValueError(f"Byte literal out of range: {token}")
        values.append(value)
    return values


def _resolve_operand(token: str, labels: dict[str, int], origin: int) -> int:
    token = token.strip()
    if token in labels:
        return origin + labels[token]
    for operator in ('+', '-'):
        if operator in token:
            left, right = token.split(operator, 1)
            base = _resolve_operand(left, labels, origin)
            offset = _resolve_operand(right, labels, 0)
            return base + offset if operator == '+' else base - offset
    return int(token, 0)


def assemble_source_lines(lines: list[str]) -> bytes:
    origin: int | None = None
    program_counter = 0
    labels: dict[str, int] = {}
    instructions: list[tuple] = []

    for line in lines:
        text = _strip_comment(line)
        if not text:
            continue

        label: str | None = None
        if ':' in text:
            label_part, remainder = text.split(':', 1)
            label = label_part.strip()
            text = remainder.strip()
        if label:
            if origin is None:
                raise ValueError("ORG must precede label definitions")
            labels[label] = program_counter
        if not text:
            continue

        tokens = text.split()
        directive = tokens[0].lower()

        if directive == 'org':
            if len(tokens) != 2:
                raise ValueError("ORG expects a single operand")
            origin = int(tokens[1], 0)
            program_counter = 0
            instructions.append(('org', origin))
            continue

        if origin is None:
            raise ValueError("Encountered instructions before ORG directive")

        if directive == 'lxi':
            register = tokens[1].rstrip(',').lower()
            operand = tokens[2]
            instructions.append(('lxi', register, operand))
            program_counter += 3
        elif directive == 'mvi':
            register = tokens[1].rstrip(',').lower()
            operand = tokens[2]
            instructions.append(('mvi', register, operand))
            program_counter += 2
        elif directive == 'mov':
            dest = tokens[1].rstrip(',').lower()
            src = tokens[2].lower()
            instructions.append(('mov', dest, src))
            program_counter += 1
        elif directive == 'lda':
            operand = tokens[1]
            instructions.append(('lda', operand))
            program_counter += 3
        elif directive == 'sta':
            operand = tokens[1]
            instructions.append(('sta', operand))
            program_counter += 3
        elif directive == 'inx':
            register = tokens[1].lower()
            instructions.append(('inx', register))
            program_counter += 1
        elif directive == 'call':
            operand = tokens[1]
            instructions.append(('call', operand))
            program_counter += 3
        elif directive == 'jmp':
            operand = tokens[1]
            instructions.append(('jmp', operand))
            program_counter += 3
        elif directive == 'jnz':
            operand = tokens[1]
            instructions.append(('jnz', operand))
            program_counter += 3
        elif directive == 'ora':
            operand = tokens[1].lower()
            instructions.append(('ora', operand))
            program_counter += 1
        elif directive == 'out':
            operand = tokens[1]
            instructions.append(('out', operand))
            program_counter += 2
        elif directive == 'db':
            operand_text = text[text.lower().find('db') + 2:].strip()
            values = _parse_db_operands(operand_text)
            instructions.append(('db', values))
            program_counter += len(values)
        else:
            raise ValueError(f"Unsupported directive: {directive}")

    if origin is None:
        raise ValueError("No ORG directive encountered")

    output = bytearray()

    for entry in instructions:
        kind = entry[0]
        if kind == 'org':
            origin = entry[1]
            continue
        if kind == 'lxi':
            _, register, operand = entry
            opcode_map = {'b': 0x01, 'd': 0x11, 'h': 0x21, 'sp': 0x31}
            if register not in opcode_map:
                raise ValueError(f"Unsupported register pair for LXI: {register}")
            value = _resolve_operand(operand, labels, origin)
            output.append(opcode_map[register])
            output.append(value & 0xFF)
            output.append((value >> 8) & 0xFF)
        elif kind == 'mvi':
            _, register, operand = entry
            opcode_map = {
                'b': 0x06,
                'c': 0x0E,
                'd': 0x16,
                'e': 0x1E,
                'h': 0x26,
                'l': 0x2E,
                'm': 0x36,
                'a': 0x3E,
            }
            if register not in opcode_map:
                raise ValueError(f"Unsupported register for MVI: {register}")
            value = int(operand, 0)
            output.append(opcode_map[register])
            output.append(value & 0xFF)
        elif kind == 'mov':
            _, dest, src = entry
            register_codes = {
                'b': 0,
                'c': 1,
                'd': 2,
                'e': 3,
                'h': 4,
                'l': 5,
                'm': 6,
                'a': 7,
            }
            if dest not in register_codes or src not in register_codes:
                raise ValueError(f"Unsupported MOV operands: {dest}, {src}")
            opcode = 0x40 | (register_codes[dest] << 3) | register_codes[src]
            output.append(opcode)
        elif kind == 'lda':
            _, operand = entry
            value = _resolve_operand(operand, labels, origin)
            output.append(0x3A)
            output.append(value & 0xFF)
            output.append((value >> 8) & 0xFF)
        elif kind == 'sta':
            _, operand = entry
            value = _resolve_operand(operand, labels, origin)
            output.append(0x32)
            output.append(value & 0xFF)
            output.append((value >> 8) & 0xFF)
        elif kind == 'inx':
            _, register = entry
            opcode_map = {'b': 0x03, 'd': 0x13, 'h': 0x23, 'sp': 0x33}
            if register not in opcode_map:
                raise ValueError(f"Unsupported register pair for INX: {register}")
            output.append(opcode_map[register])
        elif kind == 'call':
            _, operand = entry
            value = _resolve_operand(operand, labels, origin)
            output.append(0xCD)
            output.append(value & 0xFF)
            output.append((value >> 8) & 0xFF)
        elif kind == 'jmp':
            _, operand = entry
            value = _resolve_operand(operand, labels, origin)
            output.append(0xC3)
            output.append(value & 0xFF)
            output.append((value >> 8) & 0xFF)
        elif kind == 'jnz':
            _, operand = entry
            value = _resolve_operand(operand, labels, origin)
            output.append(0xC2)
            output.append(value & 0xFF)
            output.append((value >> 8) & 0xFF)
        elif kind == 'ora':
            _, operand = entry
            register_codes = {
                'b': 0,
                'c': 1,
                'd': 2,
                'e': 3,
                'h': 4,
                'l': 5,
                'm': 6,
                'a': 7,
            }
            operand = operand.lower()
            if operand not in register_codes:
                raise ValueError(f"Unsupported register for ORA: {operand}")
            output.append(0xB0 | register_codes[operand])
        elif kind == 'out':
            _, operand = entry
            value = _resolve_operand(operand, labels, origin)
            if not 0 <= value <= 0xFF:
                raise ValueError(f"OUT operand out of range: {operand}")
            output.append(0xD3)
            output.append(value & 0xFF)
        elif kind == 'db':
            output.extend(entry[1])

    return bytes(output)


def assemble_source(path: Path) -> bytes:
    return assemble_source_lines(path.read_text().splitlines())


def _build_emulator() -> None:
    subprocess.run(["make"], cwd=REPO_ROOT, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def _format_db_lines(values: list[int]) -> list[str]:
    lines: list[str] = []
    for start in range(0, len(values), 16):
        chunk = values[start:start + 16]
        formatted = ", ".join(f"0x{value:02X}" for value in chunk)
        lines.append(f"    db {formatted}")
    return lines


class HelloIntegrationTest(unittest.TestCase):
    def test_hello_program_runs_via_emulator(self) -> None:
        _build_emulator()

        source_path = REPO_ROOT / "examples" / "hello.asm"
        program_bytes = assemble_source(source_path)

        with tempfile.TemporaryDirectory() as tmpdir:
            binary_path = Path(tmpdir) / "hello.bin"
            binary_path.write_bytes(program_bytes)

            result = subprocess.run(
                [str(REPO_ROOT / "z80"), str(binary_path)],
                cwd=REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, msg=f"Emulator exited with {result.returncode}:\n{result.stdout}")
        self.assertIn("Hello from CP/M!", result.stdout)
        self.assertIn("Execution halted", result.stdout)


class RandomRecordIoTest(unittest.TestCase):
    def test_random_record_io_round_trip(self) -> None:
        _build_emulator()

        block1 = [ord('T'), ord('E'), ord('S'), ord('T')] + [((i * 5) & 0xFF) for i in range(4, 128)]
        block2 = [ord('N'), ord('E'), ord('X'), ord('T')] + [((i * 7 + 1) & 0xFF) for i in range(4, 128)]
        read_buffer = [0x00] * 128

        fcb_setup = []
        fcb_setup.append("    mvi a, 0")
        fcb_setup.append("    sta 0x005C")
        for index, char in enumerate("RANDTEST"):
            value = ord(char)
            fcb_setup.append(f"    mvi a, 0x{value:02X}")
            fcb_setup.append(f"    sta 0x{0x005D + index:04X}")
        for index, char in enumerate("DAT"):
            value = ord(char)
            fcb_setup.append(f"    mvi a, 0x{value:02X}")
            fcb_setup.append(f"    sta 0x{0x0065 + index:04X}")
        for offset in (0x0068, 0x0069, 0x006A, 0x006B, 0x007C, 0x007D, 0x007E, 0x007F):
            fcb_setup.append("    mvi a, 0")
            fcb_setup.append(f"    sta 0x{offset:04X}")

        reset_random = []
        for offset in (0x0068, 0x0069, 0x006A, 0x006B, 0x007C, 0x007D, 0x007E, 0x007F):
            reset_random.append("    mvi a, 0")
            reset_random.append(f"    sta 0x{offset:04X}")

        assembly_lines: list[str] = ["org 0x0100", "start:"]
        assembly_lines.extend(fcb_setup)
        assembly_lines.extend(
            [
                "    lxi d, 0x005C",
                "    mvi c, 0x16",
                "    call 0x0005",
                "    lxi d, write_block1",
                "    mvi c, 0x1A",
                "    call 0x0005",
                "    lxi d, 0x005C",
                "    mvi c, 0x22",
                "    call 0x0005",
                "    lxi d, write_block2",
                "    mvi c, 0x1A",
                "    call 0x0005",
                "    lxi d, 0x005C",
                "    mvi c, 0x22",
                "    call 0x0005",
                "    lxi d, 0x005C",
                "    mvi c, 0x10",
                "    call 0x0005",
                "    lxi d, 0x005C",
                "    mvi c, 0x0F",
                "    call 0x0005",
            ]
        )
        assembly_lines.extend(reset_random)
        assembly_lines.extend(
            [
                "    lxi d, 0x005C",
                "    mvi c, 0x24",
                "    call 0x0005",
                "    lxi d, read_buffer",
                "    mvi c, 0x1A",
                "    call 0x0005",
                "    lxi d, 0x005C",
                "    mvi c, 0x21",
                "    call 0x0005",
                "    lda read_buffer",
                "    mov e, a",
                "    mvi c, 0x02",
                "    call 0x0005",
                "    lda read_buffer+1",
                "    mov e, a",
                "    mvi c, 0x02",
                "    call 0x0005",
                "    lda read_buffer+2",
                "    mov e, a",
                "    mvi c, 0x02",
                "    call 0x0005",
                "    lda read_buffer+3",
                "    mov e, a",
                "    mvi c, 0x02",
                "    call 0x0005",
                "    mvi e, 0x0D",
                "    mvi c, 0x02",
                "    call 0x0005",
                "    mvi e, 0x0A",
                "    mvi c, 0x02",
                "    call 0x0005",
                "    lxi d, 0x005C",
                "    mvi c, 0x10",
                "    call 0x0005",
                "    mvi c, 0x00",
                "    call 0x0005",
            ]
        )
        assembly_lines.append("write_block1:")
        assembly_lines.extend(_format_db_lines(block1))
        assembly_lines.append("write_block2:")
        assembly_lines.extend(_format_db_lines(block2))
        assembly_lines.append("read_buffer:")
        assembly_lines.extend(_format_db_lines(read_buffer))

        program_bytes = assemble_source_lines(assembly_lines)

        with tempfile.TemporaryDirectory() as tmpdir:
            binary_path = Path(tmpdir) / "random_io.bin"
            binary_path.write_bytes(program_bytes)

            result = subprocess.run(
                [str(REPO_ROOT / "z80"), str(binary_path)],
                cwd=REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )

        output_path = REPO_ROOT / "randtest.dat"
        try:
            self.assertEqual(result.returncode, 0, msg=f"Emulator exited with {result.returncode}:\n{result.stdout}")
            self.assertIn("TEST", result.stdout)
            self.assertTrue(output_path.exists(), "Expected host-backed file was not created")
            data = output_path.read_bytes()
            self.assertGreaterEqual(len(data), 256)
            self.assertEqual(list(data[:128]), block1)
            self.assertEqual(list(data[128:256]), block2)
        finally:
            if output_path.exists():
                output_path.unlink()


class ReaderDeviceTest(unittest.TestCase):
    def test_reader_device_consumes_stream(self) -> None:
        _build_emulator()

        payload = [ord(ch) for ch in "TAPE!"]

        assembly_lines = ["org 0x0100", "start:"]
        for _ in payload:
            assembly_lines.extend(
                [
                    "    mvi c, 0x03",
                    "    call 0x0005",
                    "    mov e, a",
                    "    mvi c, 0x02",
                    "    call 0x0005",
                ]
            )
        assembly_lines.extend(
            [
                "    mvi e, 0x0D",
                "    mvi c, 0x02",
                "    call 0x0005",
                "    mvi e, 0x0A",
                "    mvi c, 0x02",
                "    call 0x0005",
                "    mvi c, 0x00",
                "    call 0x0005",
            ]
        )

        program_bytes = assemble_source_lines(assembly_lines)

        with tempfile.TemporaryDirectory() as tmpdir:
            binary_path = Path(tmpdir) / "reader.bin"
            binary_path.write_bytes(program_bytes)
            reader_path = Path(tmpdir) / "tape.dat"
            reader_path.write_bytes(bytes(payload))

            result = subprocess.run(
                [str(REPO_ROOT / "z80"), "--reader", str(reader_path), str(binary_path)],
                cwd=REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, msg=f"Reader regression failed:\n{result.stdout}")
        self.assertIn("TAPE!", result.stdout)


class PunchListDeviceTest(unittest.TestCase):
    def test_punch_and_list_streams_are_captured(self) -> None:
        _build_emulator()

        punch_bytes = [ord(ch) for ch in "PUNCH"]
        list_bytes = [ord(ch) for ch in "LIST"]

        assembly_lines = ["org 0x0100", "start:"]
        for value in punch_bytes:
            assembly_lines.extend(
                [
                    f"    mvi e, 0x{value:02X}",
                    "    mvi c, 0x04",
                    "    call 0x0005",
                ]
            )
        for value in list_bytes:
            assembly_lines.extend(
                [
                    f"    mvi e, 0x{value:02X}",
                    "    mvi c, 0x05",
                    "    call 0x0005",
                ]
            )
        assembly_lines.extend(
            [
                "    mvi c, 0x00",
                "    call 0x0005",
            ]
        )

        program_bytes = assemble_source_lines(assembly_lines)

        with tempfile.TemporaryDirectory() as tmpdir:
            binary_path = Path(tmpdir) / "devices.bin"
            binary_path.write_bytes(program_bytes)
            punch_path = Path(tmpdir) / "punch.dat"
            list_path = Path(tmpdir) / "list.dat"

            result = subprocess.run(
                [
                    str(REPO_ROOT / "z80"),
                    "--punch-out",
                    str(punch_path),
                    "--list-out",
                    str(list_path),
                    str(binary_path),
                ],
                cwd=REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )

            punch_data = punch_path.read_bytes()
            list_data = list_path.read_bytes()

        self.assertEqual(result.returncode, 0, msg=f"Punch/list regression failed:\n{result.stdout}")
        self.assertEqual(punch_data, bytes(punch_bytes))
        self.assertEqual(list_data, bytes(list_bytes))


class ConsoleStatusTest(unittest.TestCase):
    def test_console_status_reports_idle_and_ready(self) -> None:
        _build_emulator()

        assembly_lines = [
            "org 0x0100",
            "start:",
            "    mvi c, 0x0B",
            "    call 0x0005",
            "    ora a",
            "    jnz ready",
            "    lxi d, idle_msg",
            "    jmp print_status",
            "ready:",
            "    lxi d, ready_msg",
            "print_status:",
            "    mvi c, 0x09",
            "    call 0x0005",
            "    mvi c, 0x00",
            "    call 0x0005",
            "idle_msg:",
            "    db 'IDLE', 0x0D, 0x0A, '$'",
            "ready_msg:",
            "    db 'READY', 0x0D, 0x0A, '$'",
        ]

        program_bytes = assemble_source_lines(assembly_lines)

        with tempfile.TemporaryDirectory() as tmpdir:
            binary_path = Path(tmpdir) / "console_status.bin"
            binary_path.write_bytes(program_bytes)

            idle_result = subprocess.run(
                [str(REPO_ROOT / "z80"), str(binary_path)],
                cwd=REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )

            ready_result = subprocess.run(
                [str(REPO_ROOT / "z80"), str(binary_path)],
                cwd=REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                input="X",
                check=False,
            )

        self.assertEqual(idle_result.returncode, 0, msg=idle_result.stdout)
        self.assertIn("IDLE", idle_result.stdout)

        self.assertEqual(ready_result.returncode, 0, msg=ready_result.stdout)
        self.assertIn("READY", ready_result.stdout)


class NoTrapDeviceCaptureTest(unittest.TestCase):
    def test_bios_ports_capture_spool_without_traps(self) -> None:
        _build_emulator()

        punch_values = [0x50, 0x55, 0x4E, 0x43, 0x48]
        list_values = [0x4C, 0x49, 0x53, 0x54]

        assembly_lines = [
            "org 0x0100",
            "start:",
        ]
        for value in punch_values:
            assembly_lines.extend([
                f"    mvi a, 0x{value:02X}",
                "    out 3",
            ])
        for value in list_values:
            assembly_lines.extend([
                f"    mvi a, 0x{value:02X}",
                "    out 5",
            ])
        assembly_lines.append("    db 0x76")

        program_bytes = assemble_source_lines(assembly_lines)

        with tempfile.TemporaryDirectory() as tmpdir:
            binary_path = Path(tmpdir) / "bios_ports.bin"
            binary_path.write_bytes(program_bytes)
            punch_path = Path(tmpdir) / "punch_ports.dat"
            list_path = Path(tmpdir) / "list_ports.dat"

            result = subprocess.run(
                [
                    str(REPO_ROOT / "z80"),
                    "--no-cpm-traps",
                    "--punch-out",
                    str(punch_path),
                    "--list-out",
                    str(list_path),
                    str(binary_path),
                ],
                cwd=REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )

            punch_data = punch_path.read_bytes()
            list_data = list_path.read_bytes()

        self.assertEqual(result.returncode, 0, msg=f"No-trap spool capture failed:\n{result.stdout}")
        self.assertEqual(punch_data, bytes(punch_values))
        self.assertEqual(list_data, bytes(list_values))


class FileAttributeTest(unittest.TestCase):
    def test_system_and_archive_bits_are_persisted(self) -> None:
        _build_emulator()

        logical = bytearray([0xE5] * (26 * 128))
        entry = bytearray(32)
        entry[0] = 0x00
        name = "ATTRTEST"
        for index, char in enumerate(name):
            entry[1 + index] = ord(char)
        ext_values = [0x53, 0x59, 0x53]
        for index, value in enumerate(ext_values):
            entry[9 + index] = value
        logical[:32] = entry

        program_lines = ["org 0x0100", "start:"]
        program_lines.extend(
            [
                "    mvi a, 0x01",
                "    sta 0x005C",
            ]
        )
        for offset, char in enumerate(name):
            program_lines.append(f"    mvi a, 0x{ord(char):02X}")
            program_lines.append(f"    sta 0x{0x005D + offset:04X}")
        attr_bytes = [0x53, 0xD9, 0xD3]
        for offset, value in enumerate(attr_bytes):
            program_lines.append(f"    mvi a, 0x{value:02X}")
            program_lines.append(f"    sta 0x{0x0065 + offset:04X}")
        program_lines.extend(
            [
                "    lxi d, 0x005C",
                "    mvi c, 0x1E",
                "    call 0x0005",
                "    mvi c, 0x00",
                "    call 0x0005",
            ]
        )

        program_bytes = assemble_source_lines(program_lines)

        disk_bytes = bytes(logical)

        with tempfile.TemporaryDirectory() as tmpdir:
            disk_path = Path(tmpdir) / "attr.img"
            disk_path.write_bytes(disk_bytes)

            binary_path = Path(tmpdir) / "setattr.bin"
            binary_path.write_bytes(program_bytes)

            result = subprocess.run(
                [str(REPO_ROOT / "z80"), "--disk", f"A:{disk_path}", str(binary_path)],
                cwd=REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )

            updated = disk_path.read_bytes()

        self.assertEqual(result.returncode, 0, msg=f"Attribute helper failed:\n{result.stdout}")
        entry_after = updated[:32]
        self.assertEqual(entry_after[9], 0x53)
        self.assertEqual(entry_after[10], 0xD9)
        self.assertEqual(entry_after[11], 0xD3)


class DiskTranslationTableTest(unittest.TestCase):
    def test_directory_enumeration_matches_translation(self) -> None:
        translation = [(i * 5) % 26 for i in range(26)]
        logical = bytearray([0xE5] * (26 * 128))

        def write_entry(slot: int, name: str, ext: str) -> None:
            offset = slot * 32
            logical[offset] = 0x00
            padded_name = name.upper().ljust(8)
            padded_ext = ext.upper().ljust(3)
            for index, char in enumerate(padded_name):
                logical[offset + 1 + index] = ord(char)
            for index, char in enumerate(padded_ext):
                logical[offset + 9 + index] = ord(char)

        write_entry(0, "alpha", "txt")
        write_entry(1, "gamma", "bin")

        disk_bytes = bytearray(len(logical))
        for logical_sector in range(26):
            physical = translation[logical_sector]
            start = logical_sector * 128
            disk_bytes[physical * 128:(physical + 1) * 128] = logical[start:start + 128]

        with tempfile.TemporaryDirectory() as tmpdir:
            image_path = Path(tmpdir) / "skewed.img"
            image_path.write_bytes(disk_bytes)

            binary_path = Path(tmpdir) / "disk_enum"
            compile_cmd = [
                "gcc",
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-I.",
                str(REPO_ROOT / "tests" / "disk_translation_test.c"),
                str(REPO_ROOT / "disk.c"),
                "-o",
                str(binary_path),
            ]
            subprocess.run(compile_cmd, cwd=REPO_ROOT, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            result = subprocess.run(
                [str(binary_path), str(image_path)],
                cwd=REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, msg=f"disk translation helper failed:\n{result.stdout}")
        self.assertIn("ALPHA.TXT", result.stdout)
        self.assertIn("GAMMA.BIN", result.stdout)


class DiskHeaderInferenceTest(unittest.TestCase):
    def test_header_infers_geometry(self) -> None:
        sector_size = 256
        sectors_per_track = 32
        track_count = 4
        dirbuf_size = 512

        header = bytearray()
        header.extend(b"CPMI")
        header.extend(struct.pack("<I", sector_size))
        header.extend(struct.pack("<I", sectors_per_track))
        header.extend(struct.pack("<I", track_count | 0x20000000 | 0x10000000))
        header.extend(struct.pack("<H", dirbuf_size))
        header.append(0x01)

        data = bytearray(sector_size * sectors_per_track * track_count)
        data[:sector_size] = bytes(range(sector_size))

        with tempfile.TemporaryDirectory() as tmpdir:
            image_path = Path(tmpdir) / "header.img"
            image_path.write_bytes(header + data)

            binary_path = Path(tmpdir) / "header_probe"
            compile_cmd = [
                "gcc",
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-I.",
                str(REPO_ROOT / "tests" / "disk_header_test.c"),
                str(REPO_ROOT / "disk.c"),
                "-o",
                str(binary_path),
            ]
            subprocess.run(compile_cmd, cwd=REPO_ROOT, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            result = subprocess.run(
                [str(binary_path), str(image_path)],
                cwd=REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, msg=f"disk header helper failed:\n{result.stdout}")


class DiskHeaderDmaIntegrationTest(unittest.TestCase):
    def test_header_reports_default_dma(self) -> None:
        _build_emulator()

        sector_size = 128
        sectors_per_track = 26
        track_count = 2
        default_dma = 0x0200
        dirbuf_size = 256

        header = bytearray()
        header.extend(b"CPMI")
        header.extend(struct.pack("<I", sector_size))
        header.extend(struct.pack("<I", sectors_per_track))
        header.extend(struct.pack("<I", track_count | 0x40000000 | 0x20000000 | 0x10000000))
        header.extend(struct.pack("<H", default_dma))
        header.extend(struct.pack("<H", dirbuf_size))
        header.append(0x01)

        data = bytearray(sector_size * sectors_per_track * track_count)

        assembly_lines = [
            "org 0x0100",
            "start:",
            "    mvi c, 0x09",
            "    lxi d, message",
            "    call 0x0005",
            "    lda 0xF005",
            "    call print_byte",
            "    lda 0xF004",
            "    call print_byte",
            "    mvi e, 0x0D",
            "    mvi c, 0x02",
            "    call 0x0005",
            "    mvi e, 0x0A",
            "    mvi c, 0x02",
            "    call 0x0005",
            "    mvi c, 0x00",
            "    call 0x0005",
            "print_byte:",
            "    sta temp_byte",
            "    db 0xE6, 0xF0",
            "    db 0x0F, 0x0F, 0x0F, 0x0F",
            "    call print_nibble",
            "    lda temp_byte",
            "    db 0xE6, 0x0F",
            "    call print_nibble",
            "    db 0xC9",
            "print_nibble:",
            "    mov e, a",
            "    mvi d, 0",
            "    lxi h, hex_table",
            "    db 0x19",
            "    mov a, m",
            "    mov e, a",
            "    mvi c, 0x02",
            "    call 0x0005",
            "    db 0xC9",
            "message:",
            "    db 'DMA=$'",
            "hex_table:",
            "    db '0123456789ABCDEF'",
            "temp_byte:",
            "    db 0x00",
        ]

        program_bytes = assemble_source_lines(assembly_lines)

        with tempfile.TemporaryDirectory() as tmpdir:
            image_path = Path(tmpdir) / "dma_header.img"
            image_path.write_bytes(header + data)

            binary_path = Path(tmpdir) / "print_dma.bin"
            binary_path.write_bytes(program_bytes)

            result = subprocess.run(
                [str(REPO_ROOT / "z80"), "--disk", f"A:{image_path}", str(binary_path)],
                cwd=REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, msg=f"DMA header probe failed:\n{result.stdout}")
        self.assertIn("DMA=0200", result.stdout)


if __name__ == "__main__":
    unittest.main()
