from __future__ import annotations

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
    return int(token, 0)


def assemble_hello(source_path: Path) -> bytes:
    lines = source_path.read_text().splitlines()
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
        elif directive == 'call':
            operand = tokens[1]
            instructions.append(('call', operand))
            program_counter += 3
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
        elif kind == 'call':
            _, operand = entry
            value = _resolve_operand(operand, labels, origin)
            output.append(0xCD)
            output.append(value & 0xFF)
            output.append((value >> 8) & 0xFF)
        elif kind == 'db':
            output.extend(entry[1])

    return bytes(output)


class HelloIntegrationTest(unittest.TestCase):
    def test_hello_program_runs_via_emulator(self) -> None:
        subprocess.run(["make"], cwd=REPO_ROOT, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        source_path = REPO_ROOT / "examples" / "hello.asm"
        program_bytes = assemble_hello(source_path)

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


if __name__ == "__main__":
    unittest.main()
