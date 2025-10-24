# CP/M Emulator Agent Instructions

- Follow C11 conventions with 4-space indentation in C source files.
- When updating `z80.c`, keep opcode handlers factored into helpers and match documented Z80 flag behaviour; extend decoder coverage in grouped helpers rather than expanding the top-level `switch` inline.
- Prefer standard library calls and gate any platform-specific code behind `#ifdef` guards.
- Update `README.md` whenever CLI options, instruction coverage, or other user-facing workflows change, and keep the "Next steps" section in sync with the current opcode roadmap.
- Keep the README's CPMI header description in sync with any future tweaks to the disk-image inference rules so tooling stays aligned.
- Call out any newly supported Z80 prefixes or opcode families in both commit messages and documentation so follow-up tasks can focus on validation.
- Shell scripts must use `#!/usr/bin/env bash` and start with `set -euo pipefail`.
- Run `make` before committing changes that affect the emulator core.
- The CP/M regression mounts a generated disk image via `examples/bios_disk.bin`; keep the BIOS trap semantics compatible with that program when changing disk geometry or trap handlers.
- When expanding CP/M device coverage, prefer separate host streams (stdout/stderr/files) so the Python tests can capture console versus list/punch output independently.
