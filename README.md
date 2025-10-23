# CP/M-Oriented Z80 Emulator Core

## Overview
This repository now focuses on a compact Z80 CPU core intended for experimenting with a CP/M environment. The goal is to provide a clean foundation for building a disk-backed CP/M emulator while keeping the code small enough to understand and extend. The previous ZX Spectrum specific video, audio, and tape systems have been removed in favour of a simple command-line tool that executes Z80 binaries.

The current state includes:

- A CPU core that implements the full 8080 instruction set along with the Z80 rotate/bit (`CB`) and block transfer/compare (`ED`) groups required by CP/M system binaries.
- A flat 64 KiB memory map suitable for early CP/M programs.
- A stubbed disk drive abstraction that can read or write raw sector data from a disk image, paving the way for future BDOS and BIOS emulation.
- CP/M-style BIOS warm boot and BDOS entry points that translate console and file calls into host operations so simple programs can interact with the environment.

Expect to extend the instruction coverage and peripheral behaviour as CP/M functionality is implemented.

## Prerequisites
- A C11-compatible compiler (tested with `gcc`).
- `make`.

Run `./configure` to confirm the prerequisites are available on your system.

## Building
```
./configure
make
```

The build produces the `z80` executable in the project root.

## Running
The emulator currently accepts a raw binary to load at the standard CP/M transient program area (`0x0100`). It executes instructions until a `HALT` is encountered or a cycle budget is exhausted.

```
./z80 path/to/program.bin
```

Useful command-line options:

- `--cycles N` – Limit execution to `N` T-states before halting automatically (default: 1,000,000).
- `--disk-a path` – Mount a raw disk image for future BIOS/BDOS integration.

Because index (`DD`/`FD`) prefixes and most peripheral behaviours are still stubbed out, running an arbitrary CP/M program can still terminate with an "Unimplemented opcode" message. This is intentional at this stage so missing instructions can be filled in incrementally.

## Next steps
- Broaden the instruction decoder until CP/M system programs (such as the CCP and BDOS) execute correctly.
- Flesh out disk access helpers with sector caching, directory parsing, and optional disk geometry configuration.

Contributions that expand opcode coverage, improve testing, or add CP/M-compatible peripherals are welcome.
