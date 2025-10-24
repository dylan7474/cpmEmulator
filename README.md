# CP/M-Oriented Z80 Emulator Core

## Overview
This repository focuses on a compact Z80 CPU core intended for experimenting with a CP/M environment. The goal is to provide a clean foundation for building a disk-backed CP/M emulator while keeping the code small enough to understand and extend. This is currently a simple command-line tool that executes Z80 binaries.

The current state includes:

- A CPU core that implements the full 8080 instruction set along with the Z80 rotate/bit (`CB`) and block transfer/compare (`ED`) groups required by CP/M system binaries, including recent additions such as `NEG`, `RETN`/`RETI`, interrupt mode selection (`IM n`), register transfers with `I`/`R`, the decimal rotate helpers `RRD`/`RLD`, and comprehensive IX/IY-prefixed arithmetic, load, and block instructions.
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

### Building the sample CP/M program

To quickly verify the emulator, the repository ships with a minimal CP/M-compatible program in `examples/hello.asm`. A matching
hex listing is converted into a runnable binary using Python. Generate it with:

```
make example
```

This creates `examples/hello.bin`, which loads at the CP/M transient program area and is used by the smoke tests below.

## Running
The emulator currently accepts a raw binary to load at the standard CP/M transient program area (`0x0100`). It executes instructions until a `HALT` is encountered or a cycle budget is exhausted.

```
./z80 path/to/program.bin
```

For the bundled sample program:

```
./z80 examples/hello.bin
```

The BDOS shim prints the greeting stored in the sample program and then returns to the host.

## Testing

Run the regression suite to ensure the CP/M system exercise and sample transient program both still behave:

```
make test
```

The harness first assembles the `examples/hello.bin` payload and then boots a curated CP/M 2.2 supervisor image with the emulator running in "no traps" mode. Successful runs show the `Hello from CP/M!` greeting, demonstrating that the command console trampolines are still wired correctly and that the expanded Z80 `ED` and IX/IY-prefixed helpers behave as expected in both a transient program and the supervisor stack itself.

Useful command-line options:

- `--cycles N` – Limit execution to `N` T-states before halting automatically (default: 1,000,000).
- `--disk-a path` – Mount a raw disk image for future BIOS/BDOS integration.
- `--load addr:file` – Copy an additional binary into memory at `addr` (for example, to preload a ROM or BIOS image). This flag
  may be repeated.
- `--load-hex path` – Ingest an Intel HEX file at the addresses encoded in the records, which is convenient for CP/M system
  distributions that ship in textual form.
- `--entry addr` – Override the initial program counter. When absent, it defaults to the transient program area (`0x0100`) if a
  standalone program is supplied.
- `--no-cpm-traps` – Disable the host-side BDOS and BIOS shims so that genuine system images can run their own handlers.

Because most peripheral behaviours and a handful of less common opcodes are still incomplete, running an arbitrary CP/M program can still terminate with an "Unimplemented opcode" message. This is intentional at this stage so the remaining gaps can be filled in incrementally.

### Exercising CP/M system images

To validate the IX/IY-prefixed instruction paths against real system software, the test suite stores base64-encoded CP/M 2.2 supervisor images sourced from the [z80pack](https://github.com/udo-munk/z80pack) reconstruction. The helper script invoked by `make test` decodes the CCP/BDOS bundle (`cpm.bin.base64`) and BIOS stub (`bios.bin.base64`) into temporary binaries, maps them at `0xDC00` and `0xFA00`, disables the host BDOS/BIOS shims, and executes the machine for 500,000 T-states. When the emulator completes without reporting unimplemented opcodes, the IX/IY-prefixed execution paths have been exercised against the full CP/M supervisor stack. Mount a disk image with `--disk-a` to extend the experiment to filesystem and console integration as new device emulation features land.

## Next steps
- Extend the CP/M regression to cover disk I/O once the FDC abstraction matures so BIOS sector routines stay exercised.
- Flesh out disk access helpers with sector caching, directory parsing, and optional disk geometry configuration, then wire them into the BDOS trampolines used by the console example.
- Replace the manual smoke test with an automated integration test that assembles the example program, runs it under the emulator, and asserts on the captured console output to prevent regressions in flag handling for recently added ED-prefixed opcodes.

Contributions that expand opcode coverage, improve testing, or add CP/M-compatible peripherals are welcome.
