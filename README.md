# CP/M-Oriented Z80 Emulator Core

## Overview
This repository focuses on a compact Z80 CPU core intended for experimenting with a CP/M environment. The goal is to provide a clean foundation for building a disk-backed CP/M emulator while keeping the code small enough to understand and extend. This is currently a simple command-line tool that executes Z80 binaries.

The current state includes:

- A CPU core that implements the full 8080 instruction set along with the Z80 rotate/bit (`CB`) and block transfer/compare (`ED`) groups required by CP/M system binaries, including recent additions such as `NEG`, `RETN`/`RETI`, interrupt mode selection (`IM n`), register transfers with `I`/`R`, the decimal rotate helpers `RRD`/`RLD`, and comprehensive IX/IY-prefixed arithmetic, load, and block instructions.
- A flat 64 KiB memory map suitable for early CP/M programs.
- A configurable disk subsystem with multi-drive support wired into BIOS trap handlers. Each mounted image tracks per-drive geometry, exposes CP/M-compatible drive tables, sector translation tables, and disk parameter headers for `SELDSK`, caches recently accessed sectors, persists allocation vector updates alongside directory metadata, reports detailed status codes so CP/M filesystem routines can react to I/O faults while the full FDC emulation evolves, and can infer geometry directly from optional CPMI headers without an explicit `--disk-geom` override while honouring any embedded directory-buffer sizing hints so BIOS workspace reservations line up with curated media.
- CP/M-style BIOS warm boot and BDOS entry points that translate console and file calls into host operations so simple programs can interact with the environment.
- BDOS trampolines covering sequential and random record file I/O alongside directory search helpers (`SEARCH FIRST`/`SEARCH NEXT`) so console utilities can enumerate the mounted disk images without custom host shims while remaining compatible with extent sequencing, and a reader-device shim so paper-tape oriented programs can ingest host data without custom BIOS patches.
- Console device shims that drive the standard console, punch, and list streams so host tooling can observe printer or paper-tape output without custom BIOS patches, now including BDOS console-status polling against host input readiness and BIOS port handlers so `--no-cpm-traps` runs still capture punch and list output.

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

### Inspecting BIOS disk tables

When one or more disk images are mounted, the emulator reserves a BIOS workspace near the top of memory so CP/M software can interrogate the host geometry without custom patches. The word stored at `0xF000` contains the pointer to the drive table, which in turn stores one disk parameter header (DPH) pointer per drive. The byte at `0xF002` reports how many of those entries correspond to mounted drives. Each DPH references a drive-specific disk parameter block (DPB), allocation vector, and scratch buffers. The layout matches the CP/M 2.2 conventions, so `SELDSK` returns the same DPH pointer and utilities can walk the table directly to discover the sector size, tracks-per-disk, and reserved-directory allocation for each image.

Words beginning at `0xF004` expose the default DMA address that each mounted drive advertises. Entries are encoded in little-endian order and contain zero for unmounted drives, the CP/M default (`0x0080`) when no override is available, or the value parsed from a CPMI header. BIOS or BDOS components can consult that table before issuing `SETDMA` so multi-profile disk sets preserve their intended buffering behaviour automatically.

Read-only host permissions now surface through both the BDOS read-only vector and individual directory entries, so CP/M utilities will display the `R/O` attribute and avoid attempting to reclaim allocation blocks on protected media. The BDOS attribute handler also honours the system and archive bits, ensuring tools such as `STAT` or `PIP` see the same protection state that the directory encodes. Host-backed file handles now treat any of those attribute bits as write barriers, so BDOS refuses to persist records once a file is marked protected, and attribute updates performed from CP/M are written back into the directory metadata whenever BDOS writes succeed, keeping the on-disk flags synchronised across reboots.

## Testing

Run the regression suite to ensure the CP/M system exercise and sample transient program both still behave, and that disk shims continue to match CP/M conventions:

```
make test
```

The harness first invokes a Python integration test that assembles `examples/hello.asm` on the fly, runs the resulting binary under the emulator, and asserts on the captured console output so the recent `ED`-prefixed flag fixes stay covered. It then assembles a transient program that exercises the BDOS random read/write helpers against a host-backed file, confirming that extent sequencing and random record updates stay synchronised with the new helpers. Dedicated regressions next stream curated bytes through BDOS function 3 via the `--reader` flag to ensure the tape-ingest path continues to track CLI plumbing, capture the punch and list devices into host-managed files, poll BDOS function `0x0B` to confirm console-status requests reflect host input readiness, and toggle the system/archive bits on a synthetic directory entry before inspecting the disk image to confirm the flags persist and now block host writes immediately. A CPMI-focused helper runs a transient program that reads the BIOS DMA table, while a companion C harness mounts a deliberately skewed disk image via the `disk.c` API to verify that directory enumeration continues to respect CP/M translation tables, that CPMI headers can steer the BIOS directory-buffer reservation, and that read-only hints embedded in headers seed the BDOS protection vector. Additional BIOS-port checks emit punch and list bytes with `--no-cpm-traps` enabled to ensure raw system images can still spool output into the configured capture files. After those targeted checks, the suite boots a curated CP/M 2.2 supervisor image with the emulator running in "no traps" mode. Successful runs show the `Hello from CP/M!` greeting, demonstrating that the command console trampolines are still wired correctly and that the expanded Z80 `ED` and IX/IY-prefixed helpers behave as expected in both a transient program and the supervisor stack itself.

After validating the supervisor image, the regression mounts a generated single-track diskette and runs `examples/bios_disk.bin`. That transient program issues BIOS `SELDSK`, `SETTRK`, `SETSEC`, `SETDMA`, and `READ` calls, confirming that the host-side FDC abstraction can service sector reads through the CP/M BIOS entry point. The BIOS shims now surface explicit `DISK_STATUS_*` return codes, so the program can distinguish "not ready" from "bad address" failures while echoing the sector payload through BDOS function 9.

Useful command-line options:

- `--cycles N` – Limit execution to `N` T-states before halting automatically (default: 1,000,000).
- `--disk DRIVE:path` – Mount a raw disk image on CP/M drive letter `DRIVE` (for example, `--disk B:disks/work.img`). The legacy shorthand `--disk-a` is still accepted for convenience.
- `--disk-geom DRIVE:spt:ssize[:tracks]` – Override the sectors per track, sector size in bytes, and optional track count before mounting a drive. Geometry defaults to 26×128-byte sectors when unspecified.
- `--disk-xlt DRIVE:map` – Provide a comma-separated list of 1-based sector numbers describing the BIOS translation order for each track (for example, `--disk-xlt A:1,5,9,13,17,21,25,2,6,...`).
- `--reader path` – Supply bytes for the BDOS reader device from `path` (use `-` to read from standard input).
- `--punch-out path` – Capture BDOS punch device output in `path` (use `-` to forward to the host standard output stream).
- `--list-out path` – Capture BDOS list device output in `path` (use `-` to continue emitting on the host standard error stream).
- `--load addr:file` – Copy an additional binary into memory at `addr` (for example, to preload a ROM or BIOS image). This flag
  may be repeated.
- `--load-hex path` – Ingest an Intel HEX file at the addresses encoded in the records, which is convenient for CP/M system
  distributions that ship in textual form.
- `--entry addr` – Override the initial program counter. When absent, it defaults to the transient program area (`0x0100`) if a
  standalone program is supplied.
- `--no-cpm-traps` – Disable the host-side BDOS and BIOS shims so that genuine system images can run their own handlers.

Because most peripheral behaviours and a handful of less common opcodes are still incomplete, running an arbitrary CP/M program can still terminate with an "Unimplemented opcode" message. This is intentional at this stage so the remaining gaps can be filled in incrementally.

### CPMI disk headers

When mounting images that begin with the 16-byte `CPMI` header, the emulator now extracts the encoded sector size, sectors per track, and optional track count automatically. The three highest bits of the track-count field act as feature flags: bit 31 indicates that the header is followed by a translation-table length and one byte per logical sector describing the BIOS skew order (using the familiar 1-based numbering), bit 30 signals that a 16-bit little-endian default DMA address is stored immediately after the header, bit 29 advertises a 16-bit little-endian directory-buffer size that the BIOS uses when reserving scratch space for that drive, and bit 28 appends a single-byte attribute hint whose low bits seed the BDOS read-only vector before any directory traversal occurs. Optional sections appear in that order, and the payload immediately following the header (and any optional sections) is treated as the first sector, so existing raw media remain compatible while curated images can embed geometry, translation, DMA, attribute, and BIOS workspace metadata for convenience.

### Exercising CP/M system images

To validate the IX/IY-prefixed instruction paths against real system software, the test suite stores base64-encoded CP/M 2.2 supervisor images sourced from the [z80pack](https://github.com/udo-munk/z80pack) reconstruction. The helper script invoked by `make test` decodes the CCP/BDOS bundle (`cpm.bin.base64`) and BIOS stub (`bios.bin.base64`) into temporary binaries, maps them at `0xDC00` and `0xFA00`, disables the host BDOS/BIOS shims, and executes the machine for 500,000 T-states. When the emulator completes without reporting unimplemented opcodes, the IX/IY-prefixed execution paths have been exercised against the full CP/M supervisor stack. Mount a disk image with `--disk A:path` to extend the experiment to filesystem and console integration as new device emulation features land.

## Next steps
- Surface BIOS-level console-status checks while running with `--no-cpm-traps` so system images that poll the Altair console ports observe host input readiness without requiring BDOS patches.
- Persist CPMI attribute hints when BDOS rewrites directory entries so seeded read-only bits survive across cold and warm boots.
- Add a supervisor-level regression that spools output via `PIP` or a similar utility to confirm the new port handlers capture punch and list traffic end-to-end.

Contributions that expand opcode coverage, improve testing, or add CP/M-compatible peripherals are welcome.
