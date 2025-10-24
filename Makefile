# --- Makefile for Z80 Emulator ---
CC ?= gcc
PYTHON ?= python3

TARGET := z80
SRCS := z80.c disk.c

EXAMPLE_HEX := examples/hello.hex
EXAMPLE_BIN := examples/hello.bin

.ONESHELL:

CFLAGS ?= -Wall -Wextra -O2
CFLAGS += -std=c11

LDFLAGS ?=

all: $(TARGET)

.PHONY: example test cpm-system-test
example: $(EXAMPLE_BIN)

test: cpm-system-test

cpm-system-test: $(TARGET)
	./scripts/run_cpm_system_image_test.sh

$(EXAMPLE_BIN): $(EXAMPLE_HEX)
	$(PYTHON) - <<'PY'
	from pathlib import Path
	hex_path = Path("$(EXAMPLE_HEX)")
	bin_path = Path("$(EXAMPLE_BIN)")
	hex_text = "".join(hex_path.read_text().split())
	bin_path.write_bytes(bytes.fromhex(hex_text))
	print(f"Wrote {bin_path} ({bin_path.stat().st_size} bytes)")
	PY

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)

clean:
	rm -f $(TARGET) $(EXAMPLE_BIN)

.PHONY: all clean example test cpm-system-test
