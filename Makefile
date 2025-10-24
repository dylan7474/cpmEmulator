# --- Makefile for Z80 Emulator ---
CC ?= gcc
PYTHON ?= python3

TARGET := z80
SRCS := z80.c disk.c

HEX_SOURCES := $(wildcard examples/*.hex)
BINARIES := $(HEX_SOURCES:.hex=.bin)

.ONESHELL:

CFLAGS ?= -Wall -Wextra -O2
CFLAGS += -std=c11

LDFLAGS ?=

all: $(TARGET)

.PHONY: example test cpm-system-test integration-test
example: $(BINARIES)

test: integration-test cpm-system-test

integration-test: $(TARGET)
	$(PYTHON) -m unittest tests.test_integration

cpm-system-test: $(TARGET)
	./scripts/run_cpm_system_image_test.sh

examples/%.bin: examples/%.hex
	$(PYTHON) -c "from pathlib import Path; import sys; hex_path = Path(sys.argv[1]); bin_path = Path(sys.argv[2]); hex_text = ''.join(hex_path.read_text().split()); bin_path.write_bytes(bytes.fromhex(hex_text)); print(f'Wrote {bin_path} ({bin_path.stat().st_size} bytes)')" "$<" "$@"

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)

clean:
	rm -f $(TARGET) $(BINARIES)

.PHONY: all clean example test cpm-system-test integration-test
