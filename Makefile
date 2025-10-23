# --- Makefile for Z80 Emulator ---
CC ?= gcc

TARGET := z80
SRCS := z80.c disk.c

CFLAGS ?= -Wall -Wextra -O2
CFLAGS += -std=c11

LDFLAGS ?=

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
