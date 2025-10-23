#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "disk.h"

#define MEMORY_SIZE 0x10000U
#define CP_M_LOAD_ADDRESS 0x0100U
#define DEFAULT_MAX_CYCLES 1000000ULL

typedef struct {
    uint8_t a;
    uint8_t f;
    uint8_t b;
    uint8_t c;
    uint8_t d;
    uint8_t e;
    uint8_t h;
    uint8_t l;
    uint8_t a_alt;
    uint8_t f_alt;
    uint8_t b_alt;
    uint8_t c_alt;
    uint8_t d_alt;
    uint8_t e_alt;
    uint8_t h_alt;
    uint8_t l_alt;
    uint16_t ix;
    uint16_t iy;
    uint16_t sp;
    uint16_t pc;
    uint8_t i;
    uint8_t r;
    bool iff1;
    bool iff2;
    bool halted;
} Z80;

typedef struct {
    Z80 cpu;
    uint8_t memory[MEMORY_SIZE];
    DiskDrive disk_a;
} Emulator;

static inline uint16_t z80_bc(const Z80 *cpu)
{
    return (uint16_t)((cpu->b << 8) | cpu->c);
}

static inline uint16_t z80_de(const Z80 *cpu)
{
    return (uint16_t)((cpu->d << 8) | cpu->e);
}

static inline uint16_t z80_hl(const Z80 *cpu)
{
    return (uint16_t)((cpu->h << 8) | cpu->l);
}

static inline void z80_set_bc(Z80 *cpu, uint16_t value)
{
    cpu->b = (uint8_t)((value >> 8) & 0xFFU);
    cpu->c = (uint8_t)(value & 0xFFU);
}

static inline void z80_set_de(Z80 *cpu, uint16_t value)
{
    cpu->d = (uint8_t)((value >> 8) & 0xFFU);
    cpu->e = (uint8_t)(value & 0xFFU);
}

static inline void z80_set_hl(Z80 *cpu, uint16_t value)
{
    cpu->h = (uint8_t)((value >> 8) & 0xFFU);
    cpu->l = (uint8_t)(value & 0xFFU);
}

static inline uint8_t memory_read8(const Emulator *emu, uint16_t address)
{
    return emu->memory[address];
}

static inline uint16_t memory_read16(const Emulator *emu, uint16_t address)
{
    uint16_t low = emu->memory[address];
    uint16_t high = emu->memory[(uint16_t)(address + 1U)];
    return (uint16_t)(low | (high << 8));
}

static inline void memory_write8(Emulator *emu, uint16_t address, uint8_t value)
{
    emu->memory[address] = value;
}

static inline void memory_write16(Emulator *emu, uint16_t address, uint16_t value)
{
    emu->memory[address] = (uint8_t)(value & 0xFFU);
    emu->memory[(uint16_t)(address + 1U)] = (uint8_t)((value >> 8) & 0xFFU);
}

static inline void set_flag(Z80 *cpu, uint8_t mask, bool value)
{
    if (value) {
        cpu->f |= mask;
    } else {
        cpu->f &= (uint8_t)~mask;
    }
}

static inline bool flag_set(const Z80 *cpu, uint8_t mask)
{
    return (cpu->f & mask) != 0U;
}

enum {
    FLAG_C = 0x01,
    FLAG_N = 0x02,
    FLAG_PV = 0x04,
    FLAG_H = 0x10,
    FLAG_Z = 0x40,
    FLAG_S = 0x80
};

static bool parity_even(uint8_t value)
{
    value ^= (uint8_t)(value >> 4);
    value ^= (uint8_t)(value >> 2);
    value ^= (uint8_t)(value >> 1);
    return (value & 0x01U) == 0U;
}

static void z80_reset(Z80 *cpu)
{
    memset(cpu, 0, sizeof(*cpu));
    cpu->sp = 0xFFFFU;
    cpu->pc = 0x0000U;
}

static uint8_t *decode_register(Z80 *cpu, uint8_t index)
{
    switch (index) {
    case 0:
        return &cpu->b;
    case 1:
        return &cpu->c;
    case 2:
        return &cpu->d;
    case 3:
        return &cpu->e;
    case 4:
        return &cpu->h;
    case 5:
        return &cpu->l;
    case 6:
        return NULL;
    case 7:
        return &cpu->a;
    default:
        return NULL;
    }
}

static int z80_alu_add(Z80 *cpu, uint8_t value)
{
    uint16_t result = (uint16_t)(cpu->a + value);
    set_flag(cpu, FLAG_C, result > 0xFFU);
    set_flag(cpu, FLAG_H, ((cpu->a & 0x0FU) + (value & 0x0FU)) > 0x0FU);
    set_flag(cpu, FLAG_Z, (uint8_t)result == 0U);
    set_flag(cpu, FLAG_S, (result & 0x80U) != 0U);
    set_flag(cpu, FLAG_PV, (~(cpu->a ^ value) & (cpu->a ^ (uint8_t)result) & 0x80U) != 0U);
    set_flag(cpu, FLAG_N, false);
    cpu->a = (uint8_t)result;
    return 4;
}

static int z80_alu_sub(Z80 *cpu, uint8_t value)
{
    uint16_t result = (uint16_t)(cpu->a - value);
    set_flag(cpu, FLAG_C, cpu->a < value);
    set_flag(cpu, FLAG_H, (cpu->a & 0x0FU) < (value & 0x0FU));
    set_flag(cpu, FLAG_Z, (uint8_t)result == 0U);
    set_flag(cpu, FLAG_S, (result & 0x80U) != 0U);
    set_flag(cpu, FLAG_PV, ((cpu->a ^ value) & (cpu->a ^ (uint8_t)result) & 0x80U) != 0U);
    set_flag(cpu, FLAG_N, true);
    cpu->a = (uint8_t)result;
    return 4;
}

static uint8_t fetch8(Emulator *emu)
{
    uint8_t value = memory_read8(emu, emu->cpu.pc);
    emu->cpu.pc = (uint16_t)(emu->cpu.pc + 1U);
    return value;
}

static uint16_t fetch16(Emulator *emu)
{
    uint16_t value = memory_read16(emu, emu->cpu.pc);
    emu->cpu.pc = (uint16_t)(emu->cpu.pc + 2U);
    return value;
}

static int execute_ld_r_n(Emulator *emu, uint8_t opcode)
{
    uint8_t index = (opcode >> 3) & 0x07U;
    uint8_t *reg = decode_register(&emu->cpu, index);
    uint8_t value = fetch8(emu);

    if (reg != NULL) {
        *reg = value;
        return 7;
    }

    memory_write8(emu, z80_hl(&emu->cpu), value);
    return 10;
}

static int execute_ld_r_r(Emulator *emu, uint8_t opcode)
{
    uint8_t dest_index = (opcode >> 3) & 0x07U;
    uint8_t src_index = opcode & 0x07U;
    uint8_t *dest = decode_register(&emu->cpu, dest_index);
    uint8_t *src = decode_register(&emu->cpu, src_index);

    if (dest_index == 6U) {
        uint16_t addr = z80_hl(&emu->cpu);
        if (src_index == 6U) {
            uint8_t value = memory_read8(emu, addr);
            memory_write8(emu, addr, value);
        } else if (src != NULL) {
            memory_write8(emu, addr, *src);
        }
        return 7;
    }

    if (src_index == 6U) {
        if (dest != NULL) {
            *dest = memory_read8(emu, z80_hl(&emu->cpu));
        }
        return 7;
    }

    if (dest != NULL && src != NULL) {
        *dest = *src;
        return 4;
    }

    return 4;
}

static int execute_inc_r(Emulator *emu, uint8_t opcode)
{
    uint8_t index = (opcode >> 3) & 0x07U;
    uint8_t value;

    if (index == 6U) {
        uint16_t addr = z80_hl(&emu->cpu);
        value = memory_read8(emu, addr);
        value = (uint8_t)(value + 1U);
        memory_write8(emu, addr, value);
        set_flag(&emu->cpu, FLAG_Z, value == 0U);
        set_flag(&emu->cpu, FLAG_S, (value & 0x80U) != 0U);
        set_flag(&emu->cpu, FLAG_PV, value == 0x80U);
        set_flag(&emu->cpu, FLAG_N, false);
        set_flag(&emu->cpu, FLAG_H, (value & 0x0FU) == 0x00U);
        return 11;
    }

    uint8_t *reg = decode_register(&emu->cpu, index);
    if (reg != NULL) {
        value = (uint8_t)(*reg + 1U);
        set_flag(&emu->cpu, FLAG_Z, value == 0U);
        set_flag(&emu->cpu, FLAG_S, (value & 0x80U) != 0U);
        set_flag(&emu->cpu, FLAG_PV, value == 0x80U);
        set_flag(&emu->cpu, FLAG_N, false);
        set_flag(&emu->cpu, FLAG_H, ((*reg & 0x0FU) + 1U) > 0x0FU);
        *reg = value;
    }

    return 4;
}

static int execute_dec_r(Emulator *emu, uint8_t opcode)
{
    uint8_t index = (opcode >> 3) & 0x07U;
    uint8_t value;

    if (index == 6U) {
        uint16_t addr = z80_hl(&emu->cpu);
        value = memory_read8(emu, addr);
        value = (uint8_t)(value - 1U);
        memory_write8(emu, addr, value);
        set_flag(&emu->cpu, FLAG_Z, value == 0U);
        set_flag(&emu->cpu, FLAG_S, (value & 0x80U) != 0U);
        set_flag(&emu->cpu, FLAG_PV, value == 0x7FU);
        set_flag(&emu->cpu, FLAG_N, true);
        set_flag(&emu->cpu, FLAG_H, (value & 0x0FU) == 0x0FU);
        return 11;
    }

    uint8_t *reg = decode_register(&emu->cpu, index);
    if (reg != NULL) {
        value = (uint8_t)(*reg - 1U);
        set_flag(&emu->cpu, FLAG_Z, value == 0U);
        set_flag(&emu->cpu, FLAG_S, (value & 0x80U) != 0U);
        set_flag(&emu->cpu, FLAG_PV, value == 0x7FU);
        set_flag(&emu->cpu, FLAG_N, true);
        set_flag(&emu->cpu, FLAG_H, (*reg & 0x0FU) == 0U);
        *reg = value;
    }

    return 4;
}

static int z80_step(Emulator *emu)
{
    if (emu->cpu.halted) {
        return 4;
    }

    uint16_t pc = emu->cpu.pc;
    uint8_t opcode = fetch8(emu);

    switch (opcode) {
    case 0x00: /* NOP */
        return 4;
    case 0x01:
        z80_set_bc(&emu->cpu, fetch16(emu));
        return 10;
    case 0x02:
        memory_write8(emu, z80_bc(&emu->cpu), emu->cpu.a);
        return 7;
    case 0x03:
        z80_set_bc(&emu->cpu, (uint16_t)(z80_bc(&emu->cpu) + 1U));
        return 6;
    case 0x06: /* LD B,n */
    case 0x0E: /* LD C,n */
    case 0x16: /* LD D,n */
    case 0x1E: /* LD E,n */
    case 0x26: /* LD H,n */
    case 0x2E: /* LD L,n */
    case 0x36: /* LD (HL),n */
    case 0x3E: /* LD A,n */
        return execute_ld_r_n(emu, opcode);
    case 0x04:
    case 0x0C:
    case 0x14:
    case 0x1C:
    case 0x24:
    case 0x2C:
    case 0x34:
    case 0x3C:
        return execute_inc_r(emu, opcode);
    case 0x05:
    case 0x0D:
    case 0x15:
    case 0x1D:
    case 0x25:
    case 0x2D:
    case 0x35:
    case 0x3D:
        return execute_dec_r(emu, opcode);
    case 0x07: { /* RLCA */
        uint8_t carry = (uint8_t)((emu->cpu.a >> 7) & 0x01U);
        emu->cpu.a = (uint8_t)((emu->cpu.a << 1) | carry);
        set_flag(&emu->cpu, FLAG_C, carry != 0U);
        set_flag(&emu->cpu, FLAG_N, false);
        set_flag(&emu->cpu, FLAG_H, false);
        set_flag(&emu->cpu, FLAG_Z, emu->cpu.a == 0U);
        set_flag(&emu->cpu, FLAG_S, (emu->cpu.a & 0x80U) != 0U);
        set_flag(&emu->cpu, FLAG_PV, parity_even(emu->cpu.a));
        return 4;
    }
    case 0x09:
        z80_set_hl(&emu->cpu, (uint16_t)(z80_hl(&emu->cpu) + z80_bc(&emu->cpu)));
        set_flag(&emu->cpu, FLAG_N, false);
        set_flag(&emu->cpu, FLAG_H, false);
        return 11;
    case 0x0A:
        emu->cpu.a = memory_read8(emu, z80_bc(&emu->cpu));
        return 7;
    case 0x0F: { /* RRCA */
        uint8_t carry = (uint8_t)(emu->cpu.a & 0x01U);
        emu->cpu.a = (uint8_t)((emu->cpu.a >> 1) | (carry << 7));
        set_flag(&emu->cpu, FLAG_C, carry != 0U);
        set_flag(&emu->cpu, FLAG_N, false);
        set_flag(&emu->cpu, FLAG_H, false);
        set_flag(&emu->cpu, FLAG_Z, emu->cpu.a == 0U);
        set_flag(&emu->cpu, FLAG_S, (emu->cpu.a & 0x80U) != 0U);
        set_flag(&emu->cpu, FLAG_PV, parity_even(emu->cpu.a));
        return 4;
    }
    case 0x32: { /* LD (nn),A */
        uint16_t addr = fetch16(emu);
        memory_write8(emu, addr, emu->cpu.a);
        return 13;
    }
    case 0x3A: { /* LD A,(nn) */
        uint16_t addr = fetch16(emu);
        emu->cpu.a = memory_read8(emu, addr);
        return 13;
    }
    case 0x3F: { /* CCF */
        bool carry = flag_set(&emu->cpu, FLAG_C);
        set_flag(&emu->cpu, FLAG_C, !carry);
        set_flag(&emu->cpu, FLAG_H, carry);
        set_flag(&emu->cpu, FLAG_N, false);
        return 4;
    }
    case 0x76:
        emu->cpu.halted = true;
        return 4;
    case 0x78:
    case 0x79:
    case 0x7A:
    case 0x7B:
    case 0x7C:
    case 0x7D:
    case 0x7E:
    case 0x7F:
    case 0x40:
    case 0x41:
    case 0x42:
    case 0x43:
    case 0x44:
    case 0x45:
    case 0x46:
    case 0x47:
    case 0x48:
    case 0x49:
    case 0x4A:
    case 0x4B:
    case 0x4C:
    case 0x4D:
    case 0x4E:
    case 0x4F:
    case 0x50:
    case 0x51:
    case 0x52:
    case 0x53:
    case 0x54:
    case 0x55:
    case 0x56:
    case 0x57:
    case 0x58:
    case 0x59:
    case 0x5A:
    case 0x5B:
    case 0x5C:
    case 0x5D:
    case 0x5E:
    case 0x5F:
    case 0x60:
    case 0x61:
    case 0x62:
    case 0x63:
    case 0x64:
    case 0x65:
    case 0x66:
    case 0x67:
    case 0x68:
    case 0x69:
    case 0x6A:
    case 0x6B:
    case 0x6C:
    case 0x6D:
    case 0x6E:
    case 0x6F:
    case 0x70:
    case 0x71:
    case 0x72:
    case 0x73:
    case 0x74:
    case 0x75:
    case 0x77:
        return execute_ld_r_r(emu, opcode);
    case 0x80:
    case 0x81:
    case 0x82:
    case 0x83:
    case 0x84:
    case 0x85:
    case 0x86:
    case 0x87: {
        uint8_t index = opcode & 0x07U;
        uint8_t value;
        if (index == 6U) {
            value = memory_read8(emu, z80_hl(&emu->cpu));
        } else {
            uint8_t *reg = decode_register(&emu->cpu, index);
            value = reg != NULL ? *reg : 0U;
        }
        return z80_alu_add(&emu->cpu, value);
    }
    case 0x90:
    case 0x91:
    case 0x92:
    case 0x93:
    case 0x94:
    case 0x95:
    case 0x96:
    case 0x97: {
        uint8_t index = opcode & 0x07U;
        uint8_t value;
        if (index == 6U) {
            value = memory_read8(emu, z80_hl(&emu->cpu));
        } else {
            uint8_t *reg = decode_register(&emu->cpu, index);
            value = reg != NULL ? *reg : 0U;
        }
        return z80_alu_sub(&emu->cpu, value);
    }
    case 0xC3: { /* JP nn */
        uint16_t addr = fetch16(emu);
        emu->cpu.pc = addr;
        return 10;
    }
    case 0xC9: { /* RET */
        uint16_t addr = memory_read16(emu, emu->cpu.sp);
        emu->cpu.sp = (uint16_t)(emu->cpu.sp + 2U);
        emu->cpu.pc = addr;
        return 10;
    }
    case 0xCD: { /* CALL nn */
        uint16_t addr = fetch16(emu);
        emu->cpu.sp = (uint16_t)(emu->cpu.sp - 2U);
        memory_write16(emu, emu->cpu.sp, emu->cpu.pc);
        emu->cpu.pc = addr;
        return 17;
    }
    default:
        fprintf(stderr, "Unimplemented opcode 0x%02X at PC=0x%04X\n", opcode, pc);
        exit(EXIT_FAILURE);
    }
}

static void emulator_init(Emulator *emu)
{
    memset(emu, 0, sizeof(*emu));
    z80_reset(&emu->cpu);
}

static size_t load_binary(Emulator *emu, const char *path, uint16_t address)
{
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
        return 0U;
    }

    size_t offset = address;
    size_t total = 0U;
    while (offset < MEMORY_SIZE) {
        size_t chunk = fread(&emu->memory[offset], 1U, MEMORY_SIZE - offset, fp);
        if (chunk == 0U) {
            break;
        }
        offset += chunk;
        total += chunk;
    }

    fclose(fp);
    return total;
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [--cycles N] [--disk-a path] program.bin\n", prog);
}

static uint64_t parse_cycles(const char *value)
{
    char *end = NULL;
    unsigned long long parsed = strtoull(value, &end, 0);
    if (value[0] == '\0' || (end != NULL && *end != '\0')) {
        fprintf(stderr, "Invalid cycle count '%s'\n", value);
        exit(EXIT_FAILURE);
    }
    return parsed;
}

int main(int argc, char **argv)
{
    Emulator emu;
    emulator_init(&emu);

    const char *program_path = NULL;
    const char *disk_path = NULL;
    uint64_t max_cycles = DEFAULT_MAX_CYCLES;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--cycles") == 0) {
            if (i + 1 >= argc) {
                usage(argv[0]);
                return EXIT_FAILURE;
            }
            max_cycles = parse_cycles(argv[++i]);
        } else if (strcmp(argv[i], "--disk-a") == 0) {
            if (i + 1 >= argc) {
                usage(argv[0]);
                return EXIT_FAILURE;
            }
            disk_path = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return EXIT_SUCCESS;
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "Unknown option '%s'\n", argv[i]);
            usage(argv[0]);
            return EXIT_FAILURE;
        } else {
            program_path = argv[i];
        }
    }

    if (program_path == NULL) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (disk_path != NULL) {
        if (disk_mount(&emu.disk_a, disk_path, 26U, 128U) != 0) {
            fprintf(stderr, "Failed to mount disk image '%s'\n", disk_path);
            return EXIT_FAILURE;
        }
    }

    size_t loaded = load_binary(&emu, program_path, CP_M_LOAD_ADDRESS);
    if (loaded == 0U) {
        fprintf(stderr, "No bytes loaded from '%s'\n", program_path);
        disk_unmount(&emu.disk_a);
        return EXIT_FAILURE;
    }

    emu.cpu.pc = CP_M_LOAD_ADDRESS;

    uint64_t cycles = 0ULL;
    while (!emu.cpu.halted && cycles < max_cycles) {
        cycles += (uint64_t)z80_step(&emu);
    }

    printf("Execution halted after %" PRIu64 " cycles at PC=0x%04X\n", cycles, emu.cpu.pc);

    if (disk_is_mounted(&emu.disk_a)) {
        disk_unmount(&emu.disk_a);
    }

    return EXIT_SUCCESS;
}
