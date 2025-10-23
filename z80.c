#include <ctype.h>
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
#define CP_M_BIOS_ENTRY 0x0000U
#define CP_M_BDOS_ENTRY 0x0005U
#define CP_M_DEFAULT_DMA 0x0080U
#define CP_M_MAX_OPEN_FILES 16

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
    uint8_t im;
    bool iff1;
    bool iff2;
    bool halted;
} Z80;

typedef struct {
    bool in_use;
    bool read_only;
    uint16_t fcb_address;
    FILE *fp;
} CpmFileHandle;

typedef struct {
    Z80 cpu;
    uint8_t memory[MEMORY_SIZE];
    DiskDrive disk_a;
    uint16_t dma_address;
    CpmFileHandle files[CP_M_MAX_OPEN_FILES];
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

static inline uint16_t z80_af(const Z80 *cpu)
{
    return (uint16_t)((cpu->a << 8) | cpu->f);
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

static inline void z80_set_af(Z80 *cpu, uint16_t value)
{
    cpu->a = (uint8_t)((value >> 8) & 0xFFU);
    cpu->f = (uint8_t)(value & 0xFFU);
}

static inline uint16_t z80_get_pair(const Z80 *cpu, uint8_t index)
{
    switch (index & 0x03U) {
    case 0:
        return z80_bc(cpu);
    case 1:
        return z80_de(cpu);
    case 2:
        return z80_hl(cpu);
    default:
        return cpu->sp;
    }
}

static inline void z80_set_pair(Z80 *cpu, uint8_t index, uint16_t value)
{
    switch (index & 0x03U) {
    case 0:
        z80_set_bc(cpu, value);
        break;
    case 1:
        z80_set_de(cpu, value);
        break;
    case 2:
        z80_set_hl(cpu, value);
        break;
    default:
        cpu->sp = value;
        break;
    }
}

static inline uint16_t z80_get_stack_pair(const Z80 *cpu, uint8_t index)
{
    switch (index & 0x03U) {
    case 0:
        return z80_bc(cpu);
    case 1:
        return z80_de(cpu);
    case 2:
        return z80_hl(cpu);
    default:
        return z80_af(cpu);
    }
}

static inline void z80_set_stack_pair(Z80 *cpu, uint8_t index, uint16_t value)
{
    switch (index & 0x03U) {
    case 0:
        z80_set_bc(cpu, value);
        break;
    case 1:
        z80_set_de(cpu, value);
        break;
    case 2:
        z80_set_hl(cpu, value);
        break;
    default:
        z80_set_af(cpu, value);
        break;
    }
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

static uint16_t cpm_pop16(Emulator *emu)
{
    uint16_t value = memory_read16(emu, emu->cpu.sp);
    emu->cpu.sp = (uint16_t)(emu->cpu.sp + 2U);
    return value;
}

static void cpm_return_from_call(Emulator *emu)
{
    uint16_t ret = cpm_pop16(emu);
    emu->cpu.pc = ret;
}

static void cpm_reset_fcb_position(Emulator *emu, uint16_t fcb_address)
{
    memory_write8(emu, (uint16_t)(fcb_address + 12U), 0U);
    memory_write8(emu, (uint16_t)(fcb_address + 32U), 0U);
    memory_write8(emu, (uint16_t)(fcb_address + 33U), 0U);
    memory_write8(emu, (uint16_t)(fcb_address + 34U), 0U);
    memory_write8(emu, (uint16_t)(fcb_address + 35U), 0U);
}

static bool cpm_parse_fcb_filename(const Emulator *emu, uint16_t fcb_address, char *buffer, size_t size)
{
    if (buffer == NULL || size == 0U) {
        return false;
    }

    char name[9];
    char ext[4];

    for (size_t i = 0; i < 8; ++i) {
        name[i] = (char)memory_read8(emu, (uint16_t)(fcb_address + 1U + i));
    }
    name[8] = '\0';

    size_t name_end = 8U;
    while (name_end > 0U && (name[name_end - 1U] == ' ' || name[name_end - 1U] == '\0')) {
        --name_end;
    }
    name[name_end] = '\0';
    for (size_t i = 0; i < name_end; ++i) {
        name[i] = (char)tolower((unsigned char)name[i]);
    }

    for (size_t i = 0; i < 3; ++i) {
        ext[i] = (char)memory_read8(emu, (uint16_t)(fcb_address + 9U + i));
    }
    ext[3] = '\0';

    size_t ext_end = 3U;
    while (ext_end > 0U && (ext[ext_end - 1U] == ' ' || ext[ext_end - 1U] == '\0')) {
        --ext_end;
    }
    ext[ext_end] = '\0';
    for (size_t i = 0; i < ext_end; ++i) {
        ext[i] = (char)tolower((unsigned char)ext[i]);
    }

    if (name_end == 0U) {
        return false;
    }

    int written;
    if (ext_end > 0U) {
        written = snprintf(buffer, size, "%s.%s", name, ext);
    } else {
        written = snprintf(buffer, size, "%s", name);
    }

    if (written < 0) {
        return false;
    }

    return (size_t)written < size;
}

static CpmFileHandle *cpm_find_file(Emulator *emu, uint16_t fcb_address)
{
    for (size_t i = 0; i < CP_M_MAX_OPEN_FILES; ++i) {
        if (emu->files[i].in_use && emu->files[i].fcb_address == fcb_address) {
            return &emu->files[i];
        }
    }

    return NULL;
}

static CpmFileHandle *cpm_allocate_file(Emulator *emu, uint16_t fcb_address)
{
    CpmFileHandle *existing = cpm_find_file(emu, fcb_address);
    if (existing != NULL) {
        return existing;
    }

    for (size_t i = 0; i < CP_M_MAX_OPEN_FILES; ++i) {
        if (!emu->files[i].in_use) {
            emu->files[i].in_use = true;
            emu->files[i].fcb_address = fcb_address;
            emu->files[i].read_only = false;
            emu->files[i].fp = NULL;
            return &emu->files[i];
        }
    }

    return NULL;
}

static void cpm_release_file(CpmFileHandle *handle)
{
    if (handle == NULL) {
        return;
    }

    if (handle->fp != NULL) {
        fclose(handle->fp);
        handle->fp = NULL;
    }

    handle->in_use = false;
    handle->read_only = false;
    handle->fcb_address = 0U;
}

static void cpm_close_all_files(Emulator *emu)
{
    for (size_t i = 0; i < CP_M_MAX_OPEN_FILES; ++i) {
        if (emu->files[i].in_use) {
            if (emu->files[i].fp != NULL) {
                fclose(emu->files[i].fp);
                emu->files[i].fp = NULL;
            }
            emu->files[i].in_use = false;
            emu->files[i].read_only = false;
            emu->files[i].fcb_address = 0U;
        }
    }
}

static void cpm_advance_record(Emulator *emu, uint16_t fcb_address)
{
    uint8_t current = memory_read8(emu, (uint16_t)(fcb_address + 32U));
    current = (uint8_t)(current + 1U);
    memory_write8(emu, (uint16_t)(fcb_address + 32U), current);

    if (current == 0U) {
        uint8_t extend = memory_read8(emu, (uint16_t)(fcb_address + 12U));
        extend = (uint8_t)(extend + 1U);
        memory_write8(emu, (uint16_t)(fcb_address + 12U), extend);
    }
}

static uint8_t cpm_bdos_open_file(Emulator *emu, uint16_t fcb_address)
{
    char filename[32];
    if (!cpm_parse_fcb_filename(emu, fcb_address, filename, sizeof(filename))) {
        return 0xFFU;
    }

    CpmFileHandle *handle = cpm_allocate_file(emu, fcb_address);
    if (handle == NULL) {
        return 0xFFU;
    }

    if (handle->fp != NULL) {
        fclose(handle->fp);
        handle->fp = NULL;
    }

    FILE *fp = fopen(filename, "r+b");
    if (fp == NULL) {
        fp = fopen(filename, "rb");
        if (fp == NULL) {
            handle->in_use = false;
            handle->fcb_address = 0U;
            return 0xFFU;
        }
        handle->read_only = true;
    } else {
        handle->read_only = false;
    }

    handle->fp = fp;
    cpm_reset_fcb_position(emu, fcb_address);
    (void)fseek(fp, 0L, SEEK_SET);
    return 0x00U;
}

static uint8_t cpm_bdos_close_file(Emulator *emu, uint16_t fcb_address)
{
    CpmFileHandle *handle = cpm_find_file(emu, fcb_address);
    if (handle == NULL || handle->fp == NULL) {
        return 0xFFU;
    }

    fflush(handle->fp);
    fclose(handle->fp);
    handle->fp = NULL;
    handle->in_use = false;
    handle->read_only = false;
    handle->fcb_address = 0U;
    return 0x00U;
}

static uint8_t cpm_bdos_make_file(Emulator *emu, uint16_t fcb_address)
{
    char filename[32];
    if (!cpm_parse_fcb_filename(emu, fcb_address, filename, sizeof(filename))) {
        return 0xFFU;
    }

    CpmFileHandle *handle = cpm_allocate_file(emu, fcb_address);
    if (handle == NULL) {
        return 0xFFU;
    }

    if (handle->fp != NULL) {
        fclose(handle->fp);
        handle->fp = NULL;
    }

    FILE *fp = fopen(filename, "w+b");
    if (fp == NULL) {
        handle->in_use = false;
        handle->fcb_address = 0U;
        return 0xFFU;
    }

    handle->fp = fp;
    handle->read_only = false;
    cpm_reset_fcb_position(emu, fcb_address);
    return 0x00U;
}

static uint8_t cpm_bdos_delete_file(Emulator *emu, uint16_t fcb_address)
{
    char filename[32];
    if (!cpm_parse_fcb_filename(emu, fcb_address, filename, sizeof(filename))) {
        return 0xFFU;
    }

    CpmFileHandle *handle = cpm_find_file(emu, fcb_address);
    if (handle != NULL) {
        cpm_release_file(handle);
    }

    return (remove(filename) == 0) ? 0x00U : 0xFFU;
}

static uint8_t cpm_bdos_read_sequential(Emulator *emu, uint16_t fcb_address)
{
    CpmFileHandle *handle = cpm_find_file(emu, fcb_address);
    if (handle == NULL || handle->fp == NULL) {
        return 0xFFU;
    }

    uint8_t buffer[128];
    size_t read = fread(buffer, 1U, sizeof(buffer), handle->fp);
    if (read == 0U) {
        return 0x01U;
    }

    for (size_t i = 0; i < read; ++i) {
        memory_write8(emu, (uint16_t)(emu->dma_address + i), buffer[i]);
    }
    for (size_t i = read; i < sizeof(buffer); ++i) {
        memory_write8(emu, (uint16_t)(emu->dma_address + i), 0x1AU);
    }

    cpm_advance_record(emu, fcb_address);

    return 0x00U;
}

static uint8_t cpm_bdos_write_sequential(Emulator *emu, uint16_t fcb_address)
{
    CpmFileHandle *handle = cpm_find_file(emu, fcb_address);
    if (handle == NULL || handle->fp == NULL || handle->read_only) {
        return 0xFFU;
    }

    uint8_t buffer[128];
    for (size_t i = 0; i < sizeof(buffer); ++i) {
        buffer[i] = memory_read8(emu, (uint16_t)(emu->dma_address + i));
    }

    size_t written = fwrite(buffer, 1U, sizeof(buffer), handle->fp);
    if (written != sizeof(buffer)) {
        return 0x01U;
    }

    fflush(handle->fp);
    cpm_advance_record(emu, fcb_address);
    return 0x00U;
}

static uint8_t cpm_bdos_rename_file(Emulator *emu, uint16_t fcb_address)
{
    char source[32];
    char dest[32];

    if (!cpm_parse_fcb_filename(emu, fcb_address, source, sizeof(source))) {
        return 0xFFU;
    }

    if (!cpm_parse_fcb_filename(emu, (uint16_t)(fcb_address + 16U), dest, sizeof(dest))) {
        return 0xFFU;
    }

    CpmFileHandle *src_handle = cpm_find_file(emu, fcb_address);
    if (src_handle != NULL) {
        cpm_release_file(src_handle);
    }

    return (rename(source, dest) == 0) ? 0x00U : 0xFFU;
}

static uint8_t cpm_bdos_set_dma(Emulator *emu, uint16_t address)
{
    emu->dma_address = address;
    return 0x00U;
}

static void cpm_bdos_output_string(Emulator *emu, uint16_t address)
{
    for (;;) {
        uint8_t value = memory_read8(emu, address);
        if (value == '$') {
            break;
        }

        putchar((int)value);
        address = (uint16_t)(address + 1U);
    }

    fflush(stdout);
}

static void cpm_bdos_read_line(Emulator *emu, uint16_t address)
{
    uint8_t max_len = memory_read8(emu, address);
    uint16_t offset = (uint16_t)(address + 2U);
    uint8_t count = 0U;

    for (;;) {
        int ch = getchar();
        if (ch == EOF || ch == '\n' || ch == '\r') {
            break;
        }

        if (count < max_len) {
            memory_write8(emu, (uint16_t)(offset + count), (uint8_t)ch);
            ++count;
        }
    }

    memory_write8(emu, (uint16_t)(address + 1U), count);
    memory_write8(emu, (uint16_t)(offset + count), '\r');
}

static int handle_bios_call(Emulator *emu)
{
    emu->cpu.halted = true;
    return 11;
}

static int handle_bdos_call(Emulator *emu)
{
    uint8_t function = emu->cpu.c;
    uint16_t de = z80_de(&emu->cpu);
    uint8_t return_code = 0x00U;
    bool store_return = true;

    switch (function) {
    case 0x00:
        emu->cpu.halted = true;
        break;
    case 0x01: {
        int ch = getchar();
        if (ch == EOF) {
            ch = 0x1A;
        }
        emu->cpu.a = (uint8_t)ch;
        emu->cpu.l = (uint8_t)ch;
        store_return = false;
        break;
    }
    case 0x02:
        putchar((int)emu->cpu.e);
        fflush(stdout);
        return_code = emu->cpu.e;
        break;
    case 0x06:
        if (emu->cpu.e == 0xFFU) {
            int ch = getchar();
            if (ch == EOF) {
                ch = 0x00;
            }
            emu->cpu.a = (uint8_t)ch;
            emu->cpu.l = (uint8_t)ch;
            store_return = false;
        } else {
            putchar((int)emu->cpu.e);
            fflush(stdout);
            return_code = emu->cpu.e;
        }
        break;
    case 0x09:
        cpm_bdos_output_string(emu, de);
        break;
    case 0x0A:
        cpm_bdos_read_line(emu, de);
        break;
    case 0x0B:
        return_code = 0x00U;
        break;
    case 0x0C:
        return_code = 0x22U;
        break;
    case 0x0F:
        return_code = cpm_bdos_open_file(emu, de);
        break;
    case 0x10:
        return_code = cpm_bdos_close_file(emu, de);
        break;
    case 0x13:
        return_code = cpm_bdos_delete_file(emu, de);
        break;
    case 0x14:
        return_code = cpm_bdos_read_sequential(emu, de);
        break;
    case 0x15:
        return_code = cpm_bdos_write_sequential(emu, de);
        break;
    case 0x16:
        return_code = cpm_bdos_make_file(emu, de);
        break;
    case 0x17:
        return_code = cpm_bdos_rename_file(emu, de);
        break;
    case 0x1A:
        return_code = cpm_bdos_set_dma(emu, de);
        break;
    default:
        return_code = 0xFFU;
        break;
    }

    if (store_return) {
        emu->cpu.a = return_code;
        emu->cpu.l = return_code;
    }

    cpm_return_from_call(emu);
    return 17;
}

static bool handle_cpm_entry(Emulator *emu, int *cycles)
{
    if (emu->cpu.pc == CP_M_BIOS_ENTRY) {
        *cycles = handle_bios_call(emu);
        return true;
    }

    if (emu->cpu.pc == CP_M_BDOS_ENTRY) {
        *cycles = handle_bdos_call(emu);
        return true;
    }

    return false;
}

static void handle_out(uint8_t port, uint8_t value);
static uint8_t handle_in(uint8_t port);
static uint8_t fetch8(Emulator *emu);
static uint16_t fetch16(Emulator *emu);
static int execute_ld_r_n(Emulator *emu, uint8_t opcode);
static int execute_ld_r_r(Emulator *emu, uint8_t opcode);
static int execute_inc_r(Emulator *emu, uint8_t opcode);
static int execute_dec_r(Emulator *emu, uint8_t opcode);
static void set_flags_inc(Z80 *cpu, uint8_t before, uint8_t result);
static void set_flags_dec(Z80 *cpu, uint8_t before, uint8_t result);
static void z80_add_a(Z80 *cpu, uint8_t value, uint8_t carry);
static void z80_sub_a(Z80 *cpu, uint8_t value, uint8_t carry, bool store);
static void z80_and_a(Z80 *cpu, uint8_t value);
static void z80_xor_a(Z80 *cpu, uint8_t value);
static void z80_or_a(Z80 *cpu, uint8_t value);
static int execute_add_a_r(Emulator *emu, uint8_t opcode, uint8_t carry);
static int execute_sub_a_r(Emulator *emu, uint8_t opcode, uint8_t carry, bool store);
static int execute_logic_a_r(Emulator *emu, uint8_t opcode, void (*op)(Z80 *, uint8_t));
static int execute_primary_opcode(Emulator *emu, uint8_t opcode, uint16_t pc);
static int execute_indexed_prefixed(Emulator *emu, bool use_ix);
static int execute_index_cb_prefixed(Emulator *emu, bool use_ix);

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
    cpu->im = 0U;
}

static uint8_t *decode_register(Z80 *cpu, uint8_t index)
{
    switch (index & 0x07U) {
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
    case 7:
        return &cpu->a;
    default:
        return NULL;
    }
}

static uint8_t read_operand(Emulator *emu, uint8_t index)
{
    if ((index & 0x07U) == 6U) {
        return memory_read8(emu, z80_hl(&emu->cpu));
    }

    uint8_t *reg = decode_register(&emu->cpu, index);
    return (reg != NULL) ? *reg : 0U;
}

static void write_operand(Emulator *emu, uint8_t index, uint8_t value)
{
    if ((index & 0x07U) == 6U) {
        memory_write8(emu, z80_hl(&emu->cpu), value);
        return;
    }

    uint8_t *reg = decode_register(&emu->cpu, index);
    if (reg != NULL) {
        *reg = value;
    }
}

static inline uint8_t z80_ixh(const Z80 *cpu)
{
    return (uint8_t)((cpu->ix >> 8) & 0xFFU);
}

static inline uint8_t z80_ixl(const Z80 *cpu)
{
    return (uint8_t)(cpu->ix & 0xFFU);
}

static inline void z80_set_ixh(Z80 *cpu, uint8_t value)
{
    cpu->ix = (uint16_t)((cpu->ix & 0x00FFU) | ((uint16_t)value << 8));
}

static inline void z80_set_ixl(Z80 *cpu, uint8_t value)
{
    cpu->ix = (uint16_t)((cpu->ix & 0xFF00U) | value);
}

static inline uint8_t z80_iyh(const Z80 *cpu)
{
    return (uint8_t)((cpu->iy >> 8) & 0xFFU);
}

static inline uint8_t z80_iyl(const Z80 *cpu)
{
    return (uint8_t)(cpu->iy & 0xFFU);
}

static inline void z80_set_iyh(Z80 *cpu, uint8_t value)
{
    cpu->iy = (uint16_t)((cpu->iy & 0x00FFU) | ((uint16_t)value << 8));
}

static inline void z80_set_iyl(Z80 *cpu, uint8_t value)
{
    cpu->iy = (uint16_t)((cpu->iy & 0xFF00U) | value);
}

static inline uint16_t z80_get_index(const Z80 *cpu, bool use_ix)
{
    return use_ix ? cpu->ix : cpu->iy;
}

static inline void z80_set_index(Z80 *cpu, bool use_ix, uint16_t value)
{
    if (use_ix) {
        cpu->ix = value;
    } else {
        cpu->iy = value;
    }
}

static inline uint8_t z80_index_high(const Z80 *cpu, bool use_ix)
{
    return use_ix ? z80_ixh(cpu) : z80_iyh(cpu);
}

static inline uint8_t z80_index_low(const Z80 *cpu, bool use_ix)
{
    return use_ix ? z80_ixl(cpu) : z80_iyl(cpu);
}

static inline void z80_set_index_high(Z80 *cpu, bool use_ix, uint8_t value)
{
    if (use_ix) {
        z80_set_ixh(cpu, value);
    } else {
        z80_set_iyh(cpu, value);
    }
}

static inline void z80_set_index_low(Z80 *cpu, bool use_ix, uint8_t value)
{
    if (use_ix) {
        z80_set_ixl(cpu, value);
    } else {
        z80_set_iyl(cpu, value);
    }
}

static inline uint16_t z80_index_address(const Z80 *cpu, bool use_ix, int8_t displacement)
{
    uint16_t base = z80_get_index(cpu, use_ix);
    return (uint16_t)(base + (int16_t)displacement);
}

typedef enum {
    INDEX_MODE_HL,
    INDEX_MODE_IX,
    INDEX_MODE_IY
} IndexMode;

static inline uint16_t z80_get_hl_variant(const Z80 *cpu, IndexMode mode)
{
    switch (mode) {
    case INDEX_MODE_IX:
        return cpu->ix;
    case INDEX_MODE_IY:
        return cpu->iy;
    default:
        return z80_hl(cpu);
    }
}

static inline void z80_set_hl_variant(Z80 *cpu, IndexMode mode, uint16_t value)
{
    switch (mode) {
    case INDEX_MODE_IX:
        cpu->ix = value;
        break;
    case INDEX_MODE_IY:
        cpu->iy = value;
        break;
    default:
        z80_set_hl(cpu, value);
        break;
    }
}

static inline uint16_t z80_ed_get_pair(const Z80 *cpu, uint8_t pair, IndexMode mode)
{
    if (pair == 2U) {
        return z80_get_hl_variant(cpu, mode);
    }
    return z80_get_pair(cpu, pair);
}

static inline void z80_ed_set_pair(Z80 *cpu, uint8_t pair, IndexMode mode, uint16_t value)
{
    if (pair == 2U) {
        z80_set_hl_variant(cpu, mode, value);
        return;
    }
    z80_set_pair(cpu, pair, value);
}

static int execute_ed_prefixed(Emulator *emu, IndexMode mode);

static uint8_t read_index_register(const Z80 *cpu, bool use_ix, uint8_t index)
{
    switch (index & 0x07U) {
    case 0:
        return cpu->b;
    case 1:
        return cpu->c;
    case 2:
        return cpu->d;
    case 3:
        return cpu->e;
    case 4:
        return z80_index_high(cpu, use_ix);
    case 5:
        return z80_index_low(cpu, use_ix);
    case 7:
        return cpu->a;
    default:
        return 0U;
    }
}

static void write_index_register(Z80 *cpu, bool use_ix, uint8_t index, uint8_t value)
{
    switch (index & 0x07U) {
    case 0:
        cpu->b = value;
        break;
    case 1:
        cpu->c = value;
        break;
    case 2:
        cpu->d = value;
        break;
    case 3:
        cpu->e = value;
        break;
    case 4:
        z80_set_index_high(cpu, use_ix, value);
        break;
    case 5:
        z80_set_index_low(cpu, use_ix, value);
        break;
    case 7:
        cpu->a = value;
        break;
    default:
        break;
    }
}

static int execute_indexed_inc_r(Emulator *emu, uint8_t opcode, bool use_ix)
{
    uint8_t index = (opcode >> 3) & 0x07U;
    if (index == 4U) {
        uint8_t before = z80_index_high(&emu->cpu, use_ix);
        uint8_t result = (uint8_t)(before + 1U);
        z80_set_index_high(&emu->cpu, use_ix, result);
        set_flags_inc(&emu->cpu, before, result);
        return 8;
    }
    if (index == 5U) {
        uint8_t before = z80_index_low(&emu->cpu, use_ix);
        uint8_t result = (uint8_t)(before + 1U);
        z80_set_index_low(&emu->cpu, use_ix, result);
        set_flags_inc(&emu->cpu, before, result);
        return 8;
    }
    if (index == 6U) {
        int8_t disp = (int8_t)fetch8(emu);
        uint16_t addr = z80_index_address(&emu->cpu, use_ix, disp);
        uint8_t before = memory_read8(emu, addr);
        uint8_t result = (uint8_t)(before + 1U);
        memory_write8(emu, addr, result);
        set_flags_inc(&emu->cpu, before, result);
        return 23;
    }
    int cycles = execute_inc_r(emu, opcode);
    return cycles + 4;
}

static int execute_indexed_dec_r(Emulator *emu, uint8_t opcode, bool use_ix)
{
    uint8_t index = (opcode >> 3) & 0x07U;
    if (index == 4U) {
        uint8_t before = z80_index_high(&emu->cpu, use_ix);
        uint8_t result = (uint8_t)(before - 1U);
        z80_set_index_high(&emu->cpu, use_ix, result);
        set_flags_dec(&emu->cpu, before, result);
        return 8;
    }
    if (index == 5U) {
        uint8_t before = z80_index_low(&emu->cpu, use_ix);
        uint8_t result = (uint8_t)(before - 1U);
        z80_set_index_low(&emu->cpu, use_ix, result);
        set_flags_dec(&emu->cpu, before, result);
        return 8;
    }
    if (index == 6U) {
        int8_t disp = (int8_t)fetch8(emu);
        uint16_t addr = z80_index_address(&emu->cpu, use_ix, disp);
        uint8_t before = memory_read8(emu, addr);
        uint8_t result = (uint8_t)(before - 1U);
        memory_write8(emu, addr, result);
        set_flags_dec(&emu->cpu, before, result);
        return 23;
    }
    int cycles = execute_dec_r(emu, opcode);
    return cycles + 4;
}

static int execute_indexed_ld_r_n(Emulator *emu, uint8_t opcode, bool use_ix)
{
    uint8_t index = (opcode >> 3) & 0x07U;
    if (index == 4U) {
        uint8_t value = fetch8(emu);
        z80_set_index_high(&emu->cpu, use_ix, value);
        return 11;
    }
    if (index == 5U) {
        uint8_t value = fetch8(emu);
        z80_set_index_low(&emu->cpu, use_ix, value);
        return 11;
    }
    if (index == 6U) {
        int8_t disp = (int8_t)fetch8(emu);
        uint8_t value = fetch8(emu);
        uint16_t addr = z80_index_address(&emu->cpu, use_ix, disp);
        memory_write8(emu, addr, value);
        return 19;
    }
    int cycles = execute_ld_r_n(emu, opcode);
    return cycles + 4;
}

static int execute_indexed_ld_r_r(Emulator *emu, uint8_t opcode, bool use_ix)
{
    if (opcode == 0x76U) {
        emu->cpu.halted = true;
        return 4;
    }

    uint8_t dest = (opcode >> 3) & 0x07U;
    uint8_t src = opcode & 0x07U;
    bool disp_loaded = false;
    int8_t disp = 0;
    uint8_t value = 0U;
    int cycles = 8;

    if (src == 6U) {
        disp = (int8_t)fetch8(emu);
        disp_loaded = true;
        uint16_t addr = z80_index_address(&emu->cpu, use_ix, disp);
        value = memory_read8(emu, addr);
        cycles = 19;
    } else {
        value = read_index_register(&emu->cpu, use_ix, src);
    }

    if (dest == 6U) {
        if (!disp_loaded) {
            disp = (int8_t)fetch8(emu);
            disp_loaded = true;
        }
        uint16_t addr = z80_index_address(&emu->cpu, use_ix, disp);
        memory_write8(emu, addr, value);
        cycles = 19;
    } else {
        write_index_register(&emu->cpu, use_ix, dest, value);
        if (src != 6U && dest != 6U) {
            if ((dest == 4U || dest == 5U) || (src == 4U || src == 5U)) {
                cycles = 8;
            } else {
                int base = execute_ld_r_r(emu, opcode);
                return base + 4;
            }
        }
    }

    return cycles;
}

static int execute_indexed_add_a_r(Emulator *emu, uint8_t opcode, uint8_t carry, bool use_ix)
{
    uint8_t src = opcode & 0x07U;
    if (src == 4U) {
        z80_add_a(&emu->cpu, z80_index_high(&emu->cpu, use_ix), carry);
        return 8;
    }
    if (src == 5U) {
        z80_add_a(&emu->cpu, z80_index_low(&emu->cpu, use_ix), carry);
        return 8;
    }
    if (src == 6U) {
        int8_t disp = (int8_t)fetch8(emu);
        uint8_t value = memory_read8(emu, z80_index_address(&emu->cpu, use_ix, disp));
        z80_add_a(&emu->cpu, value, carry);
        return 19;
    }
    int cycles = execute_add_a_r(emu, opcode, carry);
    return cycles + 4;
}

static int execute_indexed_sub_a_r(Emulator *emu, uint8_t opcode, uint8_t carry, bool store, bool use_ix)
{
    uint8_t src = opcode & 0x07U;
    if (src == 4U) {
        z80_sub_a(&emu->cpu, z80_index_high(&emu->cpu, use_ix), carry, store);
        return 8;
    }
    if (src == 5U) {
        z80_sub_a(&emu->cpu, z80_index_low(&emu->cpu, use_ix), carry, store);
        return 8;
    }
    if (src == 6U) {
        int8_t disp = (int8_t)fetch8(emu);
        uint8_t value = memory_read8(emu, z80_index_address(&emu->cpu, use_ix, disp));
        z80_sub_a(&emu->cpu, value, carry, store);
        return 19;
    }
    int cycles = execute_sub_a_r(emu, opcode, carry, store);
    return cycles + 4;
}

static int execute_indexed_logic_a_r(Emulator *emu, uint8_t opcode, void (*op)(Z80 *, uint8_t), bool use_ix)
{
    uint8_t src = opcode & 0x07U;
    if (src == 4U) {
        op(&emu->cpu, z80_index_high(&emu->cpu, use_ix));
        return 8;
    }
    if (src == 5U) {
        op(&emu->cpu, z80_index_low(&emu->cpu, use_ix));
        return 8;
    }
    if (src == 6U) {
        int8_t disp = (int8_t)fetch8(emu);
        uint8_t value = memory_read8(emu, z80_index_address(&emu->cpu, use_ix, disp));
        op(&emu->cpu, value);
        return 19;
    }
    int cycles = execute_logic_a_r(emu, opcode, op);
    return cycles + 4;
}

static void set_flags_inc(Z80 *cpu, uint8_t before, uint8_t result)
{
    set_flag(cpu, FLAG_H, ((before & 0x0FU) + 1U) > 0x0FU);
    set_flag(cpu, FLAG_N, false);
    set_flag(cpu, FLAG_Z, result == 0U);
    set_flag(cpu, FLAG_S, (result & 0x80U) != 0U);
    set_flag(cpu, FLAG_PV, result == 0x80U);
}

static void set_flags_dec(Z80 *cpu, uint8_t before, uint8_t result)
{
    set_flag(cpu, FLAG_H, (before & 0x0FU) == 0U);
    set_flag(cpu, FLAG_N, true);
    set_flag(cpu, FLAG_Z, result == 0U);
    set_flag(cpu, FLAG_S, (result & 0x80U) != 0U);
    set_flag(cpu, FLAG_PV, before == 0x80U);
}

static void z80_add_a(Z80 *cpu, uint8_t value, uint8_t carry)
{
    uint16_t lhs = cpu->a;
    uint16_t rhs = (uint16_t)value + (uint16_t)carry;
    uint16_t sum = (uint16_t)(lhs + rhs);
    uint8_t result = (uint8_t)sum;

    set_flag(cpu, FLAG_C, sum > 0xFFU);
    set_flag(cpu, FLAG_H, ((cpu->a & 0x0FU) + (value & 0x0FU) + carry) > 0x0FU);
    set_flag(cpu, FLAG_Z, result == 0U);
    set_flag(cpu, FLAG_S, (result & 0x80U) != 0U);
    set_flag(cpu, FLAG_PV, (~(cpu->a ^ value) & (cpu->a ^ result) & 0x80U) != 0U);
    set_flag(cpu, FLAG_N, false);

    cpu->a = result;
}

static void z80_sub_a(Z80 *cpu, uint8_t value, uint8_t carry, bool store)
{
    uint16_t lhs = cpu->a;
    uint16_t rhs = (uint16_t)value + (uint16_t)carry;
    uint16_t diff = (uint16_t)((lhs - rhs) & 0xFFFFU);
    uint8_t result = (uint8_t)diff;

    set_flag(cpu, FLAG_C, lhs < rhs);
    set_flag(cpu, FLAG_H, (cpu->a & 0x0FU) < ((value & 0x0FU) + carry));
    set_flag(cpu, FLAG_Z, result == 0U);
    set_flag(cpu, FLAG_S, (result & 0x80U) != 0U);
    set_flag(cpu, FLAG_PV, ((cpu->a ^ value) & (cpu->a ^ result) & 0x80U) != 0U);
    set_flag(cpu, FLAG_N, true);

    if (store) {
        cpu->a = result;
    }
}

static void z80_and_a(Z80 *cpu, uint8_t value)
{
    cpu->a &= value;
    set_flag(cpu, FLAG_C, false);
    set_flag(cpu, FLAG_N, false);
    set_flag(cpu, FLAG_H, true);
    set_flag(cpu, FLAG_Z, cpu->a == 0U);
    set_flag(cpu, FLAG_S, (cpu->a & 0x80U) != 0U);
    set_flag(cpu, FLAG_PV, parity_even(cpu->a));
}

static void z80_xor_a(Z80 *cpu, uint8_t value)
{
    cpu->a ^= value;
    set_flag(cpu, FLAG_C, false);
    set_flag(cpu, FLAG_N, false);
    set_flag(cpu, FLAG_H, false);
    set_flag(cpu, FLAG_Z, cpu->a == 0U);
    set_flag(cpu, FLAG_S, (cpu->a & 0x80U) != 0U);
    set_flag(cpu, FLAG_PV, parity_even(cpu->a));
}

static void z80_or_a(Z80 *cpu, uint8_t value)
{
    cpu->a |= value;
    set_flag(cpu, FLAG_C, false);
    set_flag(cpu, FLAG_N, false);
    set_flag(cpu, FLAG_H, false);
    set_flag(cpu, FLAG_Z, cpu->a == 0U);
    set_flag(cpu, FLAG_S, (cpu->a & 0x80U) != 0U);
    set_flag(cpu, FLAG_PV, parity_even(cpu->a));
}

static void z80_push(Emulator *emu, uint16_t value)
{
    emu->cpu.sp = (uint16_t)(emu->cpu.sp - 2U);
    memory_write16(emu, emu->cpu.sp, value);
}

static uint16_t z80_pop(Emulator *emu)
{
    uint16_t value = memory_read16(emu, emu->cpu.sp);
    emu->cpu.sp = (uint16_t)(emu->cpu.sp + 2U);
    return value;
}

static bool evaluate_condition(const Z80 *cpu, uint8_t condition)
{
    switch (condition & 0x07U) {
    case 0:
        return !flag_set(cpu, FLAG_Z);
    case 1:
        return flag_set(cpu, FLAG_Z);
    case 2:
        return !flag_set(cpu, FLAG_C);
    case 3:
        return flag_set(cpu, FLAG_C);
    case 4:
        return !flag_set(cpu, FLAG_PV);
    case 5:
        return flag_set(cpu, FLAG_PV);
    case 6:
        return !flag_set(cpu, FLAG_S);
    default:
        return flag_set(cpu, FLAG_S);
    }
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
    uint8_t value = fetch8(emu);
    write_operand(emu, index, value);
    return (index == 6U) ? 10 : 7;
}

static int execute_ld_r_r(Emulator *emu, uint8_t opcode)
{
    uint8_t dest_index = (opcode >> 3) & 0x07U;
    uint8_t src_index = opcode & 0x07U;
    uint8_t value = read_operand(emu, src_index);
    write_operand(emu, dest_index, value);
    if (dest_index == 6U || src_index == 6U) {
        return 7;
    }
    return 4;
}

static int execute_inc_r(Emulator *emu, uint8_t opcode)
{
    uint8_t index = (opcode >> 3) & 0x07U;
    if (index == 6U) {
        uint16_t addr = z80_hl(&emu->cpu);
        uint8_t before = memory_read8(emu, addr);
        uint8_t result = (uint8_t)(before + 1U);
        memory_write8(emu, addr, result);
        set_flags_inc(&emu->cpu, before, result);
        return 11;
    }

    uint8_t *reg = decode_register(&emu->cpu, index);
    if (reg != NULL) {
        uint8_t before = *reg;
        uint8_t result = (uint8_t)(before + 1U);
        *reg = result;
        set_flags_inc(&emu->cpu, before, result);
    }

    return 4;
}

static int execute_dec_r(Emulator *emu, uint8_t opcode)
{
    uint8_t index = (opcode >> 3) & 0x07U;
    if (index == 6U) {
        uint16_t addr = z80_hl(&emu->cpu);
        uint8_t before = memory_read8(emu, addr);
        uint8_t result = (uint8_t)(before - 1U);
        memory_write8(emu, addr, result);
        set_flags_dec(&emu->cpu, before, result);
        return 11;
    }

    uint8_t *reg = decode_register(&emu->cpu, index);
    if (reg != NULL) {
        uint8_t before = *reg;
        uint8_t result = (uint8_t)(before - 1U);
        *reg = result;
        set_flags_dec(&emu->cpu, before, result);
    }

    return 4;
}

static void z80_daa(Z80 *cpu)
{
    uint8_t adjust = 0U;
    bool carry = flag_set(cpu, FLAG_C);
    uint8_t a = cpu->a;

    if (!flag_set(cpu, FLAG_N)) {
        if (flag_set(cpu, FLAG_H) || (a & 0x0FU) > 0x09U) {
            adjust |= 0x06U;
        }
        if (carry || a > 0x99U) {
            adjust |= 0x60U;
            carry = true;
        }
        a = (uint8_t)(a + adjust);
    } else {
        if (flag_set(cpu, FLAG_H)) {
            adjust |= 0x06U;
        }
        if (carry) {
            adjust |= 0x60U;
        }
        a = (uint8_t)(a - adjust);
    }

    set_flag(cpu, FLAG_C, carry);
    set_flag(cpu, FLAG_H, false);
    set_flag(cpu, FLAG_Z, a == 0U);
    set_flag(cpu, FLAG_S, (a & 0x80U) != 0U);
    set_flag(cpu, FLAG_PV, parity_even(a));

    cpu->a = a;
}

static int execute_add_a_r(Emulator *emu, uint8_t opcode, uint8_t carry)
{
    uint8_t src_index = opcode & 0x07U;
    uint8_t value = read_operand(emu, src_index);
    z80_add_a(&emu->cpu, value, carry);
    return (src_index == 6U) ? 7 : 4;
}

static int execute_sub_a_r(Emulator *emu, uint8_t opcode, uint8_t carry, bool store)
{
    uint8_t src_index = opcode & 0x07U;
    uint8_t value = read_operand(emu, src_index);
    z80_sub_a(&emu->cpu, value, carry, store);
    return (src_index == 6U) ? 7 : 4;
}

static int execute_logic_a_r(Emulator *emu, uint8_t opcode, void (*op)(Z80 *, uint8_t))
{
    uint8_t src_index = opcode & 0x07U;
    uint8_t value = read_operand(emu, src_index);
    op(&emu->cpu, value);
    return (src_index == 6U) ? 7 : 4;
}

static void set_flags_rotate(Z80 *cpu, uint8_t result, uint8_t carry)
{
    set_flag(cpu, FLAG_C, carry != 0U);
    set_flag(cpu, FLAG_N, false);
    set_flag(cpu, FLAG_H, false);
    set_flag(cpu, FLAG_Z, result == 0U);
    set_flag(cpu, FLAG_S, (result & 0x80U) != 0U);
    set_flag(cpu, FLAG_PV, parity_even(result));
}

static uint8_t z80_rlc_value(Z80 *cpu, uint8_t value)
{
    uint8_t result = (uint8_t)((value << 1) | (value >> 7));
    set_flags_rotate(cpu, result, (uint8_t)(value >> 7));
    return result;
}

static uint8_t z80_rrc_value(Z80 *cpu, uint8_t value)
{
    uint8_t result = (uint8_t)((value >> 1) | (value << 7));
    set_flags_rotate(cpu, result, (uint8_t)(value & 0x01U));
    return result;
}

static uint8_t z80_rl_value(Z80 *cpu, uint8_t value)
{
    uint8_t carry_in = flag_set(cpu, FLAG_C) ? 1U : 0U;
    uint8_t carry_out = (uint8_t)(value >> 7);
    uint8_t result = (uint8_t)((value << 1) | carry_in);
    set_flags_rotate(cpu, result, carry_out);
    return result;
}

static uint8_t z80_rr_value(Z80 *cpu, uint8_t value)
{
    uint8_t carry_in = flag_set(cpu, FLAG_C) ? 1U : 0U;
    uint8_t carry_out = (uint8_t)(value & 0x01U);
    uint8_t result = (uint8_t)((value >> 1) | (carry_in << 7));
    set_flags_rotate(cpu, result, carry_out);
    return result;
}

static uint8_t z80_sla_value(Z80 *cpu, uint8_t value)
{
    uint8_t carry_out = (uint8_t)(value >> 7);
    uint8_t result = (uint8_t)(value << 1);
    set_flags_rotate(cpu, result, carry_out);
    return result;
}

static uint8_t z80_sra_value(Z80 *cpu, uint8_t value)
{
    uint8_t carry_out = (uint8_t)(value & 0x01U);
    uint8_t result = (uint8_t)((value >> 1) | (value & 0x80U));
    set_flags_rotate(cpu, result, carry_out);
    return result;
}

static uint8_t z80_sll_value(Z80 *cpu, uint8_t value)
{
    uint8_t carry_out = (uint8_t)(value >> 7);
    uint8_t result = (uint8_t)((value << 1) | 0x01U);
    set_flags_rotate(cpu, result, carry_out);
    return result;
}

static uint8_t z80_srl_value(Z80 *cpu, uint8_t value)
{
    uint8_t carry_out = (uint8_t)(value & 0x01U);
    uint8_t result = (uint8_t)(value >> 1);
    set_flags_rotate(cpu, result, carry_out);
    return result;
}

static int execute_cb_prefixed(Emulator *emu)
{
    uint8_t opcode = fetch8(emu);
    uint8_t index = opcode & 0x07U;
    bool use_memory = (index == 6U);
    uint8_t value = 0U;
    uint8_t *reg = NULL;

    if (use_memory) {
        value = memory_read8(emu, z80_hl(&emu->cpu));
    } else {
        reg = decode_register(&emu->cpu, index);
        if (reg != NULL) {
            value = *reg;
        }
    }

    switch (opcode >> 6) {
    case 0: {
        uint8_t operation = (opcode >> 3) & 0x07U;
        switch (operation) {
        case 0:
            value = z80_rlc_value(&emu->cpu, value);
            break;
        case 1:
            value = z80_rrc_value(&emu->cpu, value);
            break;
        case 2:
            value = z80_rl_value(&emu->cpu, value);
            break;
        case 3:
            value = z80_rr_value(&emu->cpu, value);
            break;
        case 4:
            value = z80_sla_value(&emu->cpu, value);
            break;
        case 5:
            value = z80_sra_value(&emu->cpu, value);
            break;
        case 6:
            value = z80_sll_value(&emu->cpu, value);
            break;
        default:
            value = z80_srl_value(&emu->cpu, value);
            break;
        }

        if (use_memory) {
            memory_write8(emu, z80_hl(&emu->cpu), value);
            return 15;
        }

        if (reg != NULL) {
            *reg = value;
        }
        return 8;
    }
    case 1: {
        uint8_t bit = (opcode >> 3) & 0x07U;
        bool bit_set = (value & (uint8_t)(1U << bit)) != 0U;
        bool carry = flag_set(&emu->cpu, FLAG_C);

        set_flag(&emu->cpu, FLAG_H, true);
        set_flag(&emu->cpu, FLAG_N, false);
        set_flag(&emu->cpu, FLAG_Z, !bit_set);
        set_flag(&emu->cpu, FLAG_PV, !bit_set);
        if (bit == 7U) {
            set_flag(&emu->cpu, FLAG_S, bit_set);
        }
        set_flag(&emu->cpu, FLAG_C, carry);

        return use_memory ? 12 : 8;
    }
    case 2: {
        uint8_t bit = (opcode >> 3) & 0x07U;
        value = (uint8_t)(value & (uint8_t)~(1U << bit));
        if (use_memory) {
            memory_write8(emu, z80_hl(&emu->cpu), value);
            return 15;
        }
        if (reg != NULL) {
            *reg = value;
        }
        return 8;
    }
    default: {
        uint8_t bit = (opcode >> 3) & 0x07U;
        value = (uint8_t)(value | (uint8_t)(1U << bit));
        if (use_memory) {
            memory_write8(emu, z80_hl(&emu->cpu), value);
            return 15;
        }
        if (reg != NULL) {
            *reg = value;
        }
        return 8;
    }
    }
}

static int execute_indexed_prefixed(Emulator *emu, bool use_ix)
{
    uint8_t opcode = fetch8(emu);
    uint16_t pc = (uint16_t)(emu->cpu.pc - 1U);

    switch (opcode) {
    case 0x09:
    case 0x19:
    case 0x29:
    case 0x39: {
        uint8_t pair = (opcode >> 4) & 0x03U;
        uint32_t lhs = z80_get_index(&emu->cpu, use_ix);
        uint32_t rhs;
        switch (pair) {
        case 0:
            rhs = z80_bc(&emu->cpu);
            break;
        case 1:
            rhs = z80_de(&emu->cpu);
            break;
        case 2:
            rhs = z80_get_index(&emu->cpu, use_ix);
            break;
        default:
            rhs = emu->cpu.sp;
            break;
        }
        uint32_t result = lhs + rhs;
        set_flag(&emu->cpu, FLAG_N, false);
        set_flag(&emu->cpu, FLAG_H, ((lhs & 0x0FFFU) + (rhs & 0x0FFFU)) > 0x0FFFU);
        set_flag(&emu->cpu, FLAG_C, result > 0xFFFFU);
        z80_set_index(&emu->cpu, use_ix, (uint16_t)result);
        return 15;
    }
    case 0x21: {
        uint16_t value = fetch16(emu);
        z80_set_index(&emu->cpu, use_ix, value);
        return 14;
    }
    case 0x22: {
        uint16_t addr = fetch16(emu);
        memory_write16(emu, addr, z80_get_index(&emu->cpu, use_ix));
        return 20;
    }
    case 0x23:
        z80_set_index(&emu->cpu, use_ix, (uint16_t)(z80_get_index(&emu->cpu, use_ix) + 1U));
        return 10;
    case 0x24:
    case 0x2C:
    case 0x34:
        return execute_indexed_inc_r(emu, opcode, use_ix);
    case 0x25:
    case 0x2D:
    case 0x35:
        return execute_indexed_dec_r(emu, opcode, use_ix);
    case 0x26:
    case 0x2E:
    case 0x36:
        return execute_indexed_ld_r_n(emu, opcode, use_ix);
    case 0x2A: {
        uint16_t addr = fetch16(emu);
        uint16_t value = memory_read16(emu, addr);
        z80_set_index(&emu->cpu, use_ix, value);
        return 20;
    }
    case 0x2B:
        z80_set_index(&emu->cpu, use_ix, (uint16_t)(z80_get_index(&emu->cpu, use_ix) - 1U));
        return 10;
    case 0x44:
    case 0x45:
    case 0x46:
    case 0x47:
    case 0x4C:
    case 0x4D:
    case 0x4E:
    case 0x4F:
    case 0x54:
    case 0x55:
    case 0x56:
    case 0x57:
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
    case 0x78:
    case 0x79:
    case 0x7A:
    case 0x7B:
    case 0x7C:
    case 0x7D:
    case 0x7E:
    case 0x7F:
        return execute_indexed_ld_r_r(emu, opcode, use_ix);
    case 0x80:
    case 0x81:
    case 0x82:
    case 0x83:
    case 0x84:
    case 0x85:
    case 0x86:
    case 0x87:
        return execute_indexed_add_a_r(emu, opcode, 0U, use_ix);
    case 0x88:
    case 0x89:
    case 0x8A:
    case 0x8B:
    case 0x8C:
    case 0x8D:
    case 0x8E:
    case 0x8F:
        return execute_indexed_add_a_r(emu, opcode, flag_set(&emu->cpu, FLAG_C) ? 1U : 0U, use_ix);
    case 0x90:
    case 0x91:
    case 0x92:
    case 0x93:
    case 0x94:
    case 0x95:
    case 0x96:
    case 0x97:
        return execute_indexed_sub_a_r(emu, opcode, 0U, true, use_ix);
    case 0x98:
    case 0x99:
    case 0x9A:
    case 0x9B:
    case 0x9C:
    case 0x9D:
    case 0x9E:
    case 0x9F:
        return execute_indexed_sub_a_r(emu, opcode, flag_set(&emu->cpu, FLAG_C) ? 1U : 0U, true, use_ix);
    case 0xA0:
    case 0xA1:
    case 0xA2:
    case 0xA3:
    case 0xA4:
    case 0xA5:
    case 0xA6:
    case 0xA7:
        return execute_indexed_logic_a_r(emu, opcode, z80_and_a, use_ix);
    case 0xA8:
    case 0xA9:
    case 0xAA:
    case 0xAB:
    case 0xAC:
    case 0xAD:
    case 0xAE:
    case 0xAF:
        return execute_indexed_logic_a_r(emu, opcode, z80_xor_a, use_ix);
    case 0xB0:
    case 0xB1:
    case 0xB2:
    case 0xB3:
    case 0xB4:
    case 0xB5:
    case 0xB6:
    case 0xB7:
        return execute_indexed_logic_a_r(emu, opcode, z80_or_a, use_ix);
    case 0xB8:
    case 0xB9:
    case 0xBA:
    case 0xBB:
    case 0xBC:
    case 0xBD:
    case 0xBE:
    case 0xBF:
        return execute_indexed_sub_a_r(emu, opcode, 0U, false, use_ix);
    case 0xCB:
        return execute_index_cb_prefixed(emu, use_ix);
    case 0xDD:
        return execute_indexed_prefixed(emu, use_ix);
    case 0xE1: {
        uint16_t value = z80_pop(emu);
        z80_set_index(&emu->cpu, use_ix, value);
        return 14;
    }
    case 0xE3: {
        uint16_t value = memory_read16(emu, emu->cpu.sp);
        uint16_t index = z80_get_index(&emu->cpu, use_ix);
        memory_write16(emu, emu->cpu.sp, index);
        z80_set_index(&emu->cpu, use_ix, value);
        return 23;
    }
    case 0xE5:
        z80_push(emu, z80_get_index(&emu->cpu, use_ix));
        return 15;
    case 0xE9:
        emu->cpu.pc = z80_get_index(&emu->cpu, use_ix);
        return 8;
    case 0xEB: {
        uint16_t de = z80_de(&emu->cpu);
        uint16_t index = z80_get_index(&emu->cpu, use_ix);
        z80_set_de(&emu->cpu, index);
        z80_set_index(&emu->cpu, use_ix, de);
        return 8;
    }
    case 0xED: {
        IndexMode mode = use_ix ? INDEX_MODE_IX : INDEX_MODE_IY;
        int cycles = execute_ed_prefixed(emu, mode);
        return cycles + 4;
    }
    case 0xF9:
        emu->cpu.sp = z80_get_index(&emu->cpu, use_ix);
        return 10;
    case 0xFD:
        return execute_indexed_prefixed(emu, false);
    default:
        break;
    }

    int cycles = execute_primary_opcode(emu, opcode, pc);
    return cycles + 4;
}

static int execute_index_cb_prefixed(Emulator *emu, bool use_ix)
{
    int8_t displacement = (int8_t)fetch8(emu);
    uint8_t opcode = fetch8(emu);
    uint16_t addr = z80_index_address(&emu->cpu, use_ix, displacement);
    uint8_t value = memory_read8(emu, addr);
    uint8_t reg_index = opcode & 0x07U;
    uint8_t group = opcode >> 6;

    switch (group) {
    case 0: { /* Rotate/shift */
        uint8_t result;
        switch ((opcode >> 3) & 0x07U) {
        case 0:
            result = z80_rlc_value(&emu->cpu, value);
            break;
        case 1:
            result = z80_rrc_value(&emu->cpu, value);
            break;
        case 2:
            result = z80_rl_value(&emu->cpu, value);
            break;
        case 3:
            result = z80_rr_value(&emu->cpu, value);
            break;
        case 4:
            result = z80_sla_value(&emu->cpu, value);
            break;
        case 5:
            result = z80_sra_value(&emu->cpu, value);
            break;
        case 6:
            result = z80_sll_value(&emu->cpu, value);
            break;
        default:
            result = z80_srl_value(&emu->cpu, value);
            break;
        }

        memory_write8(emu, addr, result);

        if (reg_index == 4U) {
            z80_set_index_high(&emu->cpu, use_ix, result);
        } else if (reg_index == 5U) {
            z80_set_index_low(&emu->cpu, use_ix, result);
        } else if (reg_index != 6U) {
            uint8_t *reg = decode_register(&emu->cpu, reg_index);
            if (reg != NULL) {
                *reg = result;
            }
        }

        return (reg_index == 6U) ? 23 : 20;
    }
    case 1: { /* BIT */
        uint8_t bit = (opcode >> 3) & 0x07U;
        bool bit_set = (value & (uint8_t)(1U << bit)) != 0U;
        bool carry = flag_set(&emu->cpu, FLAG_C);

        set_flag(&emu->cpu, FLAG_H, true);
        set_flag(&emu->cpu, FLAG_N, false);
        set_flag(&emu->cpu, FLAG_Z, !bit_set);
        set_flag(&emu->cpu, FLAG_PV, !bit_set);
        if (bit == 7U) {
            set_flag(&emu->cpu, FLAG_S, bit_set);
        }
        set_flag(&emu->cpu, FLAG_C, carry);

        return 20;
    }
    case 2:
    case 3: { /* RES/SET */
        uint8_t bit = (opcode >> 3) & 0x07U;
        uint8_t mask = (uint8_t)(1U << bit);
        uint8_t result = (group == 2U) ? (uint8_t)(value & (uint8_t)~mask)
                                      : (uint8_t)(value | mask);

        memory_write8(emu, addr, result);

        if (reg_index == 4U) {
            z80_set_index_high(&emu->cpu, use_ix, result);
        } else if (reg_index == 5U) {
            z80_set_index_low(&emu->cpu, use_ix, result);
        } else if (reg_index == 6U) {
            /* Memory already updated. */
        } else {
            uint8_t *reg = decode_register(&emu->cpu, reg_index);
            if (reg != NULL) {
                *reg = result;
            }
        }

        return (reg_index == 6U) ? 23 : 20;
    }
    default:
        break;
    }

    fprintf(stderr, "Unhandled index CB opcode 0x%02X at PC=0x%04X\n", opcode, (uint16_t)(emu->cpu.pc - 2U));
    exit(EXIT_FAILURE);
}

static void set_flags_add16(Z80 *cpu, uint32_t lhs, uint32_t rhs, uint32_t result, uint8_t carry_in)
{
    uint16_t value16 = (uint16_t)result;
    uint32_t truncated = (uint32_t)value16;
    set_flag(cpu, FLAG_C, result > 0xFFFFU);
    set_flag(cpu, FLAG_H, ((lhs & 0x0FFFU) + (rhs & 0x0FFFU) + (uint32_t)carry_in) > 0x0FFFU);
    set_flag(cpu, FLAG_N, false);
    set_flag(cpu, FLAG_S, (value16 & 0x8000U) != 0U);
    set_flag(cpu, FLAG_Z, value16 == 0U);
    set_flag(cpu, FLAG_PV, ((~(lhs ^ rhs) & (lhs ^ truncated)) & 0x8000U) != 0U);
}

static void set_flags_sub16(Z80 *cpu, uint32_t lhs, uint32_t rhs, uint32_t result, uint8_t borrow_in)
{
    uint16_t value16 = (uint16_t)result;
    uint32_t truncated = (uint32_t)value16;
    uint32_t rhs_total = rhs + (uint32_t)borrow_in;
    set_flag(cpu, FLAG_C, lhs < rhs_total);
    set_flag(cpu, FLAG_H, (lhs & 0x0FFFU) < ((rhs & 0x0FFFU) + (uint32_t)borrow_in));
    set_flag(cpu, FLAG_N, true);
    set_flag(cpu, FLAG_S, (value16 & 0x8000U) != 0U);
    set_flag(cpu, FLAG_Z, value16 == 0U);
    set_flag(cpu, FLAG_PV, (((lhs ^ rhs) & (lhs ^ truncated)) & 0x8000U) != 0U);
}

static int execute_ed_prefixed(Emulator *emu, IndexMode mode)
{
    uint8_t opcode = fetch8(emu);
    switch (opcode) {
    case 0x40:
    case 0x48:
    case 0x50:
    case 0x58:
    case 0x60:
    case 0x68:
    case 0x78: {
        uint8_t *reg = decode_register(&emu->cpu, (opcode >> 3) & 0x07U);
        if (reg != NULL) {
            uint8_t value = handle_in(emu->cpu.c);
            *reg = value;
            set_flag(&emu->cpu, FLAG_S, (value & 0x80U) != 0U);
            set_flag(&emu->cpu, FLAG_Z, value == 0U);
            set_flag(&emu->cpu, FLAG_H, false);
            set_flag(&emu->cpu, FLAG_N, false);
            set_flag(&emu->cpu, FLAG_PV, parity_even(value));
        }
        return 12;
    }
    case 0x41:
    case 0x49:
    case 0x51:
    case 0x59:
    case 0x61:
    case 0x69:
    case 0x79: {
        uint8_t *reg = decode_register(&emu->cpu, (opcode >> 3) & 0x07U);
        uint8_t value = (reg != NULL) ? *reg : 0U;
        handle_out(emu->cpu.c, value);
        return 12;
    }
    case 0x44:
    case 0x4C:
    case 0x54:
    case 0x5C:
    case 0x64:
    case 0x6C:
    case 0x74:
    case 0x7C: {
        uint8_t value = emu->cpu.a;
        emu->cpu.a = 0U;
        z80_sub_a(&emu->cpu, value, 0U, true);
        return 8;
    }
    case 0x45:
    case 0x55:
    case 0x5D:
    case 0x65:
    case 0x6D:
    case 0x75:
    case 0x7D:
        emu->cpu.pc = z80_pop(emu);
        emu->cpu.iff1 = emu->cpu.iff2;
        return 14;
    case 0x4D:
        emu->cpu.pc = z80_pop(emu);
        emu->cpu.iff1 = emu->cpu.iff2;
        return 14;
    case 0x46:
    case 0x4E:
    case 0x66:
    case 0x6E:
        emu->cpu.im = 0U;
        return 8;
    case 0x56:
    case 0x76:
        emu->cpu.im = 1U;
        return 8;
    case 0x5E:
    case 0x7E:
        emu->cpu.im = 2U;
        return 8;
    case 0x47:
        emu->cpu.i = emu->cpu.a;
        return 9;
    case 0x4F:
        emu->cpu.r = emu->cpu.a;
        return 9;
    case 0x57:
    case 0x5F: {
        bool carry = flag_set(&emu->cpu, FLAG_C);
        uint8_t value = (opcode == 0x57U) ? emu->cpu.i : emu->cpu.r;
        emu->cpu.a = value;
        set_flag(&emu->cpu, FLAG_S, (value & 0x80U) != 0U);
        set_flag(&emu->cpu, FLAG_Z, value == 0U);
        set_flag(&emu->cpu, FLAG_H, false);
        set_flag(&emu->cpu, FLAG_N, false);
        set_flag(&emu->cpu, FLAG_PV, emu->cpu.iff2);
        set_flag(&emu->cpu, FLAG_C, carry);
        return 9;
    }
    case 0x67: {
        bool carry = flag_set(&emu->cpu, FLAG_C);
        uint16_t addr = z80_get_hl_variant(&emu->cpu, mode);
        uint8_t value = memory_read8(emu, addr);
        uint8_t new_mem = (uint8_t)(((emu->cpu.a & 0x0FU) << 4) | ((value >> 4) & 0x0FU));
        uint8_t new_a = (uint8_t)((emu->cpu.a & 0xF0U) | (value & 0x0FU));
        memory_write8(emu, addr, new_mem);
        emu->cpu.a = new_a;
        set_flag(&emu->cpu, FLAG_S, (new_a & 0x80U) != 0U);
        set_flag(&emu->cpu, FLAG_Z, new_a == 0U);
        set_flag(&emu->cpu, FLAG_H, false);
        set_flag(&emu->cpu, FLAG_N, false);
        set_flag(&emu->cpu, FLAG_PV, parity_even(new_a));
        set_flag(&emu->cpu, FLAG_C, carry);
        return 18;
    }
    case 0x6F: {
        bool carry = flag_set(&emu->cpu, FLAG_C);
        uint16_t addr = z80_get_hl_variant(&emu->cpu, mode);
        uint8_t value = memory_read8(emu, addr);
        uint8_t new_mem = (uint8_t)(((value << 4) & 0xF0U) | (emu->cpu.a & 0x0FU));
        uint8_t new_a = (uint8_t)((emu->cpu.a & 0xF0U) | ((value >> 4) & 0x0FU));
        memory_write8(emu, addr, new_mem);
        emu->cpu.a = new_a;
        set_flag(&emu->cpu, FLAG_S, (new_a & 0x80U) != 0U);
        set_flag(&emu->cpu, FLAG_Z, new_a == 0U);
        set_flag(&emu->cpu, FLAG_H, false);
        set_flag(&emu->cpu, FLAG_N, false);
        set_flag(&emu->cpu, FLAG_PV, parity_even(new_a));
        set_flag(&emu->cpu, FLAG_C, carry);
        return 18;
    }
    case 0x70: {
        uint8_t value = handle_in(emu->cpu.c);
        set_flag(&emu->cpu, FLAG_S, (value & 0x80U) != 0U);
        set_flag(&emu->cpu, FLAG_Z, value == 0U);
        set_flag(&emu->cpu, FLAG_H, false);
        set_flag(&emu->cpu, FLAG_N, false);
        set_flag(&emu->cpu, FLAG_PV, parity_even(value));
        return 12;
    }
    case 0x71:
        handle_out(emu->cpu.c, 0x00U);
        return 12;
    case 0x42:
    case 0x52:
    case 0x62:
    case 0x72: {
        uint8_t pair = (opcode >> 4) & 0x03U;
        uint32_t lhs = z80_get_hl_variant(&emu->cpu, mode);
        uint32_t rhs = z80_ed_get_pair(&emu->cpu, pair, mode);
        uint8_t borrow = flag_set(&emu->cpu, FLAG_C) ? 1U : 0U;
        uint32_t result = (lhs - rhs - (uint32_t)borrow) & 0xFFFFU;
        set_flags_sub16(&emu->cpu, lhs, rhs, result, borrow);
        z80_set_hl_variant(&emu->cpu, mode, (uint16_t)result);
        return 15;
    }
    case 0x4A:
    case 0x5A:
    case 0x6A:
    case 0x7A: {
        uint8_t pair = (opcode >> 4) & 0x03U;
        uint32_t lhs = z80_get_hl_variant(&emu->cpu, mode);
        uint32_t rhs = z80_ed_get_pair(&emu->cpu, pair, mode);
        uint8_t carry_in = flag_set(&emu->cpu, FLAG_C) ? 1U : 0U;
        uint32_t result = lhs + rhs + (uint32_t)carry_in;
        set_flags_add16(&emu->cpu, lhs, rhs, result, carry_in);
        z80_set_hl_variant(&emu->cpu, mode, (uint16_t)result);
        return 15;
    }
    case 0x43:
    case 0x53:
    case 0x63:
    case 0x73: {
        uint8_t pair = (opcode >> 4) & 0x03U;
        uint16_t addr = fetch16(emu);
        uint16_t value = z80_ed_get_pair(&emu->cpu, pair, mode);
        memory_write16(emu, addr, value);
        return 20;
    }
    case 0x4B:
    case 0x5B:
    case 0x6B:
    case 0x7B: {
        uint8_t pair = (opcode >> 4) & 0x03U;
        uint16_t addr = fetch16(emu);
        uint16_t value = memory_read16(emu, addr);
        z80_ed_set_pair(&emu->cpu, pair, mode, value);
        return 20;
    }
    case 0xA0: {
        uint16_t hl = z80_get_hl_variant(&emu->cpu, mode);
        uint16_t de = z80_de(&emu->cpu);
        uint16_t bc = z80_bc(&emu->cpu);
        uint8_t value = memory_read8(emu, hl);
        memory_write8(emu, de, value);
        hl = (uint16_t)(hl + 1U);
        de = (uint16_t)(de + 1U);
        bc = (uint16_t)(bc - 1U);
        z80_set_hl_variant(&emu->cpu, mode, hl);
        z80_set_de(&emu->cpu, de);
        z80_set_bc(&emu->cpu, bc);
        set_flag(&emu->cpu, FLAG_H, false);
        set_flag(&emu->cpu, FLAG_N, false);
        set_flag(&emu->cpu, FLAG_PV, bc != 0U);
        return 16;
    }
    case 0xB0: {
        uint16_t hl = z80_get_hl_variant(&emu->cpu, mode);
        uint16_t de = z80_de(&emu->cpu);
        uint16_t bc = z80_bc(&emu->cpu);
        uint8_t value = memory_read8(emu, hl);
        memory_write8(emu, de, value);
        hl = (uint16_t)(hl + 1U);
        de = (uint16_t)(de + 1U);
        bc = (uint16_t)(bc - 1U);
        z80_set_hl_variant(&emu->cpu, mode, hl);
        z80_set_de(&emu->cpu, de);
        z80_set_bc(&emu->cpu, bc);
        set_flag(&emu->cpu, FLAG_H, false);
        set_flag(&emu->cpu, FLAG_N, false);
        set_flag(&emu->cpu, FLAG_PV, bc != 0U);
        if (bc != 0U) {
            emu->cpu.pc = (uint16_t)(emu->cpu.pc - 2U);
            return 21;
        }
        return 16;
    }
    case 0xA8: {
        uint16_t hl = z80_get_hl_variant(&emu->cpu, mode);
        uint16_t de = z80_de(&emu->cpu);
        uint16_t bc = z80_bc(&emu->cpu);
        uint8_t value = memory_read8(emu, hl);
        memory_write8(emu, de, value);
        hl = (uint16_t)(hl - 1U);
        de = (uint16_t)(de - 1U);
        bc = (uint16_t)(bc - 1U);
        z80_set_hl_variant(&emu->cpu, mode, hl);
        z80_set_de(&emu->cpu, de);
        z80_set_bc(&emu->cpu, bc);
        set_flag(&emu->cpu, FLAG_H, false);
        set_flag(&emu->cpu, FLAG_N, false);
        set_flag(&emu->cpu, FLAG_PV, bc != 0U);
        return 16;
    }
    case 0xB8: {
        uint16_t hl = z80_get_hl_variant(&emu->cpu, mode);
        uint16_t de = z80_de(&emu->cpu);
        uint16_t bc = z80_bc(&emu->cpu);
        uint8_t value = memory_read8(emu, hl);
        memory_write8(emu, de, value);
        hl = (uint16_t)(hl - 1U);
        de = (uint16_t)(de - 1U);
        bc = (uint16_t)(bc - 1U);
        z80_set_hl_variant(&emu->cpu, mode, hl);
        z80_set_de(&emu->cpu, de);
        z80_set_bc(&emu->cpu, bc);
        set_flag(&emu->cpu, FLAG_H, false);
        set_flag(&emu->cpu, FLAG_N, false);
        set_flag(&emu->cpu, FLAG_PV, bc != 0U);
        if (bc != 0U) {
            emu->cpu.pc = (uint16_t)(emu->cpu.pc - 2U);
            return 21;
        }
        return 16;
    }
    case 0xA1: {
        uint16_t hl = z80_get_hl_variant(&emu->cpu, mode);
        uint16_t bc = z80_bc(&emu->cpu);
        uint8_t value = memory_read8(emu, hl);
        bool carry = flag_set(&emu->cpu, FLAG_C);
        z80_sub_a(&emu->cpu, value, 0U, false);
        bc = (uint16_t)(bc - 1U);
        hl = (uint16_t)(hl + 1U);
        z80_set_hl_variant(&emu->cpu, mode, hl);
        z80_set_bc(&emu->cpu, bc);
        set_flag(&emu->cpu, FLAG_PV, bc != 0U);
        set_flag(&emu->cpu, FLAG_C, carry);
        return 16;
    }
    case 0xB1: {
        uint16_t hl = z80_get_hl_variant(&emu->cpu, mode);
        uint16_t bc = z80_bc(&emu->cpu);
        uint8_t value = memory_read8(emu, hl);
        bool carry = flag_set(&emu->cpu, FLAG_C);
        z80_sub_a(&emu->cpu, value, 0U, false);
        bc = (uint16_t)(bc - 1U);
        hl = (uint16_t)(hl + 1U);
        z80_set_hl_variant(&emu->cpu, mode, hl);
        z80_set_bc(&emu->cpu, bc);
        set_flag(&emu->cpu, FLAG_PV, bc != 0U);
        set_flag(&emu->cpu, FLAG_C, carry);
        if (bc != 0U && !flag_set(&emu->cpu, FLAG_Z)) {
            emu->cpu.pc = (uint16_t)(emu->cpu.pc - 2U);
            return 21;
        }
        return 16;
    }
    case 0xA9: {
        uint16_t hl = z80_get_hl_variant(&emu->cpu, mode);
        uint16_t bc = z80_bc(&emu->cpu);
        uint8_t value = memory_read8(emu, hl);
        bool carry = flag_set(&emu->cpu, FLAG_C);
        z80_sub_a(&emu->cpu, value, 0U, false);
        bc = (uint16_t)(bc - 1U);
        hl = (uint16_t)(hl - 1U);
        z80_set_hl_variant(&emu->cpu, mode, hl);
        z80_set_bc(&emu->cpu, bc);
        set_flag(&emu->cpu, FLAG_PV, bc != 0U);
        set_flag(&emu->cpu, FLAG_C, carry);
        return 16;
    }
    case 0xB9: {
        uint16_t hl = z80_get_hl_variant(&emu->cpu, mode);
        uint16_t bc = z80_bc(&emu->cpu);
        uint8_t value = memory_read8(emu, hl);
        bool carry = flag_set(&emu->cpu, FLAG_C);
        z80_sub_a(&emu->cpu, value, 0U, false);
        bc = (uint16_t)(bc - 1U);
        hl = (uint16_t)(hl - 1U);
        z80_set_hl_variant(&emu->cpu, mode, hl);
        z80_set_bc(&emu->cpu, bc);
        set_flag(&emu->cpu, FLAG_PV, bc != 0U);
        set_flag(&emu->cpu, FLAG_C, carry);
        if (bc != 0U && !flag_set(&emu->cpu, FLAG_Z)) {
            emu->cpu.pc = (uint16_t)(emu->cpu.pc - 2U);
            return 21;
        }
        return 16;
    }
    default:
        fprintf(stderr, "ED-prefixed opcode 0x%02X not implemented at PC=0x%04X\n", opcode, (uint16_t)(emu->cpu.pc - 2U));
        exit(EXIT_FAILURE);
    }
}

static void handle_out(uint8_t port, uint8_t value)
{
    (void)port;
    (void)value;
}

static uint8_t handle_in(uint8_t port)
{
    (void)port;
    return 0x00U;
}


static int execute_primary_opcode(Emulator *emu, uint8_t opcode, uint16_t pc)
{
    switch (opcode) {
    case 0x00:
        return 4;
    case 0x01:
    case 0x11:
    case 0x21:
    case 0x31: {
        uint8_t pair = (opcode >> 4) & 0x03U;
        uint16_t value = fetch16(emu);
        z80_set_pair(&emu->cpu, pair, value);
        return 10;
    }
    case 0x02:
        memory_write8(emu, z80_bc(&emu->cpu), emu->cpu.a);
        return 7;
    case 0x03:
    case 0x13:
    case 0x23:
    case 0x33: {
        uint8_t pair = (opcode >> 4) & 0x03U;
        uint16_t value = (uint16_t)(z80_get_pair(&emu->cpu, pair) + 1U);
        z80_set_pair(&emu->cpu, pair, value);
        return 6;
    }
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
    case 0x06:
    case 0x0E:
    case 0x16:
    case 0x1E:
    case 0x26:
    case 0x2E:
    case 0x36:
    case 0x3E:
        return execute_ld_r_n(emu, opcode);
    case 0x07: {
        uint8_t carry = (uint8_t)((emu->cpu.a >> 7) & 0x01U);
        emu->cpu.a = (uint8_t)((emu->cpu.a << 1) | carry);
        set_flag(&emu->cpu, FLAG_C, carry != 0U);
        set_flag(&emu->cpu, FLAG_N, false);
        set_flag(&emu->cpu, FLAG_H, false);
        return 4;
    }
    case 0x08: {
        uint8_t a = emu->cpu.a;
        uint8_t f = emu->cpu.f;
        emu->cpu.a = emu->cpu.a_alt;
        emu->cpu.f = emu->cpu.f_alt;
        emu->cpu.a_alt = a;
        emu->cpu.f_alt = f;
        return 4;
    }
    case 0x09:
    case 0x19:
    case 0x29:
    case 0x39: {
        uint16_t hl = z80_hl(&emu->cpu);
        uint16_t value = z80_get_pair(&emu->cpu, (opcode >> 4) & 0x03U);
        uint32_t sum = (uint32_t)hl + (uint32_t)value;
        set_flag(&emu->cpu, FLAG_N, false);
        set_flag(&emu->cpu, FLAG_H, ((hl & 0x0FFFU) + (value & 0x0FFFU)) > 0x0FFFU);
        set_flag(&emu->cpu, FLAG_C, sum > 0xFFFFU);
        z80_set_hl(&emu->cpu, (uint16_t)sum);
        return 11;
    }
    case 0x0A:
        emu->cpu.a = memory_read8(emu, z80_bc(&emu->cpu));
        return 7;
    case 0x0B:
    case 0x1B:
    case 0x2B:
    case 0x3B: {
        uint8_t pair = (opcode >> 4) & 0x03U;
        uint16_t value = (uint16_t)(z80_get_pair(&emu->cpu, pair) - 1U);
        z80_set_pair(&emu->cpu, pair, value);
        return 6;
    }
    case 0x0F: {
        uint8_t carry = (uint8_t)(emu->cpu.a & 0x01U);
        emu->cpu.a = (uint8_t)((emu->cpu.a >> 1) | (carry << 7));
        set_flag(&emu->cpu, FLAG_C, carry != 0U);
        set_flag(&emu->cpu, FLAG_N, false);
        set_flag(&emu->cpu, FLAG_H, false);
        return 4;
    }
    case 0x10: {
        int8_t disp = (int8_t)fetch8(emu);
        emu->cpu.b = (uint8_t)(emu->cpu.b - 1U);
        if (emu->cpu.b != 0U) {
            emu->cpu.pc = (uint16_t)(emu->cpu.pc + disp);
            return 13;
        }
        return 8;
    }
    case 0x12:
        memory_write8(emu, z80_de(&emu->cpu), emu->cpu.a);
        return 7;
    case 0x17: {
        uint8_t carry_in = flag_set(&emu->cpu, FLAG_C) ? 1U : 0U;
        uint8_t carry_out = (uint8_t)((emu->cpu.a >> 7) & 0x01U);
        emu->cpu.a = (uint8_t)((emu->cpu.a << 1) | carry_in);
        set_flag(&emu->cpu, FLAG_C, carry_out != 0U);
        set_flag(&emu->cpu, FLAG_N, false);
        set_flag(&emu->cpu, FLAG_H, false);
        return 4;
    }
    case 0x18: {
        int8_t disp = (int8_t)fetch8(emu);
        emu->cpu.pc = (uint16_t)(emu->cpu.pc + disp);
        return 12;
    }
    case 0x1A:
        emu->cpu.a = memory_read8(emu, z80_de(&emu->cpu));
        return 7;
    case 0x1F: {
        uint8_t carry_in = flag_set(&emu->cpu, FLAG_C) ? 1U : 0U;
        uint8_t carry_out = (uint8_t)(emu->cpu.a & 0x01U);
        emu->cpu.a = (uint8_t)((emu->cpu.a >> 1) | (carry_in << 7));
        set_flag(&emu->cpu, FLAG_C, carry_out != 0U);
        set_flag(&emu->cpu, FLAG_N, false);
        set_flag(&emu->cpu, FLAG_H, false);
        return 4;
    }
    case 0x20:
    case 0x28:
    case 0x30:
    case 0x38: {
        int8_t disp = (int8_t)fetch8(emu);
        bool take;
        switch ((opcode >> 3) & 0x03U) {
        case 0:
            take = !flag_set(&emu->cpu, FLAG_Z);
            break;
        case 1:
            take = flag_set(&emu->cpu, FLAG_Z);
            break;
        case 2:
            take = !flag_set(&emu->cpu, FLAG_C);
            break;
        default:
            take = flag_set(&emu->cpu, FLAG_C);
            break;
        }
        if (take) {
            emu->cpu.pc = (uint16_t)(emu->cpu.pc + disp);
            return 12;
        }
        return 7;
    }
    case 0x22: {
        uint16_t addr = fetch16(emu);
        memory_write16(emu, addr, z80_hl(&emu->cpu));
        return 16;
    }
    case 0x27:
        z80_daa(&emu->cpu);
        return 4;
    case 0x2A: {
        uint16_t addr = fetch16(emu);
        uint16_t value = memory_read16(emu, addr);
        z80_set_hl(&emu->cpu, value);
        return 16;
    }
    case 0x2F:
        emu->cpu.a = (uint8_t)~emu->cpu.a;
        set_flag(&emu->cpu, FLAG_N, true);
        set_flag(&emu->cpu, FLAG_H, true);
        return 4;
    case 0x32: {
        uint16_t addr = fetch16(emu);
        memory_write8(emu, addr, emu->cpu.a);
        return 13;
    }
    case 0x37:
        set_flag(&emu->cpu, FLAG_C, true);
        set_flag(&emu->cpu, FLAG_N, false);
        set_flag(&emu->cpu, FLAG_H, false);
        return 4;
    case 0x3A: {
        uint16_t addr = fetch16(emu);
        emu->cpu.a = memory_read8(emu, addr);
        return 13;
    }
    case 0x3F: {
        bool carry = flag_set(&emu->cpu, FLAG_C);
        set_flag(&emu->cpu, FLAG_C, !carry);
        set_flag(&emu->cpu, FLAG_H, carry);
        set_flag(&emu->cpu, FLAG_N, false);
        return 4;
    }
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
    case 0x78:
    case 0x79:
    case 0x7A:
    case 0x7B:
    case 0x7C:
    case 0x7D:
    case 0x7E:
    case 0x7F:
        return execute_ld_r_r(emu, opcode);
    case 0x76:
        emu->cpu.halted = true;
        return 4;
    case 0x80:
    case 0x81:
    case 0x82:
    case 0x83:
    case 0x84:
    case 0x85:
    case 0x86:
    case 0x87:
        return execute_add_a_r(emu, opcode, 0U);
    case 0x88:
    case 0x89:
    case 0x8A:
    case 0x8B:
    case 0x8C:
    case 0x8D:
    case 0x8E:
    case 0x8F:
        return execute_add_a_r(emu, opcode, flag_set(&emu->cpu, FLAG_C) ? 1U : 0U);
    case 0x90:
    case 0x91:
    case 0x92:
    case 0x93:
    case 0x94:
    case 0x95:
    case 0x96:
    case 0x97:
        return execute_sub_a_r(emu, opcode, 0U, true);
    case 0x98:
    case 0x99:
    case 0x9A:
    case 0x9B:
    case 0x9C:
    case 0x9D:
    case 0x9E:
    case 0x9F:
        return execute_sub_a_r(emu, opcode, flag_set(&emu->cpu, FLAG_C) ? 1U : 0U, true);
    case 0xA0:
    case 0xA1:
    case 0xA2:
    case 0xA3:
    case 0xA4:
    case 0xA5:
    case 0xA6:
    case 0xA7:
        return execute_logic_a_r(emu, opcode, z80_and_a);
    case 0xA8:
    case 0xA9:
    case 0xAA:
    case 0xAB:
    case 0xAC:
    case 0xAD:
    case 0xAE:
    case 0xAF:
        return execute_logic_a_r(emu, opcode, z80_xor_a);
    case 0xB0:
    case 0xB1:
    case 0xB2:
    case 0xB3:
    case 0xB4:
    case 0xB5:
    case 0xB6:
    case 0xB7:
        return execute_logic_a_r(emu, opcode, z80_or_a);
    case 0xB8:
    case 0xB9:
    case 0xBA:
    case 0xBB:
    case 0xBC:
    case 0xBD:
    case 0xBE:
    case 0xBF:
        return execute_sub_a_r(emu, opcode, 0U, false);
    case 0xC0:
    case 0xC8:
    case 0xD0:
    case 0xD8:
    case 0xE0:
    case 0xE8:
    case 0xF0:
    case 0xF8: {
        uint8_t condition = (opcode >> 3) & 0x07U;
        if (evaluate_condition(&emu->cpu, condition)) {
            emu->cpu.pc = z80_pop(emu);
            return 11;
        }
        return 5;
    }
    case 0xC1:
    case 0xD1:
    case 0xE1:
    case 0xF1: {
        uint8_t pair = (opcode >> 4) & 0x03U;
        uint16_t value = z80_pop(emu);
        z80_set_stack_pair(&emu->cpu, pair, value);
        return 10;
    }
    case 0xC2:
    case 0xCA:
    case 0xD2:
    case 0xDA:
    case 0xE2:
    case 0xEA:
    case 0xF2:
    case 0xFA: {
        uint16_t addr = fetch16(emu);
        uint8_t condition = (opcode >> 3) & 0x07U;
        if (evaluate_condition(&emu->cpu, condition)) {
            emu->cpu.pc = addr;
        }
        return 10;
    }
    case 0xC3: {
        uint16_t addr = fetch16(emu);
        emu->cpu.pc = addr;
        return 10;
    }
    case 0xC4:
    case 0xCC:
    case 0xD4:
    case 0xDC:
    case 0xE4:
    case 0xEC:
    case 0xF4:
    case 0xFC: {
        uint16_t addr = fetch16(emu);
        uint8_t condition = (opcode >> 3) & 0x07U;
        if (evaluate_condition(&emu->cpu, condition)) {
            z80_push(emu, emu->cpu.pc);
            emu->cpu.pc = addr;
            return 17;
        }
        return 10;
    }
    case 0xC5:
    case 0xD5:
    case 0xE5:
    case 0xF5: {
        uint8_t pair = (opcode >> 4) & 0x03U;
        uint16_t value = z80_get_stack_pair(&emu->cpu, pair);
        z80_push(emu, value);
        return 11;
    }
    case 0xC6: {
        uint8_t value = fetch8(emu);
        z80_add_a(&emu->cpu, value, 0U);
        return 7;
    }
    case 0xC7:
    case 0xCF:
    case 0xD7:
    case 0xDF:
    case 0xE7:
    case 0xEF:
    case 0xF7:
    case 0xFF: {
        uint16_t addr = (uint16_t)(opcode & 0x38U);
        z80_push(emu, emu->cpu.pc);
        emu->cpu.pc = addr;
        return 11;
    }
    case 0xC9:
        emu->cpu.pc = z80_pop(emu);
        return 10;
    case 0xCB:
        return execute_cb_prefixed(emu);
    case 0xCD: {
        uint16_t addr = fetch16(emu);
        z80_push(emu, emu->cpu.pc);
        emu->cpu.pc = addr;
        return 17;
    }
    case 0xCE: {
        uint8_t value = fetch8(emu);
        z80_add_a(&emu->cpu, value, flag_set(&emu->cpu, FLAG_C) ? 1U : 0U);
        return 7;
    }
    case 0xD3: {
        uint8_t port = fetch8(emu);
        handle_out(port, emu->cpu.a);
        return 11;
    }
    case 0xD6: {
        uint8_t value = fetch8(emu);
        z80_sub_a(&emu->cpu, value, 0U, true);
        return 7;
    }
    case 0xD9: {
        uint8_t b = emu->cpu.b;
        uint8_t c = emu->cpu.c;
        uint8_t d = emu->cpu.d;
        uint8_t e = emu->cpu.e;
        uint8_t h = emu->cpu.h;
        uint8_t l = emu->cpu.l;
        emu->cpu.b = emu->cpu.b_alt;
        emu->cpu.c = emu->cpu.c_alt;
        emu->cpu.d = emu->cpu.d_alt;
        emu->cpu.e = emu->cpu.e_alt;
        emu->cpu.h = emu->cpu.h_alt;
        emu->cpu.l = emu->cpu.l_alt;
        emu->cpu.b_alt = b;
        emu->cpu.c_alt = c;
        emu->cpu.d_alt = d;
        emu->cpu.e_alt = e;
        emu->cpu.h_alt = h;
        emu->cpu.l_alt = l;
        return 4;
    }
    case 0xDB: {
        uint8_t port = fetch8(emu);
        emu->cpu.a = handle_in(port);
        return 11;
    }
    case 0xDD:
        return execute_indexed_prefixed(emu, true);
    case 0xDE: {
        uint8_t value = fetch8(emu);
        z80_sub_a(&emu->cpu, value, flag_set(&emu->cpu, FLAG_C) ? 1U : 0U, true);
        return 7;
    }
    case 0xE3: {
        uint16_t value = memory_read16(emu, emu->cpu.sp);
        uint16_t hl = z80_hl(&emu->cpu);
        memory_write16(emu, emu->cpu.sp, hl);
        z80_set_hl(&emu->cpu, value);
        return 19;
    }
    case 0xE6: {
        uint8_t value = fetch8(emu);
        z80_and_a(&emu->cpu, value);
        return 7;
    }
    case 0xE9:
        emu->cpu.pc = z80_hl(&emu->cpu);
        return 4;
    case 0xEB: {
        uint8_t d = emu->cpu.d;
        uint8_t e = emu->cpu.e;
        emu->cpu.d = emu->cpu.h;
        emu->cpu.e = emu->cpu.l;
        emu->cpu.h = d;
        emu->cpu.l = e;
        return 4;
    }
    case 0xED:
        return execute_ed_prefixed(emu, INDEX_MODE_HL);
    case 0xEE: {
        uint8_t value = fetch8(emu);
        z80_xor_a(&emu->cpu, value);
        return 7;
    }
    case 0xF3:
        emu->cpu.iff1 = false;
        emu->cpu.iff2 = false;
        return 4;
    case 0xF6: {
        uint8_t value = fetch8(emu);
        z80_or_a(&emu->cpu, value);
        return 7;
    }
    case 0xF9:
        emu->cpu.sp = z80_hl(&emu->cpu);
        return 6;
    case 0xFB:
        emu->cpu.iff1 = true;
        emu->cpu.iff2 = true;
        return 4;
    case 0xFD:
        return execute_indexed_prefixed(emu, false);
    case 0xFE: {
        uint8_t value = fetch8(emu);
        z80_sub_a(&emu->cpu, value, 0U, false);
        return 7;
    }
    default:
        fprintf(stderr, "Unimplemented opcode 0x%02X at PC=0x%04X\n", opcode, pc);
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "Opcode 0x%02X fell through at PC=0x%04X\n", opcode, pc);
    exit(EXIT_FAILURE);
}

static int z80_step(Emulator *emu)
{
    if (emu->cpu.halted) {
        return 4;
    }

    int trap_cycles = 0;
    if (handle_cpm_entry(emu, &trap_cycles)) {
        return trap_cycles;
    }

    uint16_t pc = emu->cpu.pc;
    uint8_t opcode = fetch8(emu);

    return execute_primary_opcode(emu, opcode, pc);
}

static void emulator_init(Emulator *emu)
{
    memset(emu, 0, sizeof(*emu));
    z80_reset(&emu->cpu);
    emu->dma_address = CP_M_DEFAULT_DMA;
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

    cpm_close_all_files(&emu);

    if (disk_is_mounted(&emu.disk_a)) {
        disk_unmount(&emu.disk_a);
    }

    return EXIT_SUCCESS;
}
