#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
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
#define CP_M_RECORD_SIZE 128U
#define CP_M_MAX_OPEN_FILES 16
#define CP_M_MAX_DISK_DRIVES 16
#define BIOS_TABLE_REGION_START 0xF000U
#define BIOS_TABLE_REGION_END 0xFF00U
#define BIOS_DPH_SCRATCH_BYTES 16U
#define BIOS_DIRBUF_BYTES 128U

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
    bool active;
    uint8_t drive;
    uint8_t user_number;
    size_t next_index;
    char filename_pattern[9];
    char extension_pattern[4];
} DirectorySearchState;

typedef struct {
    Z80 cpu;
    uint8_t memory[MEMORY_SIZE];
    DiskDrive disks[CP_M_MAX_DISK_DRIVES];
    uint16_t dma_address;
    uint8_t bios_selected_disk;
    uint16_t bios_track;
    uint16_t bios_sector;
    bool trap_cpm_calls;
    CpmFileHandle files[CP_M_MAX_OPEN_FILES];
    uint16_t bios_dph_addresses[CP_M_MAX_DISK_DRIVES];
    uint16_t bios_drive_table_address;
    uint16_t bios_table_next;
    uint8_t default_drive;
    DirectorySearchState directory_search;
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

static uint16_t bios_allocate(Emulator *emu, size_t size, size_t alignment)
{
    if (emu == NULL || size == 0U) {
        return 0U;
    }

    if (alignment == 0U) {
        alignment = 1U;
    }

    uint16_t old_next = emu->bios_table_next;
    if (old_next < BIOS_TABLE_REGION_START + size) {
        return 0U;
    }

    uint16_t base = (uint16_t)(old_next - (uint16_t)size);
    if (alignment > 1U) {
        uint16_t mask = (uint16_t)(alignment - 1U);
        base = (uint16_t)(base & (uint16_t)~mask);
    }

    if (base < BIOS_TABLE_REGION_START) {
        return 0U;
    }

    emu->bios_table_next = base;
    for (uint16_t addr = base; addr < old_next; ++addr) {
        memory_write8(emu, addr, 0x00U);
    }

    return base;
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

static uint32_t cpm_fcb_random_record_value(const Emulator *emu, uint16_t fcb_address)
{
    uint32_t value = memory_read8(emu, (uint16_t)(fcb_address + 33U));
    value |= (uint32_t)memory_read8(emu, (uint16_t)(fcb_address + 34U)) << 8;
    value |= (uint32_t)(memory_read8(emu, (uint16_t)(fcb_address + 35U)) & 0x7FU) << 16;
    return value;
}

static void cpm_fcb_set_random_record_value(Emulator *emu, uint16_t fcb_address, uint32_t record)
{
    if (record > 0xFFFFFFU) {
        record = 0xFFFFFFU;
    }

    memory_write8(emu, (uint16_t)(fcb_address + 33U), (uint8_t)(record & 0xFFU));
    memory_write8(emu, (uint16_t)(fcb_address + 34U), (uint8_t)((record >> 8) & 0xFFU));
    memory_write8(emu, (uint16_t)(fcb_address + 35U), (uint8_t)((record >> 16) & 0x7FU));
}

static void cpm_fcb_update_from_record(Emulator *emu, uint16_t fcb_address, uint32_t record)
{
    if (record > 0xFFFFFFU) {
        record = 0xFFFFFFU;
    }

    uint32_t extent_index = record / CP_M_RECORD_SIZE;
    uint8_t current_record = (uint8_t)(record % CP_M_RECORD_SIZE);
    uint8_t extent_low = (uint8_t)(extent_index & 0x1FU);
    uint8_t extent_high = (uint8_t)((extent_index >> 5) & 0xFFU);

    uint8_t extent_byte = memory_read8(emu, (uint16_t)(fcb_address + 12U));
    extent_byte = (uint8_t)((extent_byte & 0xE0U) | extent_low);
    memory_write8(emu, (uint16_t)(fcb_address + 12U), extent_byte);
    memory_write8(emu, (uint16_t)(fcb_address + 13U), 0x00U);
    memory_write8(emu, (uint16_t)(fcb_address + 14U), extent_high);
    memory_write8(emu, (uint16_t)(fcb_address + 32U), current_record);
    cpm_fcb_set_random_record_value(emu, fcb_address, record);
}

static uint32_t cpm_fcb_record_from_extent(const Emulator *emu, uint16_t fcb_address)
{
    uint8_t extent = memory_read8(emu, (uint16_t)(fcb_address + 12U)) & 0x1FU;
    uint8_t extent_high = memory_read8(emu, (uint16_t)(fcb_address + 14U));
    uint8_t current_record = memory_read8(emu, (uint16_t)(fcb_address + 32U));

    uint32_t extent_index = ((uint32_t)extent_high << 5) | extent;
    return extent_index * CP_M_RECORD_SIZE + current_record;
}

static bool cpm_record_to_offset(uint32_t record, long *offset)
{
    if (offset == NULL) {
        return false;
    }

    if (record > (uint32_t)(LONG_MAX / CP_M_RECORD_SIZE)) {
        return false;
    }

    *offset = (long)(record * CP_M_RECORD_SIZE);
    return true;
}

static void cpm_reset_fcb_position(Emulator *emu, uint16_t fcb_address)
{
    cpm_fcb_update_from_record(emu, fcb_address, 0U);
    memory_write8(emu, (uint16_t)(fcb_address + 15U), 0U);
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

static void cpm_reset_directory_search(Emulator *emu)
{
    if (emu == NULL) {
        return;
    }

    emu->directory_search.active = false;
    emu->directory_search.drive = 0U;
    emu->directory_search.user_number = 0xFFU;
    emu->directory_search.next_index = 0U;
    memset(emu->directory_search.filename_pattern, ' ', sizeof(emu->directory_search.filename_pattern));
    memset(emu->directory_search.extension_pattern, ' ', sizeof(emu->directory_search.extension_pattern));
    emu->directory_search.filename_pattern[8] = '\0';
    emu->directory_search.extension_pattern[3] = '\0';
}

static bool bios_initialise_drive_tables(Emulator *emu)
{
    if (emu == NULL) {
        return false;
    }

    emu->bios_table_next = BIOS_TABLE_REGION_END;
    emu->bios_drive_table_address = 0U;
    for (size_t i = 0U; i < CP_M_MAX_DISK_DRIVES; ++i) {
        emu->bios_dph_addresses[i] = 0U;
    }

    cpm_reset_directory_search(emu);

    size_t table_bytes = CP_M_MAX_DISK_DRIVES * sizeof(uint16_t);
    if (table_bytes > 0U) {
        uint16_t table_addr = bios_allocate(emu, table_bytes, 2U);
        if (table_addr == 0U && CP_M_MAX_DISK_DRIVES != 0U) {
            return false;
        }
        emu->bios_drive_table_address = table_addr;
    }

    bool default_set = false;
    uint8_t drive_count = 0U;

    for (size_t i = 0U; i < CP_M_MAX_DISK_DRIVES; ++i) {
        DiskDrive *drive = &emu->disks[i];
        uint16_t dph_addr = 0U;
        if (disk_is_mounted(drive)) {
            const DiskParameterBlock *dpb = disk_parameter_block(drive);
            if (dpb != NULL) {
                uint16_t dpb_addr = bios_allocate(emu, sizeof(*dpb), 2U);
                if (dpb_addr == 0U) {
                    return false;
                }

                memory_write16(emu, dpb_addr + 0U, dpb->spt);
                memory_write8(emu, (uint16_t)(dpb_addr + 2U), dpb->bsh);
                memory_write8(emu, (uint16_t)(dpb_addr + 3U), dpb->blm);
                memory_write8(emu, (uint16_t)(dpb_addr + 4U), dpb->exm);
                memory_write16(emu, (uint16_t)(dpb_addr + 5U), dpb->dsm);
                memory_write16(emu, (uint16_t)(dpb_addr + 7U), dpb->drm);
                memory_write8(emu, (uint16_t)(dpb_addr + 9U), dpb->al0);
                memory_write8(emu, (uint16_t)(dpb_addr + 10U), dpb->al1);
                memory_write16(emu, (uint16_t)(dpb_addr + 11U), dpb->cks);
                memory_write16(emu, (uint16_t)(dpb_addr + 13U), dpb->off);

                size_t xlt_length = 0U;
                const uint8_t *xlt_data = disk_translation_table(drive, &xlt_length);
                uint16_t xlt_addr = 0U;
                if (xlt_data != NULL && xlt_length > 0U) {
                    xlt_addr = bios_allocate(emu, xlt_length, 2U);
                    if (xlt_addr == 0U) {
                        return false;
                    }

                    for (size_t j = 0U; j < xlt_length; ++j) {
                        memory_write8(emu, (uint16_t)(xlt_addr + (uint16_t)j), (uint8_t)(xlt_data[j] + 1U));
                    }
                }

                size_t dirbuf_bytes = BIOS_DIRBUF_BYTES;
                if (drive->geometry.sector_size > dirbuf_bytes) {
                    dirbuf_bytes = drive->geometry.sector_size;
                }

                uint16_t dirbuf_addr = bios_allocate(emu, dirbuf_bytes, 2U);
                if (dirbuf_addr == 0U && dirbuf_bytes != 0U) {
                    return false;
                }

                size_t alv_bytes = disk_allocation_vector_bytes(drive);
                uint16_t alv_addr = 0U;
                if (alv_bytes > 0U) {
                    alv_addr = bios_allocate(emu, alv_bytes, 2U);
                    if (alv_addr == 0U) {
                        return false;
                    }

                    const uint8_t *alv_data = disk_allocation_vector(drive);
                    if (alv_data != NULL) {
                        for (size_t j = 0U; j < alv_bytes; ++j) {
                            memory_write8(emu, (uint16_t)(alv_addr + (uint16_t)j), alv_data[j]);
                        }
                    }
                }

                uint16_t csv_addr = 0U;
                if (dpb->cks != 0U) {
                    csv_addr = bios_allocate(emu, dpb->cks, 2U);
                    if (csv_addr == 0U) {
                        return false;
                    }
                }

                uint16_t dph_size = (uint16_t)(6U * sizeof(uint16_t) + BIOS_DPH_SCRATCH_BYTES);
                dph_addr = bios_allocate(emu, dph_size, 2U);
                if (dph_addr == 0U) {
                    return false;
                }

                uint16_t scratch_addr = (uint16_t)(dph_addr + 12U);
                memory_write16(emu, dph_addr + 0U, xlt_addr);
                memory_write16(emu, dph_addr + 2U, scratch_addr);
                memory_write16(emu, dph_addr + 4U, dirbuf_addr);
                memory_write16(emu, dph_addr + 6U, dpb_addr);
                memory_write16(emu, dph_addr + 8U, csv_addr);
                memory_write16(emu, dph_addr + 10U, alv_addr);

                if (!default_set) {
                    emu->default_drive = (uint8_t)i;
                    default_set = true;
                }
                ++drive_count;
            }
        }

        emu->bios_dph_addresses[i] = dph_addr;
        if (emu->bios_drive_table_address != 0U) {
            memory_write16(emu, (uint16_t)(emu->bios_drive_table_address + (uint16_t)(i * 2U)), dph_addr);
        }
    }

    if (!default_set) {
        emu->default_drive = 0U;
    }

    memory_write16(emu, BIOS_TABLE_REGION_START, emu->bios_drive_table_address);
    memory_write8(emu, (uint16_t)(BIOS_TABLE_REGION_START + 2U), drive_count);

    return true;
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

    uint32_t record = cpm_fcb_random_record_value(emu, fcb_address);
    long offset;
    if (!cpm_record_to_offset(record, &offset)) {
        return 0xFFU;
    }

    if (fseek(handle->fp, offset, SEEK_SET) != 0) {
        return 0xFFU;
    }

    uint8_t buffer[CP_M_RECORD_SIZE];
    size_t read = fread(buffer, 1U, CP_M_RECORD_SIZE, handle->fp);
    if (read == 0U) {
        memory_write8(emu, (uint16_t)(fcb_address + 15U), 0U);
        return 0x01U;
    }

    for (size_t i = 0; i < read; ++i) {
        memory_write8(emu, (uint16_t)(emu->dma_address + (uint16_t)i), buffer[i]);
    }
    for (size_t i = read; i < CP_M_RECORD_SIZE; ++i) {
        memory_write8(emu, (uint16_t)(emu->dma_address + (uint16_t)i), 0x1AU);
    }

    cpm_fcb_update_from_record(emu, fcb_address, record + 1U);
    memory_write8(emu, (uint16_t)(fcb_address + 15U), (uint8_t)read);

    return 0x00U;
}

static uint8_t cpm_bdos_write_sequential(Emulator *emu, uint16_t fcb_address)
{
    CpmFileHandle *handle = cpm_find_file(emu, fcb_address);
    if (handle == NULL || handle->fp == NULL || handle->read_only) {
        return 0xFFU;
    }

    uint32_t record = cpm_fcb_random_record_value(emu, fcb_address);
    long offset;
    if (!cpm_record_to_offset(record, &offset)) {
        return 0xFFU;
    }

    if (fseek(handle->fp, offset, SEEK_SET) != 0) {
        return 0xFFU;
    }

    uint8_t buffer[CP_M_RECORD_SIZE];
    for (size_t i = 0; i < CP_M_RECORD_SIZE; ++i) {
        buffer[i] = memory_read8(emu, (uint16_t)(emu->dma_address + (uint16_t)i));
    }

    size_t written = fwrite(buffer, 1U, CP_M_RECORD_SIZE, handle->fp);
    if (written != CP_M_RECORD_SIZE) {
        return 0x01U;
    }

    if (fflush(handle->fp) != 0) {
        return 0x01U;
    }

    cpm_fcb_update_from_record(emu, fcb_address, record + 1U);
    memory_write8(emu, (uint16_t)(fcb_address + 15U), (uint8_t)CP_M_RECORD_SIZE);
    return 0x00U;
}

static uint8_t cpm_bdos_read_random(Emulator *emu, uint16_t fcb_address)
{
    CpmFileHandle *handle = cpm_find_file(emu, fcb_address);
    if (handle == NULL || handle->fp == NULL) {
        return 0xFFU;
    }

    uint32_t record = cpm_fcb_random_record_value(emu, fcb_address);
    long offset;
    if (!cpm_record_to_offset(record, &offset)) {
        return 0xFFU;
    }

    if (fseek(handle->fp, offset, SEEK_SET) != 0) {
        return 0xFFU;
    }

    uint8_t buffer[CP_M_RECORD_SIZE];
    size_t read = fread(buffer, 1U, CP_M_RECORD_SIZE, handle->fp);
    if (read == 0U) {
        memory_write8(emu, (uint16_t)(fcb_address + 15U), 0U);
        return 0x01U;
    }

    for (size_t i = 0; i < read; ++i) {
        memory_write8(emu, (uint16_t)(emu->dma_address + (uint16_t)i), buffer[i]);
    }
    for (size_t i = read; i < CP_M_RECORD_SIZE; ++i) {
        memory_write8(emu, (uint16_t)(emu->dma_address + (uint16_t)i), 0x1AU);
    }

    cpm_fcb_update_from_record(emu, fcb_address, record + 1U);
    memory_write8(emu, (uint16_t)(fcb_address + 15U), (uint8_t)read);
    return 0x00U;
}

static uint8_t cpm_bdos_write_random(Emulator *emu, uint16_t fcb_address)
{
    CpmFileHandle *handle = cpm_find_file(emu, fcb_address);
    if (handle == NULL || handle->fp == NULL || handle->read_only) {
        return 0xFFU;
    }

    uint32_t record = cpm_fcb_random_record_value(emu, fcb_address);
    long offset;
    if (!cpm_record_to_offset(record, &offset)) {
        return 0xFFU;
    }

    if (fseek(handle->fp, offset, SEEK_SET) != 0) {
        return 0xFFU;
    }

    uint8_t buffer[CP_M_RECORD_SIZE];
    for (size_t i = 0; i < CP_M_RECORD_SIZE; ++i) {
        buffer[i] = memory_read8(emu, (uint16_t)(emu->dma_address + (uint16_t)i));
    }

    size_t written = fwrite(buffer, 1U, CP_M_RECORD_SIZE, handle->fp);
    if (written != CP_M_RECORD_SIZE) {
        return 0x01U;
    }

    if (fflush(handle->fp) != 0) {
        return 0x01U;
    }

    cpm_fcb_update_from_record(emu, fcb_address, record + 1U);
    memory_write8(emu, (uint16_t)(fcb_address + 15U), (uint8_t)CP_M_RECORD_SIZE);
    return 0x00U;
}

static uint8_t cpm_bdos_compute_file_size(Emulator *emu, uint16_t fcb_address)
{
    CpmFileHandle *handle = cpm_find_file(emu, fcb_address);
    if (handle == NULL || handle->fp == NULL) {
        return 0xFFU;
    }

    long current = ftell(handle->fp);
    if (current < 0L) {
        current = 0L;
    }

    if (fseek(handle->fp, 0L, SEEK_END) != 0) {
        return 0xFFU;
    }

    long end = ftell(handle->fp);
    if (end < 0L) {
        (void)fseek(handle->fp, current, SEEK_SET);
        return 0xFFU;
    }

    if (fseek(handle->fp, current, SEEK_SET) != 0) {
        return 0xFFU;
    }

    uint32_t records = (uint32_t)(end / (long)CP_M_RECORD_SIZE);
    uint8_t remainder = (uint8_t)(end % (long)CP_M_RECORD_SIZE);
    if ((end % (long)CP_M_RECORD_SIZE) != 0L) {
        ++records;
    }

    cpm_fcb_update_from_record(emu, fcb_address, records);
    memory_write8(emu, (uint16_t)(fcb_address + 15U), remainder);
    return 0x00U;
}

static uint8_t cpm_bdos_set_random_record(Emulator *emu, uint16_t fcb_address)
{
    uint32_t record = cpm_fcb_record_from_extent(emu, fcb_address);
    cpm_fcb_update_from_record(emu, fcb_address, record);
    return 0x00U;
}

static uint16_t cpm_bdos_login_vector(const Emulator *emu)
{
    uint16_t mask = 0U;
    for (size_t i = 0U; i < CP_M_MAX_DISK_DRIVES && i < 16U; ++i) {
        if (disk_is_mounted(&emu->disks[i])) {
            mask |= (uint16_t)(1U << i);
        }
    }
    return mask;
}

static uint16_t cpm_bdos_read_only_vector(const Emulator *emu)
{
    uint16_t mask = 0U;
    for (size_t i = 0U; i < CP_M_MAX_DISK_DRIVES && i < 16U; ++i) {
        if (disk_is_mounted(&emu->disks[i]) && emu->disks[i].read_only) {
            mask |= (uint16_t)(1U << i);
        }
    }
    return mask;
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

static bool cpm_prepare_directory_search(Emulator *emu, uint16_t fcb_address, DirectorySearchState *state)
{
    if (emu == NULL || state == NULL) {
        return false;
    }

    uint8_t drive_code = memory_read8(emu, fcb_address);
    uint8_t drive = 0U;

    if (drive_code == 0U) {
        drive = (emu->default_drive < CP_M_MAX_DISK_DRIVES) ? emu->default_drive : 0U;
    } else if (drive_code <= CP_M_MAX_DISK_DRIVES) {
        drive = (uint8_t)(drive_code - 1U);
    } else {
        return false;
    }

    if (drive >= CP_M_MAX_DISK_DRIVES) {
        return false;
    }

    if (!disk_is_mounted(&emu->disks[drive])) {
        return false;
    }

    state->drive = drive;
    state->next_index = 0U;
    state->active = true;
    state->user_number = 0xFFU;

    for (size_t i = 0U; i < 8U; ++i) {
        char ch = (char)memory_read8(emu, (uint16_t)(fcb_address + 1U + i));
        if (ch >= 'a' && ch <= 'z') {
            ch = (char)(ch - ('a' - 'A'));
        }
        if (ch == '?') {
            state->filename_pattern[i] = '?';
        } else if (ch == 0x00 || ch == 0x20) {
            state->filename_pattern[i] = ' ';
        } else {
            state->filename_pattern[i] = ch;
        }
    }
    state->filename_pattern[8] = '\0';

    for (size_t i = 0U; i < 3U; ++i) {
        char ch = (char)memory_read8(emu, (uint16_t)(fcb_address + 9U + i));
        if (ch >= 'a' && ch <= 'z') {
            ch = (char)(ch - ('a' - 'A'));
        }
        if (ch == '?') {
            state->extension_pattern[i] = '?';
        } else if (ch == 0x00 || ch == 0x20) {
            state->extension_pattern[i] = ' ';
        } else {
            state->extension_pattern[i] = ch;
        }
    }
    state->extension_pattern[3] = '\0';

    return true;
}

static bool cpm_directory_entry_matches(const DirectorySearchState *state, const DiskDirectoryEntry *entry)
{
    if (state == NULL || entry == NULL) {
        return false;
    }

    if (entry->is_deleted || entry->is_empty) {
        return false;
    }

    if (state->user_number != 0xFFU && entry->user_number != state->user_number) {
        return false;
    }

    for (size_t i = 0U; i < 8U; ++i) {
        char pattern = state->filename_pattern[i];
        if (pattern == '\0') {
            pattern = ' ';
        }
        char value = entry->filename_padded[i];
        if (pattern != '?' && pattern != value) {
            return false;
        }
    }

    for (size_t i = 0U; i < 3U; ++i) {
        char pattern = state->extension_pattern[i];
        if (pattern == '\0') {
            pattern = ' ';
        }
        char value = entry->extension_padded[i];
        if (pattern != '?' && pattern != value) {
            return false;
        }
    }

    return true;
}

static uint8_t cpm_bdos_search_directory(Emulator *emu, uint16_t fcb_address, bool reset)
{
    if (reset || !emu->directory_search.active) {
        if (!cpm_prepare_directory_search(emu, fcb_address, &emu->directory_search)) {
            cpm_reset_directory_search(emu);
            return 0xFFU;
        }
    }

    DirectorySearchState *state = &emu->directory_search;
    if (state->drive >= CP_M_MAX_DISK_DRIVES) {
        cpm_reset_directory_search(emu);
        return 0xFFU;
    }

    DiskDrive *drive = &emu->disks[state->drive];
    size_t total = disk_directory_entry_count(drive);
    for (size_t index = state->next_index; index < total; ++index) {
        DiskDirectoryEntry entry;
        DiskStatus status = disk_read_directory_entry(drive, index, &entry);
        if (status != DISK_STATUS_OK) {
            cpm_reset_directory_search(emu);
            return 0xFFU;
        }

        if (!cpm_directory_entry_matches(state, &entry)) {
            continue;
        }

        for (size_t i = 0U; i < sizeof(entry.raw); ++i) {
            memory_write8(emu, (uint16_t)(emu->dma_address + (uint16_t)i), entry.raw[i]);
        }

        state->next_index = index + 1U;
        return (uint8_t)(index & 0x7FU);
    }

    cpm_reset_directory_search(emu);
    return 0xFFU;
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

static uint8_t cpm_bios_select_disk(Emulator *emu, uint8_t disk)
{
    if (disk < CP_M_MAX_DISK_DRIVES && disk_is_mounted(&emu->disks[disk])) {
        uint16_t dph = emu->bios_dph_addresses[disk];
        if (dph != 0U) {
            emu->bios_selected_disk = disk;
            emu->bios_track = 0U;
            emu->bios_sector = 1U;
            emu->default_drive = disk;
            z80_set_hl(&emu->cpu, dph);
            cpm_reset_directory_search(emu);
            return 0x01U;
        }
    }

    emu->bios_selected_disk = 0xFFU;
    z80_set_hl(&emu->cpu, 0x0000U);
    cpm_reset_directory_search(emu);
    return 0x00U;
}

static uint8_t cpm_bios_transfer_sector(Emulator *emu, bool write)
{
    if (emu->bios_selected_disk >= CP_M_MAX_DISK_DRIVES) {
        return (uint8_t)DISK_STATUS_NOT_READY;
    }

    DiskDrive *drive = &emu->disks[emu->bios_selected_disk];
    if (!disk_is_mounted(drive)) {
        return (uint8_t)DISK_STATUS_NOT_READY;
    }

    if (emu->bios_sector == 0U) {
        return (uint8_t)DISK_STATUS_BAD_ADDRESS;
    }

    size_t sector_size = disk_sector_size(drive);
    if (sector_size == 0U) {
        return (uint8_t)DISK_STATUS_NOT_READY;
    }

    uint16_t dma = emu->dma_address;
    uint8_t *buffer = (uint8_t *)malloc(sector_size);
    if (buffer == NULL) {
        return (uint8_t)DISK_STATUS_IO_ERROR;
    }

    size_t sector_index = (size_t)(emu->bios_sector - 1U);
    DiskStatus status;

    if (write) {
        for (size_t i = 0; i < sector_size; ++i) {
            buffer[i] = memory_read8(emu, (uint16_t)(dma + (uint16_t)i));
        }
        status = disk_write_sector(drive, emu->bios_track, sector_index, buffer, sector_size);
        if (status == DISK_STATUS_OK) {
            size_t alv_bytes = disk_allocation_vector_bytes(drive);
            if (alv_bytes > 0U) {
                uint16_t dph = emu->bios_dph_addresses[emu->bios_selected_disk];
                if (dph != 0U) {
                    uint16_t alv_addr = memory_read16(emu, (uint16_t)(dph + 10U));
                    if (alv_addr != 0U) {
                        uint8_t *shadow = (uint8_t *)malloc(alv_bytes);
                        if (shadow != NULL) {
                            for (size_t i = 0; i < alv_bytes; ++i) {
                                shadow[i] = memory_read8(emu, (uint16_t)(alv_addr + (uint16_t)i));
                            }
                            disk_update_allocation_vector(drive, shadow, alv_bytes);
                            free(shadow);
                        }
                    }
                }
            }
        }
    } else {
        status = disk_read_sector(drive, emu->bios_track, sector_index, buffer, sector_size);
        if (status == DISK_STATUS_OK) {
            for (size_t i = 0; i < sector_size; ++i) {
                memory_write8(emu, (uint16_t)(dma + (uint16_t)i), buffer[i]);
            }
        }
    }

    free(buffer);
    return (uint8_t)status;
}

static int handle_bios_call(Emulator *emu)
{
    uint8_t function = emu->cpu.c;
    uint8_t status = 0x00U;

    switch (function) {
    case 0x00:
        emu->cpu.halted = true;
        break;
    case 0x08:
        emu->bios_track = 0U;
        emu->bios_sector = 1U;
        break;
    case 0x09: {
        uint8_t disk = emu->cpu.e;
        uint8_t result = cpm_bios_select_disk(emu, disk);
        emu->cpu.a = result;
        break;
    }
    case 0x0A:
        emu->bios_track = z80_de(&emu->cpu);
        break;
    case 0x0B:
        emu->bios_sector = z80_de(&emu->cpu);
        break;
    case 0x0C:
        emu->dma_address = z80_de(&emu->cpu);
        break;
    case 0x0D:
        status = cpm_bios_transfer_sector(emu, false);
        emu->cpu.a = status;
        emu->cpu.l = status;
        break;
    case 0x0E:
        status = cpm_bios_transfer_sector(emu, true);
        emu->cpu.a = status;
        emu->cpu.l = status;
        break;
    case 0x0F:
        emu->cpu.a = 0x00U;
        emu->cpu.l = 0x00U;
        break;
    case 0x10: {
        uint16_t address = z80_de(&emu->cpu);
        z80_set_hl(&emu->cpu, address);
        break;
    }
    default:
        break;
    }

    cpm_return_from_call(emu);
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
    case 0x11:
        return_code = cpm_bdos_search_directory(emu, de, true);
        break;
    case 0x12:
        return_code = cpm_bdos_search_directory(emu, de, false);
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
    case 0x18: {
        uint16_t mask = cpm_bdos_login_vector(emu);
        z80_set_hl(&emu->cpu, mask);
        return_code = (uint8_t)(mask & 0xFFU);
        break;
    }
    case 0x19:
        return_code = emu->default_drive;
        break;
    case 0x1A:
        return_code = cpm_bdos_set_dma(emu, de);
        break;
    case 0x1D: {
        uint16_t mask = cpm_bdos_read_only_vector(emu);
        z80_set_hl(&emu->cpu, mask);
        return_code = (uint8_t)(mask & 0xFFU);
        break;
    }
    case 0x21:
        return_code = cpm_bdos_read_random(emu, de);
        break;
    case 0x22:
        return_code = cpm_bdos_write_random(emu, de);
        break;
    case 0x23:
        return_code = cpm_bdos_compute_file_size(emu, de);
        break;
    case 0x24:
        return_code = cpm_bdos_set_random_record(emu, de);
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
    if (!emu->trap_cpm_calls) {
        return false;
    }

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
    emu->bios_selected_disk = 0xFFU;
    emu->bios_track = 0U;
    emu->bios_sector = 1U;
    emu->trap_cpm_calls = true;
    emu->bios_table_next = BIOS_TABLE_REGION_END;
    emu->default_drive = 0U;
    cpm_reset_directory_search(emu);
}

static void emulator_unmount_disks(Emulator *emu)
{
    if (emu == NULL) {
        return;
    }

    for (size_t i = 0; i < CP_M_MAX_DISK_DRIVES; ++i) {
        if (disk_is_mounted(&emu->disks[i])) {
            disk_unmount(&emu->disks[i]);
        }
    }
}

static int hex_value(char ch)
{
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }
    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }
    return -1;
}

static bool parse_hex_byte(const char *text, uint8_t *value)
{
    int high = hex_value(text[0]);
    int low = hex_value(text[1]);
    if (high < 0 || low < 0) {
        return false;
    }
    *value = (uint8_t)((high << 4) | low);
    return true;
}

static bool parse_hex_word(const char *text, uint16_t *value)
{
    uint8_t high;
    uint8_t low;
    if (!parse_hex_byte(text, &high) || !parse_hex_byte(text + 2, &low)) {
        return false;
    }
    *value = (uint16_t)((high << 8) | low);
    return true;
}

static size_t load_intel_hex_file(Emulator *emu, const char *path)
{
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
        return 0U;
    }

    char line[512];
    uint32_t base = 0U;
    size_t total = 0U;

    while (fgets(line, sizeof(line), fp) != NULL) {
        size_t len = strlen(line);
        while (len > 0U && (line[len - 1U] == '\n' || line[len - 1U] == '\r')) {
            line[--len] = '\0';
        }

        if (len == 0U) {
            continue;
        }

        if (line[0] != ':') {
            fprintf(stderr, "Invalid Intel HEX record in %s: missing ':'\n", path);
            fclose(fp);
            return 0U;
        }

        if (len < 11U) {
            fprintf(stderr, "Invalid Intel HEX record in %s: line too short\n", path);
            fclose(fp);
            return 0U;
        }

        uint8_t byte_count;
        uint16_t address16;
        uint8_t record_type;
        if (!parse_hex_byte(&line[1], &byte_count) || !parse_hex_word(&line[3], &address16)
            || !parse_hex_byte(&line[7], &record_type)) {
            fprintf(stderr, "Invalid Intel HEX record in %s: bad header fields\n", path);
            fclose(fp);
            return 0U;
        }

        size_t expected_len = 11U + (size_t)byte_count * 2U;
        if (len < expected_len) {
            fprintf(stderr, "Invalid Intel HEX record in %s: truncated data\n", path);
            fclose(fp);
            return 0U;
        }

        uint32_t sum = (uint32_t)byte_count + (uint32_t)(address16 >> 8) + (uint32_t)(address16 & 0xFFU)
                        + (uint32_t)record_type;
        uint8_t data_bytes[256];
        size_t data_len = (size_t)byte_count;
        if (data_len > sizeof(data_bytes)) {
            fprintf(stderr, "Intel HEX record too large in %s\n", path);
            fclose(fp);
            return 0U;
        }

        for (size_t i = 0U; i < data_len; ++i) {
            uint8_t value;
            if (!parse_hex_byte(&line[9 + i * 2U], &value)) {
                fprintf(stderr, "Invalid data byte in Intel HEX file %s\n", path);
                fclose(fp);
                return 0U;
            }
            data_bytes[i] = value;
            sum += value;
        }

        uint8_t checksum;
        if (!parse_hex_byte(&line[9 + data_len * 2U], &checksum)) {
            fprintf(stderr, "Invalid checksum in Intel HEX file %s\n", path);
            fclose(fp);
            return 0U;
        }

        if (((sum + (uint32_t)checksum) & 0xFFU) != 0U) {
            fprintf(stderr, "Checksum mismatch in Intel HEX file %s\n", path);
            fclose(fp);
            return 0U;
        }

        if (record_type == 0x00U) {
            uint32_t absolute = base + (uint32_t)address16;
            for (size_t i = 0U; i < data_len; ++i) {
                uint32_t addr = absolute + (uint32_t)i;
                if (addr >= MEMORY_SIZE) {
                    fprintf(stderr, "Intel HEX load in %s exceeds memory at 0x%04X\n", path,
                            (unsigned int)addr);
                    fclose(fp);
                    return 0U;
                }
                emu->memory[addr] = data_bytes[i];
                ++total;
            }
        } else if (record_type == 0x01U) {
            break;
        } else if (record_type == 0x02U) {
            if (byte_count != 2U) {
                fprintf(stderr, "Invalid extended segment address record in %s\n", path);
                fclose(fp);
                return 0U;
            }
            uint16_t segment = (uint16_t)((data_bytes[0] << 8) | data_bytes[1]);
            base = (uint32_t)segment << 4;
            if (base >= MEMORY_SIZE) {
                fprintf(stderr, "Extended segment base 0x%04X from %s exceeds memory\n",
                        (unsigned int)segment, path);
                fclose(fp);
                return 0U;
            }
        } else if (record_type == 0x04U) {
            if (byte_count != 2U) {
                fprintf(stderr, "Invalid extended linear address record in %s\n", path);
                fclose(fp);
                return 0U;
            }
            uint16_t value = (uint16_t)((data_bytes[0] << 8) | data_bytes[1]);
            base = (uint32_t)value << 16;
            if (base >= MEMORY_SIZE) {
                fprintf(stderr, "Extended linear base 0x%04X from %s exceeds memory\n",
                        (unsigned int)value, path);
                fclose(fp);
                return 0U;
            }
        } else if (record_type == 0x05U) {
            /* Start linear address record – ignore, entry point is provided separately. */
        } else {
            fprintf(stderr, "Unsupported Intel HEX record type 0x%02X in %s\n",
                    record_type, path);
            fclose(fp);
            return 0U;
        }
    }

    if (ferror(fp) != 0) {
        fprintf(stderr, "Error reading Intel HEX file %s\n", path);
        fclose(fp);
        return 0U;
    }

    fclose(fp);
    return total;
}

static size_t load_binary_file(Emulator *emu, const char *path, uint16_t address)
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

    if (offset >= MEMORY_SIZE && fgetc(fp) != EOF) {
        fprintf(stderr, "Binary '%s' truncated while loading at 0x%04X\n", path, address);
        fclose(fp);
        return 0U;
    }

    fclose(fp);
    return total;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [--cycles N] [--disk DRIVE:path] [--disk-geom DRIVE:spt:ssize[:tracks]]\n"
            "           [--disk-a path] [--load addr:file] [--load-hex path]\n"
            "           [--entry addr] [--no-cpm-traps] [program.bin]\n",
            prog);
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

static bool parse_uint16(const char *text, uint16_t *out)
{
    char *end = NULL;
    unsigned long parsed = strtoul(text, &end, 0);
    if (text[0] == '\0' || (end != NULL && *end != '\0') || parsed > 0xFFFFUL) {
        return false;
    }

    *out = (uint16_t)parsed;
    return true;
}

static bool parse_size_t_value(const char *text, size_t *out)
{
    if (text == NULL) {
        return false;
    }

    char *end = NULL;
    errno = 0;
    unsigned long parsed = strtoul(text, &end, 0);
    if (errno != 0 || text[0] == '\0' || (end != NULL && *end != '\0')) {
        return false;
    }

    *out = (size_t)parsed;
    return true;
}

static int parse_drive_letter_char(char ch)
{
    if (ch >= 'a' && ch <= 'z') {
        ch = (char)(ch - ('a' - 'A'));
    }

    if (ch < 'A' || ch >= 'A' + CP_M_MAX_DISK_DRIVES) {
        return -1;
    }

    return ch - 'A';
}

static int parse_drive_letter_token(const char *text)
{
    if (text == NULL || text[0] == '\0' || text[1] != '\0') {
        return -1;
    }

    return parse_drive_letter_char(text[0]);
}

static bool parse_disk_image_spec(const char *spec, int *drive_index, const char **path_out)
{
    if (spec == NULL || drive_index == NULL || path_out == NULL) {
        return false;
    }

    const char *colon = strchr(spec, ':');
    if (colon == NULL || colon == spec || colon[1] == '\0') {
        return false;
    }

    if (colon != spec + 1) {
        return false;
    }

    int index = parse_drive_letter_char(spec[0]);
    if (index < 0) {
        return false;
    }

    *drive_index = index;
    *path_out = colon + 1;
    return true;
}

static bool parse_disk_geometry_spec(const char *spec, int *drive_index, DiskGeometry *geometry)
{
    if (spec == NULL || drive_index == NULL || geometry == NULL) {
        return false;
    }

    geometry->translation_table = NULL;
    geometry->translation_table_length = 0U;

    size_t len = strlen(spec);
    if (len == 0U || len >= 128U) {
        return false;
    }

    char buffer[128];
    memcpy(buffer, spec, len + 1U);

    char *tokens[4];
    size_t token_count = 0U;
    char *cursor = buffer;

    while (true) {
        if (token_count >= 4U) {
            return false;
        }

        tokens[token_count++] = cursor;
        char *colon = strchr(cursor, ':');
        if (colon == NULL) {
            break;
        }

        *colon = '\0';
        cursor = colon + 1;
        if (*cursor == '\0') {
            return false;
        }
    }

    if (token_count < 3U || token_count > 4U) {
        return false;
    }

    int index = parse_drive_letter_token(tokens[0]);
    if (index < 0) {
        return false;
    }

    size_t sectors_per_track;
    size_t sector_size;
    size_t track_count = 0U;

    if (!parse_size_t_value(tokens[1], &sectors_per_track) || sectors_per_track == 0U) {
        return false;
    }

    if (!parse_size_t_value(tokens[2], &sector_size) || sector_size == 0U) {
        return false;
    }

    if (token_count == 4U) {
        if (!parse_size_t_value(tokens[3], &track_count)) {
            return false;
        }
    }

    geometry->sectors_per_track = sectors_per_track;
    geometry->sector_size = sector_size;
    geometry->track_count = track_count;
    *drive_index = index;
    return true;
}

static bool parse_disk_translation_spec(const char *spec, int *drive_index, uint8_t **table_out, size_t *length_out)
{
    if (spec == NULL || drive_index == NULL || table_out == NULL || length_out == NULL) {
        return false;
    }

    const char *colon = strchr(spec, ':');
    if (colon == NULL || colon == spec || colon[1] == '\0') {
        return false;
    }

    if (colon != spec + 1) {
        return false;
    }

    int index = parse_drive_letter_char(spec[0]);
    if (index < 0) {
        return false;
    }

    const char *list = colon + 1;
    size_t list_len = strlen(list);
    if (list_len == 0U || list_len >= 512U) {
        return false;
    }

    size_t entry_count = 1U;
    for (const char *p = list; *p != '\0'; ++p) {
        if (*p == ',') {
            ++entry_count;
        }
    }

    uint8_t *table = (uint8_t *)malloc(entry_count);
    if (table == NULL) {
        return false;
    }

    char *mutable = (char *)malloc(list_len + 1U);
    if (mutable == NULL) {
        free(table);
        return false;
    }
    memcpy(mutable, list, list_len + 1U);

    size_t parsed = 0U;
    char *token = mutable;
    while (token != NULL) {
        char *next = strchr(token, ',');
        if (next != NULL) {
            *next = '\0';
        }

        size_t value;
        if (!parse_size_t_value(token, &value) || value == 0U || value > 256U) {
            free(table);
            free(mutable);
            return false;
        }

        if (parsed >= entry_count) {
            free(table);
            free(mutable);
            return false;
        }

        table[parsed++] = (uint8_t)(value - 1U);

        token = (next != NULL) ? (next + 1) : NULL;
    }

    free(mutable);

    if (parsed == 0U) {
        free(table);
        return false;
    }

    *drive_index = index;
    *table_out = table;
    *length_out = parsed;
    return true;
}

int main(int argc, char **argv)
{
    Emulator emu;
    emulator_init(&emu);

    const char *program_path = NULL;
    uint64_t max_cycles = DEFAULT_MAX_CYCLES;
    uint16_t entry_point = CP_M_LOAD_ADDRESS;
    bool entry_specified = false;
    bool memory_loaded = false;

    const char *disk_paths[CP_M_MAX_DISK_DRIVES];
    DiskGeometry disk_geometries[CP_M_MAX_DISK_DRIVES];
    uint8_t *disk_translation_tables[CP_M_MAX_DISK_DRIVES];
    size_t disk_translation_lengths[CP_M_MAX_DISK_DRIVES];
    for (size_t i = 0; i < CP_M_MAX_DISK_DRIVES; ++i) {
        disk_paths[i] = NULL;
        disk_geometries[i].track_count = 0U;
        disk_geometries[i].sectors_per_track = DISK_DEFAULT_SECTORS_PER_TRACK;
        disk_geometries[i].sector_size = DISK_DEFAULT_SECTOR_BYTES;
        disk_geometries[i].translation_table = NULL;
        disk_geometries[i].translation_table_length = 0U;
        disk_translation_tables[i] = NULL;
        disk_translation_lengths[i] = 0U;
    }

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--cycles") == 0) {
            if (i + 1 >= argc) {
                usage(argv[0]);
                return EXIT_FAILURE;
            }
            max_cycles = parse_cycles(argv[++i]);
        } else if (strcmp(argv[i], "--disk") == 0) {
            if (i + 1 >= argc) {
                usage(argv[0]);
                return EXIT_FAILURE;
            }
            const char *spec = argv[++i];
            int drive_index;
            const char *path;
            if (!parse_disk_image_spec(spec, &drive_index, &path)) {
                fprintf(stderr, "Invalid --disk argument '%s'\n", spec);
                return EXIT_FAILURE;
            }
            disk_paths[drive_index] = path;
        } else if (strcmp(argv[i], "--disk-geom") == 0) {
            if (i + 1 >= argc) {
                usage(argv[0]);
                return EXIT_FAILURE;
            }
            const char *spec = argv[++i];
            DiskGeometry geom;
            int drive_index;
            if (!parse_disk_geometry_spec(spec, &drive_index, &geom)) {
                fprintf(stderr, "Invalid --disk-geom argument '%s'\n", spec);
                return EXIT_FAILURE;
            }
            disk_geometries[drive_index] = geom;
        } else if (strcmp(argv[i], "--disk-xlt") == 0) {
            if (i + 1 >= argc) {
                usage(argv[0]);
                return EXIT_FAILURE;
            }
            const char *spec = argv[++i];
            int drive_index;
            uint8_t *table;
            size_t length;
            if (!parse_disk_translation_spec(spec, &drive_index, &table, &length)) {
                fprintf(stderr, "Invalid --disk-xlt argument '%s'\n", spec);
                return EXIT_FAILURE;
            }
            free(disk_translation_tables[drive_index]);
            disk_translation_tables[drive_index] = table;
            disk_translation_lengths[drive_index] = length;
        } else if (strncmp(argv[i], "--disk-", 7) == 0 && argv[i][7] != '\0' && argv[i][8] == '\0') {
            int drive_index = parse_drive_letter_char(argv[i][7]);
            if (drive_index < 0) {
                fprintf(stderr, "Unknown option '%s'\n", argv[i]);
                return EXIT_FAILURE;
            }
            if (i + 1 >= argc) {
                usage(argv[0]);
                return EXIT_FAILURE;
            }
            disk_paths[drive_index] = argv[++i];
        } else if (strcmp(argv[i], "--load") == 0) {
            if (i + 1 >= argc) {
                usage(argv[0]);
                return EXIT_FAILURE;
            }
            const char *spec = argv[++i];
            const char *colon = strchr(spec, ':');
            if (colon == NULL || colon == spec || colon[1] == '\0') {
                fprintf(stderr, "Invalid --load argument '%s'\n", spec);
                return EXIT_FAILURE;
            }
            char address_buf[32];
            size_t len = (size_t)(colon - spec);
            if (len >= sizeof(address_buf)) {
                fprintf(stderr, "Address portion too long in --load argument '%s'\n", spec);
                return EXIT_FAILURE;
            }
            memcpy(address_buf, spec, len);
            address_buf[len] = '\0';
            uint16_t address;
            if (!parse_uint16(address_buf, &address)) {
                fprintf(stderr, "Invalid load address '%s'\n", address_buf);
                return EXIT_FAILURE;
            }
            const char *path = colon + 1;
            size_t loaded = load_binary_file(&emu, path, address);
            if (loaded == 0U) {
                return EXIT_FAILURE;
            }
            memory_loaded = true;
        } else if (strcmp(argv[i], "--load-hex") == 0) {
            if (i + 1 >= argc) {
                usage(argv[0]);
                return EXIT_FAILURE;
            }
            const char *path = argv[++i];
            size_t loaded = load_intel_hex_file(&emu, path);
            if (loaded == 0U) {
                return EXIT_FAILURE;
            }
            memory_loaded = true;
        } else if (strcmp(argv[i], "--entry") == 0) {
            if (i + 1 >= argc) {
                usage(argv[0]);
                return EXIT_FAILURE;
            }
            uint16_t address;
            if (!parse_uint16(argv[++i], &address)) {
                fprintf(stderr, "Invalid entry address '%s'\n", argv[i]);
                return EXIT_FAILURE;
            }
            entry_point = address;
            entry_specified = true;
        } else if (strcmp(argv[i], "--no-cpm-traps") == 0) {
            emu.trap_cpm_calls = false;
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

    for (size_t i = 0; i < CP_M_MAX_DISK_DRIVES; ++i) {
        disk_geometries[i].translation_table = disk_translation_tables[i];
        disk_geometries[i].translation_table_length = disk_translation_lengths[i];
    }

    for (size_t i = 0; i < CP_M_MAX_DISK_DRIVES; ++i) {
        if (disk_paths[i] != NULL) {
            if (disk_mount(&emu.disks[i], disk_paths[i], &disk_geometries[i]) != 0) {
                fprintf(stderr, "Failed to mount disk image '%s' for drive %c\n", disk_paths[i], (int)('A' + i));
                emulator_unmount_disks(&emu);
                for (size_t j = 0; j < CP_M_MAX_DISK_DRIVES; ++j) {
                    free(disk_translation_tables[j]);
                }
                return EXIT_FAILURE;
            }
        }
    }

    for (size_t i = 0; i < CP_M_MAX_DISK_DRIVES; ++i) {
        free(disk_translation_tables[i]);
        disk_geometries[i].translation_table = NULL;
        disk_geometries[i].translation_table_length = 0U;
    }

    if (!bios_initialise_drive_tables(&emu)) {
        fprintf(stderr, "Failed to initialise CP/M BIOS drive tables\n");
        emulator_unmount_disks(&emu);
        return EXIT_FAILURE;
    }

    if (program_path != NULL) {
        size_t loaded = load_binary_file(&emu, program_path, CP_M_LOAD_ADDRESS);
        if (loaded == 0U) {
            fprintf(stderr, "No bytes loaded from '%s'\n", program_path);
            emulator_unmount_disks(&emu);
            return EXIT_FAILURE;
        }
        memory_loaded = true;
        if (!entry_specified) {
            entry_point = CP_M_LOAD_ADDRESS;
        }
    }

    if (!memory_loaded) {
        usage(argv[0]);
        emulator_unmount_disks(&emu);
        return EXIT_FAILURE;
    }

    emu.cpu.pc = entry_point;

    uint64_t cycles = 0ULL;
    while (!emu.cpu.halted && cycles < max_cycles) {
        cycles += (uint64_t)z80_step(&emu);
    }

    printf("Execution halted after %" PRIu64 " cycles at PC=0x%04X\n", cycles, emu.cpu.pc);

    cpm_close_all_files(&emu);

    emulator_unmount_disks(&emu);

    return EXIT_SUCCESS;
}
