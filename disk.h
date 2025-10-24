#ifndef DISK_H
#define DISK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define DISK_DEFAULT_SECTOR_BYTES 128U
#define DISK_DEFAULT_SECTORS_PER_TRACK 26U

typedef struct {
    size_t track_count;
    size_t sectors_per_track;
    size_t sector_size;
    const uint8_t *translation_table;
    size_t translation_table_length;
    uint16_t default_dma_address;
    bool has_default_dma;
    bool translation_table_owned;
    bool allow_header;
    size_t directory_buffer_bytes;
    bool has_directory_buffer;
} DiskGeometry;

typedef enum {
    DISK_STATUS_OK = 0,
    DISK_STATUS_NOT_READY = 1,
    DISK_STATUS_BAD_ADDRESS = 2,
    DISK_STATUS_READ_ONLY = 3,
    DISK_STATUS_IO_ERROR = 4
} DiskStatus;

typedef struct {
    uint16_t spt;
    uint8_t bsh;
    uint8_t blm;
    uint8_t exm;
    uint16_t dsm;
    uint16_t drm;
    uint8_t al0;
    uint8_t al1;
    uint16_t cks;
    uint16_t off;
} DiskParameterBlock;

typedef struct {
    uint8_t user_number;
    bool is_empty;
    bool is_deleted;
    char filename[9];
    char extension[4];
    char filename_padded[8];
    char extension_padded[3];
    uint8_t extent;
    uint8_t s1;
    uint8_t s2;
    uint8_t record_count;
    uint8_t allocations[16];
    size_t allocation_count;
    uint8_t raw[32];
} DiskDirectoryEntry;

typedef struct {
    FILE *fp;
    DiskGeometry geometry;
    size_t image_size;
    bool mounted;
    bool read_only;
    uint16_t default_dma_address;
    bool has_default_dma;
    size_t data_offset;
    size_t directory_buffer_bytes;
    bool has_directory_buffer;
    DiskParameterBlock parameter_block;
    bool parameter_block_valid;
    size_t records_per_track;
    size_t block_records;
    size_t reserved_tracks;
    size_t directory_offset;
    size_t directory_entries;
    size_t allocation_vector_bytes;
    size_t directory_metadata_bytes;
    uint8_t *directory_metadata;
    uint8_t *allocation_vector_data;
    bool allocation_vector_from_bios;
    uint8_t *translation_table;
    size_t translation_table_entries;
    uint8_t *cache;
    size_t cache_track;
    size_t cache_sector;
    bool cache_valid;
} DiskDrive;

int disk_mount(DiskDrive *drive, const char *path, const DiskGeometry *geometry);
DiskStatus disk_read_sector(DiskDrive *drive, size_t track, size_t sector, uint8_t *buffer, size_t length);
DiskStatus disk_write_sector(DiskDrive *drive, size_t track, size_t sector, const uint8_t *buffer, size_t length);
void disk_unmount(DiskDrive *drive);
bool disk_is_mounted(const DiskDrive *drive);
const DiskParameterBlock *disk_parameter_block(const DiskDrive *drive);
size_t disk_directory_entry_count(const DiskDrive *drive);
size_t disk_allocation_vector_bytes(const DiskDrive *drive);
const uint8_t *disk_allocation_vector(const DiskDrive *drive);
const uint8_t *disk_translation_table(const DiskDrive *drive, size_t *length);
DiskStatus disk_read_directory_entry(DiskDrive *drive, size_t index, DiskDirectoryEntry *entry);
DiskStatus disk_write_directory_entry(DiskDrive *drive, size_t index, const uint8_t raw[32]);
void disk_invalidate_cache(DiskDrive *drive);
void disk_update_allocation_vector(DiskDrive *drive, const uint8_t *data, size_t length);

static inline size_t disk_sector_size(const DiskDrive *drive)
{
    return drive != NULL ? drive->geometry.sector_size : 0U;
}

#endif
