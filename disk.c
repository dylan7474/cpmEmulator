#include "disk.h"

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define DISK_HEADER_MAGIC "CPMI"
#define DISK_HEADER_SIZE 16U

static DiskStatus disk_cache_ensure(DiskDrive *drive, size_t track, size_t sector);
static void disk_parse_directory_entry_bytes(const uint8_t raw[32], DiskDirectoryEntry *entry);

static bool disk_try_apply_header(FILE *fp, DiskGeometry *geom, size_t file_size, size_t *data_offset)
{
    if (fp == NULL || geom == NULL || data_offset == NULL) {
        return false;
    }

    if (file_size < DISK_HEADER_SIZE) {
        return false;
    }

    uint8_t header[DISK_HEADER_SIZE];
    long original = ftell(fp);
    if (original < 0L) {
        original = 0L;
    }

    if (fseek(fp, 0L, SEEK_SET) != 0) {
        return false;
    }

    size_t read = fread(header, 1U, sizeof(header), fp);
    if (read != sizeof(header)) {
        (void)fseek(fp, original, SEEK_SET);
        return false;
    }

    if (memcmp(header, DISK_HEADER_MAGIC, strlen(DISK_HEADER_MAGIC)) != 0) {
        (void)fseek(fp, original, SEEK_SET);
        return false;
    }

    uint32_t sector_size = (uint32_t)header[4] | ((uint32_t)header[5] << 8) | ((uint32_t)header[6] << 16)
                           | ((uint32_t)header[7] << 24);
    uint32_t sectors_per_track = (uint32_t)header[8] | ((uint32_t)header[9] << 8) | ((uint32_t)header[10] << 16)
                                 | ((uint32_t)header[11] << 24);
    uint32_t track_count = (uint32_t)header[12] | ((uint32_t)header[13] << 8) | ((uint32_t)header[14] << 16)
                           | ((uint32_t)header[15] << 24);

    if (sector_size == 0U || sectors_per_track == 0U) {
        (void)fseek(fp, original, SEEK_SET);
        return false;
    }

    geom->sector_size = (size_t)sector_size;
    geom->sectors_per_track = (size_t)sectors_per_track;
    geom->track_count = (size_t)track_count;
    *data_offset = DISK_HEADER_SIZE;

    if (fseek(fp, (long)*data_offset, SEEK_SET) != 0) {
        (void)fseek(fp, original, SEEK_SET);
        return false;
    }

    return true;
}

static void disk_apply_host_read_only_flag(const DiskDrive *drive, uint8_t *entry_raw)
{
    if (drive == NULL || entry_raw == NULL || !drive->read_only) {
        return;
    }

    if (entry_raw[0] == 0xE5U || entry_raw[0] == 0x00U) {
        return;
    }

    entry_raw[9] |= 0x80U;
}

static long compute_offset(const DiskDrive *drive, size_t track, size_t sector)
{
    if (drive == NULL || drive->geometry.sectors_per_track == 0U || drive->geometry.sector_size == 0U) {
        return -1L;
    }

    if (drive->geometry.track_count > 0U && track >= drive->geometry.track_count) {
        return -1L;
    }

    if (sector >= drive->geometry.sectors_per_track) {
        return -1L;
    }

    if (drive->geometry.sectors_per_track > 0U && track > (SIZE_MAX / drive->geometry.sectors_per_track)) {
        return -1L;
    }

    size_t base = track * drive->geometry.sectors_per_track;
    if (base > SIZE_MAX - sector) {
        return -1L;
    }

    size_t index = base + sector;
    size_t sector_bytes = drive->geometry.sector_size;
    if (sector_bytes != 0U && index > (SIZE_MAX / sector_bytes)) {
        return -1L;
    }

    size_t byte_offset = index * sector_bytes;
    if (drive->data_offset > SIZE_MAX - byte_offset) {
        return -1L;
    }

    byte_offset += drive->data_offset;

    if (byte_offset > (size_t)LONG_MAX) {
        return -1L;
    }

    return (long)byte_offset;
}

static void disk_invalidate_cache_internal(DiskDrive *drive)
{
    if (drive == NULL) {
        return;
    }

    drive->cache_valid = false;
    drive->cache_track = 0U;
    drive->cache_sector = 0U;
}

static void disk_reset_metadata(DiskDrive *drive)
{
    if (drive == NULL) {
        return;
    }

    memset(&drive->parameter_block, 0, sizeof(drive->parameter_block));
    drive->parameter_block_valid = false;
    drive->records_per_track = 0U;
    drive->block_records = 0U;
    drive->reserved_tracks = 0U;
    drive->directory_offset = 0U;
    drive->directory_entries = 0U;
    drive->allocation_vector_bytes = 0U;
    drive->directory_metadata_bytes = 0U;
    if (drive->directory_metadata != NULL) {
        free(drive->directory_metadata);
        drive->directory_metadata = NULL;
    }
    if (drive->allocation_vector_data != NULL) {
        free(drive->allocation_vector_data);
        drive->allocation_vector_data = NULL;
    }
    drive->allocation_vector_from_bios = false;
}

static void disk_compute_metadata(DiskDrive *drive)
{
    disk_reset_metadata(drive);

    if (drive == NULL || drive->geometry.sectors_per_track == 0U || drive->geometry.sector_size == 0U) {
        return;
    }

    size_t logical_records_per_sector = drive->geometry.sector_size / DISK_DEFAULT_SECTOR_BYTES;
    if (logical_records_per_sector == 0U || drive->geometry.sector_size % DISK_DEFAULT_SECTOR_BYTES != 0U) {
        return;
    }

    size_t records_per_track = drive->geometry.sectors_per_track * logical_records_per_sector;
    size_t track_bytes = drive->geometry.sectors_per_track * drive->geometry.sector_size;
    if (track_bytes == 0U) {
        return;
    }

    size_t total_tracks = drive->geometry.track_count;
    if (total_tracks == 0U) {
        total_tracks = (track_bytes != 0U) ? (drive->image_size / track_bytes) : 0U;
    }

    if (total_tracks == 0U) {
        return;
    }

    size_t reserved_tracks = (total_tracks > 2U) ? 2U : 0U;
    size_t data_tracks = (total_tracks > reserved_tracks) ? (total_tracks - reserved_tracks) : 0U;
    size_t data_records = data_tracks * records_per_track;
    if (data_records == 0U) {
        return;
    }

    size_t block_records = 8U;
    while (block_records < 2048U && data_records / block_records > 0xFFFFU) {
        block_records <<= 1U;
    }

    while (block_records > 128U) {
        block_records >>= 1U;
    }

    if (block_records == 0U) {
        block_records = 1U;
    }

    if (block_records > data_records) {
        size_t value = 1U;
        while ((value << 1U) <= data_records) {
            value <<= 1U;
        }
        block_records = value > 0U ? value : 1U;
    }

    size_t block_size_bytes = DISK_DEFAULT_SECTOR_BYTES * block_records;
    size_t block_count = data_records / block_records;
    if (block_count == 0U) {
        block_count = 1U;
    }

    if (block_count > 0x10000U) {
        block_count = 0x10000U;
    }

    DiskParameterBlock *dpb = &drive->parameter_block;
    dpb->spt = (uint16_t)((records_per_track > 0xFFFFU) ? 0xFFFFU : records_per_track);

    dpb->bsh = 0U;
    size_t tmp = block_records;
    while (tmp > 1U) {
        tmp >>= 1U;
        ++dpb->bsh;
    }

    if (dpb->bsh > 7U) {
        dpb->bsh = 7U;
    }

    dpb->blm = (uint8_t)((uint16_t)1U << dpb->bsh);
    dpb->blm = (uint8_t)(dpb->blm - 1U);

    if (block_records <= 16U) {
        dpb->exm = 0U;
    } else if (block_records <= 32U) {
        dpb->exm = 1U;
    } else if (block_records <= 64U) {
        dpb->exm = 3U;
    } else {
        dpb->exm = 7U;
    }

    dpb->dsm = (uint16_t)(block_count - 1U);

    size_t dir_entries = 64U;
    size_t dir_bytes = dir_entries * 32U;
    size_t dir_blocks = (dir_bytes + block_size_bytes - 1U) / block_size_bytes;
    if (dir_blocks == 0U) {
        dir_blocks = 1U;
    }

    if (dir_blocks >= block_count) {
        dir_blocks = (block_count > 1U) ? (block_count - 1U) : 1U;
        dir_bytes = dir_blocks * block_size_bytes;
        dir_entries = dir_bytes / 32U;
    }

    if (dir_entries == 0U) {
        dir_entries = 32U;
    }

    if (dir_entries > 0xFFFFU) {
        dir_entries = 0xFFFFU;
    }

    dpb->drm = (uint16_t)(dir_entries - 1U);

    dpb->al0 = 0U;
    dpb->al1 = 0U;
    for (size_t i = 0U; i < dir_blocks && i < 8U; ++i) {
        dpb->al0 |= (uint8_t)(0x80U >> i);
    }
    for (size_t i = 8U; i < dir_blocks && i < 16U; ++i) {
        dpb->al1 |= (uint8_t)(0x80U >> (i - 8U));
    }

    size_t cks = dir_entries / 4U;
    if (cks > 0xFFFFU) {
        cks = 0xFFFFU;
    }
    dpb->cks = (uint16_t)cks;
    dpb->off = (uint16_t)reserved_tracks;

    drive->parameter_block_valid = true;
    drive->records_per_track = records_per_track;
    drive->block_records = block_records;
    drive->reserved_tracks = reserved_tracks;
    drive->directory_offset = reserved_tracks * track_bytes;
    drive->directory_entries = dir_entries;
    drive->allocation_vector_bytes = (size_t)((block_count + 7U) / 8U);
    drive->directory_metadata_bytes = dir_entries * 32U;
}

static size_t disk_map_logical_sector(const DiskDrive *drive, size_t logical_sector)
{
    if (drive == NULL || drive->geometry.sectors_per_track == 0U) {
        return logical_sector;
    }

    if (drive->translation_table != NULL && drive->translation_table_entries == drive->geometry.sectors_per_track) {
        if (logical_sector < drive->translation_table_entries) {
            return drive->translation_table[logical_sector];
        }
    }

    return logical_sector;
}

static void disk_mark_block_allocated(DiskDrive *drive, uint16_t block)
{
    if (drive == NULL || drive->allocation_vector_data == NULL || !drive->parameter_block_valid) {
        return;
    }

    uint16_t max_block = drive->parameter_block.dsm;
    if (block > max_block) {
        return;
    }

    size_t byte_index = block / 8U;
    size_t bit_index = block % 8U;
    if (byte_index >= drive->allocation_vector_bytes) {
        return;
    }

    uint8_t mask = (uint8_t)(0x80U >> bit_index);
    drive->allocation_vector_data[byte_index] |= mask;
}

static void disk_recompute_allocation_vector(DiskDrive *drive)
{
    if (drive == NULL || drive->allocation_vector_data == NULL || drive->directory_metadata == NULL) {
        return;
    }

    if (drive->allocation_vector_bytes == 0U || !drive->parameter_block_valid) {
        return;
    }

    memset(drive->allocation_vector_data, 0, drive->allocation_vector_bytes);

    size_t entry_count = drive->directory_entries;
    size_t records_per_block = drive->block_records;
    if (records_per_block == 0U) {
        records_per_block = 1U;
    }

    for (size_t i = 0U; i < entry_count; ++i) {
        const uint8_t *raw = &drive->directory_metadata[i * 32U];
        DiskDirectoryEntry entry;
        disk_parse_directory_entry_bytes(raw, &entry);

        if (entry.is_empty || entry.is_deleted) {
            continue;
        }

        size_t blocks_hint = (entry.record_count + records_per_block - 1U) / records_per_block;
        if (blocks_hint > entry.allocation_count) {
            blocks_hint = entry.allocation_count;
        }

        for (size_t j = 0U; j < entry.allocation_count; ++j) {
            uint8_t block = entry.allocations[j];
            if (block == 0U && j >= blocks_hint) {
                continue;
            }

            disk_mark_block_allocated(drive, block);
        }
    }
}

static bool disk_refresh_directory_metadata(DiskDrive *drive)
{
    if (drive == NULL || drive->directory_metadata == NULL) {
        return true;
    }

    if (drive->directory_metadata_bytes == 0U) {
        return true;
    }

    size_t track_bytes = drive->geometry.sectors_per_track * drive->geometry.sector_size;
    if (track_bytes == 0U) {
        return false;
    }

    size_t track = drive->directory_offset / track_bytes;
    size_t track_offset = drive->directory_offset % track_bytes;
    size_t sector = track_offset / drive->geometry.sector_size;
    size_t sector_offset = track_offset % drive->geometry.sector_size;

    size_t copied = 0U;
    while (copied < drive->directory_metadata_bytes) {
        DiskStatus status = disk_cache_ensure(drive, track, sector);
        if (status != DISK_STATUS_OK) {
            return false;
        }

        size_t available = drive->geometry.sector_size - sector_offset;
        size_t remaining = drive->directory_metadata_bytes - copied;
        size_t take = (remaining < available) ? remaining : available;
        memcpy(drive->directory_metadata + copied, drive->cache + sector_offset, take);
        copied += take;
        sector_offset = 0U;
        ++sector;
        if (sector >= drive->geometry.sectors_per_track) {
            sector = 0U;
            ++track;
        }
    }

    if (drive->read_only) {
        size_t entry_count = drive->directory_metadata_bytes / 32U;
        for (size_t i = 0U; i < entry_count; ++i) {
            disk_apply_host_read_only_flag(drive, drive->directory_metadata + i * 32U);
        }
    }

    if (!drive->allocation_vector_from_bios) {
        disk_recompute_allocation_vector(drive);
    }

    return true;
}

static void disk_apply_write_to_metadata(DiskDrive *drive, size_t track, size_t sector, const uint8_t *buffer)
{
    if (drive == NULL || drive->directory_metadata == NULL || buffer == NULL) {
        return;
    }

    size_t track_bytes = drive->geometry.sectors_per_track * drive->geometry.sector_size;
    if (track_bytes == 0U) {
        return;
    }

    size_t sector_size = drive->geometry.sector_size;
    size_t sector_start = track * track_bytes + sector * sector_size;
    size_t dir_start = drive->directory_offset;
    size_t dir_end = drive->directory_offset + drive->directory_metadata_bytes;

    if (dir_start >= sector_start + sector_size || dir_end <= sector_start) {
        return;
    }

    size_t overlap_start = (sector_start > dir_start) ? sector_start : dir_start;
    size_t overlap_end = (sector_start + sector_size < dir_end) ? (sector_start + sector_size) : dir_end;
    if (overlap_end <= overlap_start) {
        return;
    }

    size_t buffer_offset = overlap_start - sector_start;
    size_t metadata_offset = overlap_start - dir_start;
    size_t copy_bytes = overlap_end - overlap_start;

    memcpy(drive->directory_metadata + metadata_offset, buffer + buffer_offset, copy_bytes);

    if (!drive->allocation_vector_from_bios) {
        disk_recompute_allocation_vector(drive);
    }
}

static DiskStatus disk_read_uncached(DiskDrive *drive, size_t track, size_t sector, uint8_t *buffer)
{
    if (drive == NULL || buffer == NULL) {
        return DISK_STATUS_NOT_READY;
    }

    long offset = compute_offset(drive, track, sector);
    if (offset < 0) {
        return DISK_STATUS_BAD_ADDRESS;
    }

    if (fseek(drive->fp, offset, SEEK_SET) != 0) {
        return DISK_STATUS_IO_ERROR;
    }

    size_t expected = drive->geometry.sector_size;
    size_t read = fread(buffer, 1U, expected, drive->fp);
    if (read != expected) {
        memset(buffer, 0, expected);
        return DISK_STATUS_IO_ERROR;
    }

    return DISK_STATUS_OK;
}

static DiskStatus disk_write_uncached(DiskDrive *drive, size_t track, size_t sector, const uint8_t *buffer)
{
    if (drive == NULL || buffer == NULL) {
        return DISK_STATUS_NOT_READY;
    }

    if (fseek(drive->fp, 0L, SEEK_CUR) == -1L && ferror(drive->fp) != 0) {
        clearerr(drive->fp);
    }

    long offset = compute_offset(drive, track, sector);
    if (offset < 0) {
        return DISK_STATUS_BAD_ADDRESS;
    }

    if (fseek(drive->fp, offset, SEEK_SET) != 0) {
        return DISK_STATUS_IO_ERROR;
    }

    size_t expected = drive->geometry.sector_size;
    size_t written = fwrite(buffer, 1U, expected, drive->fp);
    if (written != expected) {
        return DISK_STATUS_IO_ERROR;
    }

    if (fflush(drive->fp) != 0) {
        return DISK_STATUS_IO_ERROR;
    }

    size_t end_offset = (size_t)offset + expected;
    if (end_offset > drive->image_size) {
        drive->image_size = end_offset;
    }

    return DISK_STATUS_OK;
}

static DiskStatus disk_cache_ensure(DiskDrive *drive, size_t track, size_t sector)
{
    if (drive == NULL || drive->cache == NULL) {
        return DISK_STATUS_IO_ERROR;
    }

    if (drive->cache_valid && drive->cache_track == track && drive->cache_sector == sector) {
        return DISK_STATUS_OK;
    }

    size_t physical_sector = disk_map_logical_sector(drive, sector);
    DiskStatus status = disk_read_uncached(drive, track, physical_sector, drive->cache);
    if (status != DISK_STATUS_OK) {
        return status;
    }

    drive->cache_valid = true;
    drive->cache_track = track;
    drive->cache_sector = sector;
    return DISK_STATUS_OK;
}

static void disk_parse_directory_entry_bytes(const uint8_t raw[32], DiskDirectoryEntry *entry)
{
    memset(entry, 0, sizeof(*entry));
    memcpy(entry->raw, raw, 32U);

    entry->user_number = raw[0];
    entry->is_deleted = (raw[0] == 0xE5U);
    entry->is_empty = entry->is_deleted;

    char name_padded[8];
    char ext_padded[3];
    for (size_t i = 0U; i < 8U; ++i) {
        uint8_t ch = raw[1U + i];
        if (ch >= 'a' && ch <= 'z') {
            ch = (uint8_t)(ch - ('a' - 'A'));
        }
        if (ch < 0x20U || ch == 0x7FU) {
            ch = ' ';
        }
        name_padded[i] = (char)ch;
    }

    for (size_t i = 0U; i < 3U; ++i) {
        uint8_t ch = raw[9U + i];
        if (ch >= 'a' && ch <= 'z') {
            ch = (uint8_t)(ch - ('a' - 'A'));
        }
        if (ch < 0x20U || ch == 0x7FU) {
            ch = ' ';
        }
        ext_padded[i] = (char)ch;
    }

    memcpy(entry->filename_padded, name_padded, sizeof(entry->filename_padded));
    memcpy(entry->extension_padded, ext_padded, sizeof(entry->extension_padded));

    size_t name_len = 8U;
    while (name_len > 0U && name_padded[name_len - 1U] == ' ') {
        --name_len;
    }
    memcpy(entry->filename, name_padded, name_len);
    entry->filename[name_len] = '\0';

    size_t ext_len = 3U;
    while (ext_len > 0U && ext_padded[ext_len - 1U] == ' ') {
        --ext_len;
    }
    memcpy(entry->extension, ext_padded, ext_len);
    entry->extension[ext_len] = '\0';

    entry->extent = raw[12U];
    entry->s1 = raw[13U];
    entry->s2 = raw[14U];
    entry->record_count = raw[15U];
    entry->allocation_count = 16U;
    for (size_t i = 0U; i < 16U; ++i) {
        entry->allocations[i] = raw[16U + i];
    }
}

int disk_mount(DiskDrive *drive, const char *path, const DiskGeometry *geometry)
{
    if (drive == NULL || path == NULL || geometry == NULL) {
        return -1;
    }

    DiskGeometry geom = *geometry;
    if (geom.sectors_per_track == 0U || geom.sector_size == 0U) {
        return -1;
    }

    if (geom.sector_size > SIZE_MAX / geom.sectors_per_track) {
        return -1;
    }

    FILE *fp = fopen(path, "r+b");
    bool read_only = false;
    if (fp == NULL) {
        fp = fopen(path, "rb");
        read_only = true;
        if (fp == NULL) {
            return -1;
        }
    }

    if (fseek(fp, 0L, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }

    long file_size = ftell(fp);
    if (file_size < 0) {
        fclose(fp);
        return -1;
    }

    size_t image_size = (size_t)file_size;
    size_t data_offset = 0U;

    if (fseek(fp, 0L, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }

    if (geom.allow_header) {
        size_t header_offset = 0U;
        if (disk_try_apply_header(fp, &geom, image_size, &header_offset)) {
            data_offset = header_offset;
        } else {
            if (fseek(fp, 0L, SEEK_SET) != 0) {
                fclose(fp);
                return -1;
            }
        }
    }

    if (data_offset > image_size) {
        fclose(fp);
        return -1;
    }

    image_size -= data_offset;

    size_t track_bytes = geom.sectors_per_track * geom.sector_size;

    if (track_bytes > 0U) {
        if (geom.track_count == 0U) {
            geom.track_count = image_size / track_bytes;
        } else {
            if (geom.track_count > SIZE_MAX / track_bytes) {
                fclose(fp);
                return -1;
            }
            size_t required = geom.track_count * track_bytes;
            if (required > image_size) {
                fclose(fp);
                return -1;
            }
        }
    }

    if (fseek(fp, (long)data_offset, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }

    uint8_t *cache = (uint8_t *)malloc(geom.sector_size);
    if (cache == NULL) {
        fclose(fp);
        return -1;
    }

    disk_unmount(drive);

    drive->fp = fp;
    drive->geometry = geom;
    drive->image_size = image_size;
    drive->mounted = true;
    drive->read_only = read_only;
    drive->data_offset = data_offset;
    drive->cache = cache;
    drive->cache_valid = false;
    drive->cache_track = 0U;
    drive->cache_sector = 0U;
    drive->translation_table = NULL;
    drive->translation_table_entries = 0U;

    if (geom.sectors_per_track > 0U) {
        drive->translation_table = (uint8_t *)malloc(geom.sectors_per_track);
        if (drive->translation_table == NULL) {
            disk_unmount(drive);
            return -1;
        }
        drive->translation_table_entries = geom.sectors_per_track;
        for (size_t i = 0U; i < geom.sectors_per_track; ++i) {
            drive->translation_table[i] = (uint8_t)i;
        }

        if (geom.translation_table_length > 0U) {
            if (geom.translation_table == NULL || geom.translation_table_length != geom.sectors_per_track) {
                disk_unmount(drive);
                return -1;
            }

            for (size_t i = 0U; i < geom.translation_table_length; ++i) {
                uint8_t value = geom.translation_table[i];
                if (value >= geom.sectors_per_track) {
                    disk_unmount(drive);
                    return -1;
                }
                drive->translation_table[i] = value;
            }
        }
    }

    disk_compute_metadata(drive);

    drive->directory_metadata = NULL;
    drive->allocation_vector_data = NULL;
    drive->allocation_vector_from_bios = false;

    if (drive->directory_metadata_bytes > 0U) {
        drive->directory_metadata = (uint8_t *)malloc(drive->directory_metadata_bytes);
        if (drive->directory_metadata == NULL) {
            disk_unmount(drive);
            return -1;
        }
    }

    if (drive->allocation_vector_bytes > 0U) {
        drive->allocation_vector_data = (uint8_t *)malloc(drive->allocation_vector_bytes);
        if (drive->allocation_vector_data == NULL) {
            disk_unmount(drive);
            return -1;
        }
        memset(drive->allocation_vector_data, 0, drive->allocation_vector_bytes);
    }

    if (drive->directory_metadata != NULL) {
        if (!disk_refresh_directory_metadata(drive)) {
            disk_unmount(drive);
            return -1;
        }
    } else if (drive->allocation_vector_data != NULL && !drive->allocation_vector_from_bios) {
        memset(drive->allocation_vector_data, 0, drive->allocation_vector_bytes);
    }

    return 0;
}

DiskStatus disk_read_sector(DiskDrive *drive, size_t track, size_t sector, uint8_t *buffer, size_t length)
{
    if (drive == NULL || buffer == NULL || !drive->mounted) {
        return DISK_STATUS_NOT_READY;
    }

    if (drive->geometry.sector_size == 0U || drive->geometry.sectors_per_track == 0U) {
        return DISK_STATUS_NOT_READY;
    }

    if (length < drive->geometry.sector_size) {
        return DISK_STATUS_IO_ERROR;
    }

    if (drive->cache != NULL) {
        DiskStatus status = disk_cache_ensure(drive, track, sector);
        if (status != DISK_STATUS_OK) {
            return status;
        }
        memcpy(buffer, drive->cache, drive->geometry.sector_size);
        return DISK_STATUS_OK;
    }

    size_t physical_sector = disk_map_logical_sector(drive, sector);
    return disk_read_uncached(drive, track, physical_sector, buffer);
}

DiskStatus disk_write_sector(DiskDrive *drive, size_t track, size_t sector, const uint8_t *buffer, size_t length)
{
    if (drive == NULL || buffer == NULL || !drive->mounted) {
        return DISK_STATUS_NOT_READY;
    }

    if (drive->read_only) {
        return DISK_STATUS_READ_ONLY;
    }

    if (drive->geometry.sector_size == 0U || drive->geometry.sectors_per_track == 0U) {
        return DISK_STATUS_NOT_READY;
    }

    if (length < drive->geometry.sector_size) {
        return DISK_STATUS_IO_ERROR;
    }

    size_t physical_sector = disk_map_logical_sector(drive, sector);
    DiskStatus status = disk_write_uncached(drive, track, physical_sector, buffer);
    if (status != DISK_STATUS_OK) {
        return status;
    }

    if (drive->cache != NULL) {
        memcpy(drive->cache, buffer, drive->geometry.sector_size);
        drive->cache_valid = true;
        drive->cache_track = track;
        drive->cache_sector = sector;
    }

    disk_apply_write_to_metadata(drive, track, sector, buffer);

    return DISK_STATUS_OK;
}

void disk_unmount(DiskDrive *drive)
{
    if (drive == NULL) {
        return;
    }

    if (drive->fp != NULL) {
        fclose(drive->fp);
        drive->fp = NULL;
    }

    if (drive->cache != NULL) {
        free(drive->cache);
        drive->cache = NULL;
    }

    if (drive->translation_table != NULL) {
        free(drive->translation_table);
        drive->translation_table = NULL;
    }
    drive->translation_table_entries = 0U;

    memset(&drive->geometry, 0, sizeof(drive->geometry));
    drive->image_size = 0U;
    drive->mounted = false;
    drive->read_only = false;
    drive->data_offset = 0U;
    disk_reset_metadata(drive);
    disk_invalidate_cache_internal(drive);
}

bool disk_is_mounted(const DiskDrive *drive)
{
    return drive != NULL && drive->mounted;
}

const DiskParameterBlock *disk_parameter_block(const DiskDrive *drive)
{
    if (drive == NULL || !drive->parameter_block_valid) {
        return NULL;
    }
    return &drive->parameter_block;
}

size_t disk_directory_entry_count(const DiskDrive *drive)
{
    if (drive == NULL || !drive->parameter_block_valid) {
        return 0U;
    }
    return drive->directory_entries;
}

size_t disk_allocation_vector_bytes(const DiskDrive *drive)
{
    if (drive == NULL || !drive->parameter_block_valid) {
        return 0U;
    }
    return drive->allocation_vector_bytes;
}

const uint8_t *disk_allocation_vector(const DiskDrive *drive)
{
    if (drive == NULL) {
        return NULL;
    }
    return drive->allocation_vector_data;
}

const uint8_t *disk_translation_table(const DiskDrive *drive, size_t *length)
{
    if (drive == NULL) {
        return NULL;
    }

    if (length != NULL) {
        *length = drive->translation_table_entries;
    }

    return drive->translation_table;
}

DiskStatus disk_read_directory_entry(DiskDrive *drive, size_t index, DiskDirectoryEntry *entry)
{
    if (drive == NULL || entry == NULL || !drive->mounted) {
        return DISK_STATUS_NOT_READY;
    }

    if (!drive->parameter_block_valid) {
        return DISK_STATUS_NOT_READY;
    }

    if (index >= drive->directory_entries) {
        return DISK_STATUS_BAD_ADDRESS;
    }

    if (drive->directory_metadata != NULL) {
        size_t offset = index * 32U;
        if (offset + 32U <= drive->directory_metadata_bytes) {
            disk_parse_directory_entry_bytes(&drive->directory_metadata[offset], entry);
            return DISK_STATUS_OK;
        }
    }

    size_t track_bytes = drive->geometry.sectors_per_track * drive->geometry.sector_size;
    if (track_bytes == 0U) {
        return DISK_STATUS_NOT_READY;
    }

    size_t entry_offset = drive->directory_offset + index * 32U;
    size_t track = entry_offset / track_bytes;
    size_t track_offset = entry_offset % track_bytes;
    size_t sector = track_offset / drive->geometry.sector_size;
    size_t sector_offset = track_offset % drive->geometry.sector_size;

    uint8_t raw[32];
    size_t copied = 0U;
    while (copied < sizeof(raw)) {
        DiskStatus status = disk_cache_ensure(drive, track, sector);
        if (status != DISK_STATUS_OK) {
            return status;
        }

        size_t available = drive->geometry.sector_size - sector_offset;
        size_t take = (sizeof(raw) - copied < available) ? (sizeof(raw) - copied) : available;
        memcpy(&raw[copied], drive->cache + sector_offset, take);
        copied += take;
        sector_offset = 0U;
        ++sector;
        if (sector >= drive->geometry.sectors_per_track) {
            sector = 0U;
            ++track;
        }
    }

    disk_apply_host_read_only_flag(drive, raw);
    disk_parse_directory_entry_bytes(raw, entry);
    return DISK_STATUS_OK;
}

void disk_invalidate_cache(DiskDrive *drive)
{
    if (drive == NULL) {
        return;
    }

    disk_invalidate_cache_internal(drive);
}

void disk_update_allocation_vector(DiskDrive *drive, const uint8_t *data, size_t length)
{
    if (drive == NULL || data == NULL) {
        return;
    }

    if (drive->allocation_vector_bytes == 0U || length != drive->allocation_vector_bytes) {
        return;
    }

    if (drive->allocation_vector_data == NULL) {
        drive->allocation_vector_data = (uint8_t *)malloc(drive->allocation_vector_bytes);
        if (drive->allocation_vector_data == NULL) {
            return;
        }
    }

    memcpy(drive->allocation_vector_data, data, drive->allocation_vector_bytes);
    drive->allocation_vector_from_bios = true;
}
