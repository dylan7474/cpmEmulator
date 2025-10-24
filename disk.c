#include "disk.h"

#include <limits.h>
#include <stdint.h>
#include <string.h>

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
    if (byte_offset > (size_t)LONG_MAX) {
        return -1L;
    }

    return (long)byte_offset;
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

    if (fseek(fp, 0L, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }

    disk_unmount(drive);

    drive->fp = fp;
    drive->geometry = geom;
    drive->image_size = image_size;
    drive->mounted = true;
    drive->read_only = read_only;

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

void disk_unmount(DiskDrive *drive)
{
    if (drive == NULL) {
        return;
    }

    if (drive->fp != NULL) {
        fclose(drive->fp);
        drive->fp = NULL;
    }

    memset(&drive->geometry, 0, sizeof(drive->geometry));
    drive->image_size = 0U;
    drive->mounted = false;
    drive->read_only = false;
}

bool disk_is_mounted(const DiskDrive *drive)
{
    return drive != NULL && drive->mounted;
}
