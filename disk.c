#include "disk.h"

#include <stdint.h>
#include <string.h>

static long compute_offset(const DiskDrive *drive, size_t track, size_t sector)
{
    if (drive->sectors_per_track == 0U || drive->sector_size == 0U) {
        return -1L;
    }

    size_t index = track * drive->sectors_per_track + sector;
    return (long)(index * drive->sector_size);
}

int disk_mount(DiskDrive *drive, const char *path, size_t sectors_per_track, size_t sector_size)
{
    if (drive == NULL || path == NULL) {
        return -1;
    }

    drive->fp = fopen(path, "r+b");
    if (drive->fp == NULL) {
        drive->fp = fopen(path, "rb");
        if (drive->fp == NULL) {
            return -1;
        }
    }

    drive->sectors_per_track = sectors_per_track;
    drive->sector_size = sector_size;
    drive->mounted = true;

    return 0;
}

int disk_read_sector(DiskDrive *drive, size_t track, size_t sector, uint8_t *buffer, size_t length)
{
    if (drive == NULL || buffer == NULL || !drive->mounted) {
        return -1;
    }

    if (length < drive->sector_size) {
        return -1;
    }

    long offset = compute_offset(drive, track, sector);
    if (offset < 0 || fseek(drive->fp, offset, SEEK_SET) != 0) {
        return -1;
    }

    size_t read = fread(buffer, 1U, drive->sector_size, drive->fp);
    if (read != drive->sector_size) {
        if (feof(drive->fp)) {
            memset(buffer, 0, drive->sector_size);
            return 0;
        }
        return -1;
    }

    return 0;
}

int disk_write_sector(DiskDrive *drive, size_t track, size_t sector, const uint8_t *buffer, size_t length)
{
    if (drive == NULL || buffer == NULL || !drive->mounted) {
        return -1;
    }

    if (length < drive->sector_size) {
        return -1;
    }

    if (drive->fp == NULL) {
        return -1;
    }

    if (fseek(drive->fp, 0L, SEEK_CUR) == -1L && ferror(drive->fp) != 0) {
        clearerr(drive->fp);
    }

    long offset = compute_offset(drive, track, sector);
    if (offset < 0 || fseek(drive->fp, offset, SEEK_SET) != 0) {
        return -1;
    }

    size_t written = fwrite(buffer, 1U, drive->sector_size, drive->fp);
    if (written != drive->sector_size) {
        return -1;
    }

    fflush(drive->fp);
    return 0;
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

    drive->sectors_per_track = 0U;
    drive->sector_size = 0U;
    drive->mounted = false;
}

bool disk_is_mounted(const DiskDrive *drive)
{
    return drive != NULL && drive->mounted;
}
