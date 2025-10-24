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
} DiskGeometry;

typedef enum {
    DISK_STATUS_OK = 0,
    DISK_STATUS_NOT_READY = 1,
    DISK_STATUS_BAD_ADDRESS = 2,
    DISK_STATUS_READ_ONLY = 3,
    DISK_STATUS_IO_ERROR = 4
} DiskStatus;

typedef struct {
    FILE *fp;
    DiskGeometry geometry;
    size_t image_size;
    bool mounted;
    bool read_only;
} DiskDrive;

int disk_mount(DiskDrive *drive, const char *path, const DiskGeometry *geometry);
DiskStatus disk_read_sector(DiskDrive *drive, size_t track, size_t sector, uint8_t *buffer, size_t length);
DiskStatus disk_write_sector(DiskDrive *drive, size_t track, size_t sector, const uint8_t *buffer, size_t length);
void disk_unmount(DiskDrive *drive);
bool disk_is_mounted(const DiskDrive *drive);

static inline size_t disk_sector_size(const DiskDrive *drive)
{
    return drive != NULL ? drive->geometry.sector_size : 0U;
}

#endif
