#ifndef DISK_H
#define DISK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define DISK_SECTOR_BYTES 128U

typedef struct {
    FILE *fp;
    size_t sectors_per_track;
    size_t sector_size;
    bool mounted;
} DiskDrive;

int disk_mount(DiskDrive *drive, const char *path, size_t sectors_per_track, size_t sector_size);
int disk_read_sector(DiskDrive *drive, size_t track, size_t sector, uint8_t *buffer, size_t length);
int disk_write_sector(DiskDrive *drive, size_t track, size_t sector, const uint8_t *buffer, size_t length);
void disk_unmount(DiskDrive *drive);
bool disk_is_mounted(const DiskDrive *drive);

#endif
