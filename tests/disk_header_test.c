#include "disk.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EXPECTED_SECTOR_SIZE 256U
#define EXPECTED_SECTORS_PER_TRACK 32U
#define EXPECTED_TRACKS 4U

static bool verify_pattern(const uint8_t *buffer, size_t length)
{
    if (buffer == NULL) {
        return false;
    }

    for (size_t i = 0U; i < length; ++i) {
        if (buffer[i] != (uint8_t)i) {
            return false;
        }
    }

    return true;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <disk image>\n", argv[0]);
        return 1;
    }

    const char *path = argv[1];

    DiskDrive drive;
    memset(&drive, 0, sizeof(drive));

    DiskGeometry geometry;
    memset(&geometry, 0, sizeof(geometry));
    geometry.sectors_per_track = DISK_DEFAULT_SECTORS_PER_TRACK;
    geometry.sector_size = DISK_DEFAULT_SECTOR_BYTES;
    geometry.allow_header = true;

    if (disk_mount(&drive, path, &geometry) != 0) {
        fprintf(stderr, "disk_mount failed for '%s'\n", path);
        return 2;
    }

    bool ok = true;

    if (drive.geometry.sector_size != EXPECTED_SECTOR_SIZE) {
        fprintf(stderr, "sector size mismatch: %zu\n", drive.geometry.sector_size);
        ok = false;
    }

    if (drive.geometry.sectors_per_track != EXPECTED_SECTORS_PER_TRACK) {
        fprintf(stderr, "sectors/track mismatch: %zu\n", drive.geometry.sectors_per_track);
        ok = false;
    }

    if (drive.geometry.track_count != EXPECTED_TRACKS) {
        fprintf(stderr, "track count mismatch: %zu\n", drive.geometry.track_count);
        ok = false;
    }

    uint8_t *buffer = (uint8_t *)malloc(EXPECTED_SECTOR_SIZE);
    if (buffer == NULL) {
        fprintf(stderr, "Failed to allocate sector buffer\n");
        ok = false;
    }

    if (ok) {
        DiskStatus status = disk_read_sector(&drive, 0U, 0U, buffer, EXPECTED_SECTOR_SIZE);
        if (status != DISK_STATUS_OK) {
            fprintf(stderr, "disk_read_sector returned %d\n", (int)status);
            ok = false;
        } else if (!verify_pattern(buffer, EXPECTED_SECTOR_SIZE)) {
            fprintf(stderr, "Sector contents did not match expected pattern\n");
            ok = false;
        }
    }

    free(buffer);
    disk_unmount(&drive);

    return ok ? 0 : 3;
}
