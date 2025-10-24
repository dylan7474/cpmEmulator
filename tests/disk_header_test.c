#include "disk.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EXPECTED_SECTOR_SIZE 256U
#define EXPECTED_SECTORS_PER_TRACK 32U
#define EXPECTED_TRACKS 4U
#define EXPECTED_DIRBUF 512U

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

    if (drive.has_default_dma) {
        fprintf(stderr, "unexpected default DMA value: 0x%04X\n", drive.default_dma_address);
        ok = false;
    }

    if (!drive.has_directory_buffer || drive.directory_buffer_bytes != EXPECTED_DIRBUF) {
        fprintf(stderr, "directory buffer mismatch: has=%d size=%zu\n",
                drive.has_directory_buffer ? 1 : 0, drive.directory_buffer_bytes);
        ok = false;
    }

    if (!drive.has_attribute_hints || (drive.attribute_flags & DISK_ATTRIBUTE_FLAG_READ_ONLY) == 0U) {
        fprintf(stderr, "attribute hints missing read-only flag\n");
        ok = false;
    }

    if (!drive.header_read_only || !drive.read_only) {
        fprintf(stderr, "read-only hint was not applied to drive state\n");
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

    if (ok) {
        bool original_read_only = drive.read_only;
        bool original_header_ro = drive.header_read_only;
        bool original_host_ro = drive.host_read_only;
        bool original_has_hints = drive.has_attribute_hints;
        uint8_t original_attr_flags = drive.attribute_flags;

        drive.read_only = false;
        drive.header_read_only = false;
        drive.host_read_only = false;
        drive.has_attribute_hints = true;
        drive.attribute_flags = DISK_ATTRIBUTE_FLAG_READ_ONLY;

        uint8_t entry[32];
        memset(entry, 0, sizeof(entry));
        entry[0] = 0x01;
        memcpy(&entry[1], "HINTFILE", 8);
        memcpy(&entry[9], "TXT", 3);

        DiskStatus write_status = disk_write_directory_entry(&drive, 0U, entry);
        if (write_status != DISK_STATUS_OK) {
            fprintf(stderr, "disk_write_directory_entry failed: %d\n", (int)write_status);
            ok = false;
        } else {
            DiskDirectoryEntry loaded;
            DiskStatus read_status = disk_read_directory_entry(&drive, 0U, &loaded);
            if (read_status != DISK_STATUS_OK) {
                fprintf(stderr, "disk_read_directory_entry failed: %d\n", (int)read_status);
                ok = false;
            } else if ((loaded.raw[9] & 0x80U) == 0U) {
                fprintf(stderr, "CPMI attribute hint overlay did not persist read-only bit\n");
                ok = false;
            }
        }

        drive.read_only = original_read_only;
        drive.header_read_only = original_header_ro;
        drive.host_read_only = original_host_ro;
        drive.has_attribute_hints = original_has_hints;
        drive.attribute_flags = original_attr_flags;
    }

    free(buffer);
    disk_unmount(&drive);

    return ok ? 0 : 3;
}
