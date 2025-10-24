#include "disk.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static bool read_first_entries(DiskDrive *drive)
{
    const char *expected[] = {"ALPHA.TXT", "GAMMA.BIN"};
    size_t expected_count = sizeof(expected) / sizeof(expected[0]);
    size_t found = 0U;
    size_t total = disk_directory_entry_count(drive);

    for (size_t index = 0U; index < total && found < expected_count; ++index) {
        DiskDirectoryEntry entry;
        DiskStatus status = disk_read_directory_entry(drive, index, &entry);
        if (status != DISK_STATUS_OK) {
            fprintf(stderr, "disk_read_directory_entry failed with status %d at index %zu\n", (int)status, index);
            return false;
        }

        if (entry.is_empty || entry.is_deleted) {
            continue;
        }

        char name[16];
        if (entry.extension[0] != '\0') {
            (void)snprintf(name, sizeof(name), "%s.%s", entry.filename, entry.extension);
        } else {
            (void)snprintf(name, sizeof(name), "%s", entry.filename);
        }

        if (strcmp(name, expected[found]) != 0) {
            fprintf(stderr, "Unexpected entry '%s' (expected '%s')\n", name, expected[found]);
            return false;
        }

        printf("%s\n", name);
        ++found;
    }

    if (found != expected_count) {
        fprintf(stderr, "Only found %zu entries\n", found);
        return false;
    }

    return true;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <disk_image>\n", argv[0]);
        return 1;
    }

    const char *image_path = argv[1];

    DiskDrive drive;
    memset(&drive, 0, sizeof(drive));

    uint8_t translation_table[DISK_DEFAULT_SECTORS_PER_TRACK];
    for (size_t i = 0U; i < DISK_DEFAULT_SECTORS_PER_TRACK; ++i) {
        translation_table[i] = (uint8_t)((i * 5U) % DISK_DEFAULT_SECTORS_PER_TRACK);
    }

    DiskGeometry geometry;
    memset(&geometry, 0, sizeof(geometry));
    geometry.track_count = 1U;
    geometry.sectors_per_track = DISK_DEFAULT_SECTORS_PER_TRACK;
    geometry.sector_size = DISK_DEFAULT_SECTOR_BYTES;
    geometry.translation_table = translation_table;
    geometry.translation_table_length = DISK_DEFAULT_SECTORS_PER_TRACK;

    if (disk_mount(&drive, image_path, &geometry) != 0) {
        fprintf(stderr, "Failed to mount disk image '%s'\n", image_path);
        return 2;
    }

    bool ok = read_first_entries(&drive);
    disk_unmount(&drive);

    return ok ? 0 : 3;
}
