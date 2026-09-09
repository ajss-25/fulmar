#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static const char *const asset_names[] = {
    "Fulmar.app.zip",
    "Fulmar.app.zip.sha256",
    "Fulmar.dSYMs.zip",
    "LICENSE",
    "LocalHarness.sbom.cdx.json",
    "SHA256SUMS.txt",
    "THIRD_PARTY_NOTICES.md",
    "release-manifest.json",
    "static-security-summary.json"
};

static int fail(const char *message) {
    (void)fprintf(stderr, "Atomic public-asset publication failed: %s\n", message);
    return 1;
}

static bool safe_name(const char *name) {
    return name != NULL && name[0] != '\0' && strcmp(name, ".") != 0
        && strcmp(name, "..") != 0 && strchr(name, '/') == NULL;
}

static int asset_index(const char *name) {
    const size_t count = sizeof(asset_names) / sizeof(asset_names[0]);
    for (size_t index = 0; index < count; index += 1) {
        if (strcmp(name, asset_names[index]) == 0) {
            return (int)index;
        }
    }
    return -1;
}

static bool same_identity(const struct stat *left, const struct stat *right) {
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino;
}

static int open_attested_parent(const char *path, struct stat *identity) {
    char canonical[MAXPATHLEN];
    if (path == NULL || path[0] != '/' || realpath(path, canonical) == NULL
        || strcmp(path, canonical) != 0) {
        return -1;
    }

    struct stat before;
    if (lstat(path, &before) != 0 || !S_ISDIR(before.st_mode)
        || before.st_uid != geteuid()) {
        return -1;
    }
    const int descriptor = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0 || fstat(descriptor, identity) != 0
        || !S_ISDIR(identity->st_mode) || identity->st_uid != geteuid()
        || !same_identity(&before, identity)) {
        if (descriptor >= 0) {
            (void)close(descriptor);
        }
        return -1;
    }
    return descriptor;
}

static bool parent_path_still_matches(const char *path, const struct stat *identity) {
    struct stat current;
    return lstat(path, &current) == 0 && S_ISDIR(current.st_mode)
        && same_identity(&current, identity);
}

static bool exact_private_staging(const struct stat *value) {
    return S_ISDIR(value->st_mode) && value->st_uid == geteuid()
        && (value->st_mode & 07777) == 0700;
}

static int inspect_assets(const int staging_descriptor, const bool allow_partial,
                          bool present[sizeof(asset_names) / sizeof(asset_names[0])]) {
    const int enumeration_descriptor = dup(staging_descriptor);
    if (enumeration_descriptor < 0) {
        return -1;
    }
    DIR *const directory = fdopendir(enumeration_descriptor);
    if (directory == NULL) {
        (void)close(enumeration_descriptor);
        return -1;
    }

    errno = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        const int index = asset_index(entry->d_name);
        if (index < 0 || present[(size_t)index]) {
            (void)closedir(directory);
            return -1;
        }
        const int file_descriptor = openat(
            staging_descriptor,
            entry->d_name,
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
        );
        struct stat metadata;
        if (file_descriptor < 0 || fstat(file_descriptor, &metadata) != 0) {
            if (file_descriptor >= 0) {
                (void)close(file_descriptor);
            }
            (void)closedir(directory);
            return -1;
        }
        const mode_t permission_bits = metadata.st_mode & 07777;
        if (!S_ISREG(metadata.st_mode) || metadata.st_uid != geteuid()
            || metadata.st_nlink != 1
            || (!allow_partial && permission_bits != 0644)
            || (allow_partial && permission_bits != 0600 && permission_bits != 0644)) {
            (void)close(file_descriptor);
            (void)closedir(directory);
            return -1;
        }
        if (!allow_partial && fsync(file_descriptor) != 0) {
            (void)close(file_descriptor);
            (void)closedir(directory);
            return -1;
        }
        (void)close(file_descriptor);
        present[(size_t)index] = true;
    }
    if (errno != 0 || closedir(directory) != 0) {
        return -1;
    }

    if (!allow_partial) {
        const size_t count = sizeof(asset_names) / sizeof(asset_names[0]);
        for (size_t index = 0; index < count; index += 1) {
            if (!present[index]) {
                return -1;
            }
        }
    }
    return 0;
}

static int publish(const char *parent_path, const char *staging_name,
                   const char *destination_name) {
    if (!safe_name(staging_name) || !safe_name(destination_name)
        || strcmp(staging_name, destination_name) == 0) {
        return fail("unsafe publication name");
    }

    struct stat parent_identity;
    const int parent_descriptor = open_attested_parent(parent_path, &parent_identity);
    if (parent_descriptor < 0) {
        return fail("the destination parent is not a canonical owner-controlled directory");
    }

    struct stat staging_identity;
    struct stat unwanted_destination;
    if (fstatat(parent_descriptor, staging_name, &staging_identity, AT_SYMLINK_NOFOLLOW) != 0
        || !exact_private_staging(&staging_identity)) {
        (void)close(parent_descriptor);
        return fail("the private sibling staging directory is unsafe");
    }
    errno = 0;
    if (fstatat(parent_descriptor, destination_name, &unwanted_destination,
                AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) {
        (void)close(parent_descriptor);
        return fail("the final destination already exists");
    }

    const int staging_descriptor = openat(
        parent_descriptor,
        staging_name,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
    );
    struct stat opened_staging_identity;
    bool present[sizeof(asset_names) / sizeof(asset_names[0])] = { false };
    if (staging_descriptor < 0 || fstat(staging_descriptor, &opened_staging_identity) != 0
        || !same_identity(&staging_identity, &opened_staging_identity)
        || inspect_assets(staging_descriptor, false, present) != 0
        || fsync(staging_descriptor) != 0
        || !parent_path_still_matches(parent_path, &parent_identity)) {
        if (staging_descriptor >= 0) {
            (void)close(staging_descriptor);
        }
        (void)close(parent_descriptor);
        return fail("the staged asset set is incomplete, mutable, or replaced");
    }
    (void)close(staging_descriptor);

    errno = 0;
    if (fstatat(parent_descriptor, destination_name, &unwanted_destination,
                AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) {
        (void)close(parent_descriptor);
        return fail("the final destination appeared before publication");
    }
    if (renameatx_np(parent_descriptor, staging_name, parent_descriptor,
                     destination_name, RENAME_EXCL) != 0) {
        (void)close(parent_descriptor);
        return fail("exclusive atomic rename did not commit");
    }
    if (fsync(parent_descriptor) != 0
        || fstatat(parent_descriptor, destination_name, &unwanted_destination,
                   AT_SYMLINK_NOFOLLOW) != 0
        || !same_identity(&staging_identity, &unwanted_destination)
        || fstatat(parent_descriptor, staging_name, &opened_staging_identity,
                   AT_SYMLINK_NOFOLLOW) == 0
        || errno != ENOENT
        || !parent_path_still_matches(parent_path, &parent_identity)) {
        (void)close(parent_descriptor);
        return fail("the committed destination could not be durably re-attested");
    }
    (void)close(parent_descriptor);
    return 0;
}

static bool parse_identity_component(const char *text, uint64_t *value) {
    char *end = NULL;
    errno = 0;
    const unsigned long long parsed = strtoull(text, &end, 10);
    if (errno != 0 || end == text || end == NULL || *end != '\0') {
        return false;
    }
    *value = (uint64_t)parsed;
    return true;
}

static int cleanup_staging(const char *parent_path, const char *staging_name,
                           const char *device_text, const char *inode_text) {
    uint64_t expected_device;
    uint64_t expected_inode;
    if (!safe_name(staging_name)
        || !parse_identity_component(device_text, &expected_device)
        || !parse_identity_component(inode_text, &expected_inode)) {
        return fail("unsafe cleanup capability");
    }

    struct stat parent_identity;
    const int parent_descriptor = open_attested_parent(parent_path, &parent_identity);
    if (parent_descriptor < 0) {
        return fail("cleanup parent could not be attested");
    }
    struct stat staging_identity;
    if (fstatat(parent_descriptor, staging_name, &staging_identity,
                AT_SYMLINK_NOFOLLOW) != 0
        || !exact_private_staging(&staging_identity)
        || (uint64_t)staging_identity.st_dev != expected_device
        || (uint64_t)staging_identity.st_ino != expected_inode) {
        (void)close(parent_descriptor);
        return fail("cleanup staging identity changed");
    }
    const int staging_descriptor = openat(
        parent_descriptor,
        staging_name,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
    );
    struct stat opened_identity;
    bool present[sizeof(asset_names) / sizeof(asset_names[0])] = { false };
    if (staging_descriptor < 0 || fstat(staging_descriptor, &opened_identity) != 0
        || !same_identity(&staging_identity, &opened_identity)
        || inspect_assets(staging_descriptor, true, present) != 0) {
        if (staging_descriptor >= 0) {
            (void)close(staging_descriptor);
        }
        (void)close(parent_descriptor);
        return fail("cleanup refused an unreviewed staging tree");
    }

    const size_t count = sizeof(asset_names) / sizeof(asset_names[0]);
    for (size_t index = 0; index < count; index += 1) {
        if (present[index] && unlinkat(staging_descriptor, asset_names[index], 0) != 0) {
            (void)close(staging_descriptor);
            (void)close(parent_descriptor);
            return fail("cleanup could not remove a reviewed staged asset");
        }
    }
    if (fsync(staging_descriptor) != 0) {
        (void)close(staging_descriptor);
        (void)close(parent_descriptor);
        return fail("cleanup could not sync the emptied staging directory");
    }
    (void)close(staging_descriptor);
    if (!parent_path_still_matches(parent_path, &parent_identity)
        || unlinkat(parent_descriptor, staging_name, AT_REMOVEDIR) != 0
        || fsync(parent_descriptor) != 0) {
        (void)close(parent_descriptor);
        return fail("cleanup could not retire the private staging directory");
    }
    (void)close(parent_descriptor);
    return 0;
}

int main(const int argc, char *const argv[]) {
    if (argc == 5 && strcmp(argv[1], "publish") == 0) {
        return publish(argv[2], argv[3], argv[4]);
    }
    if (argc == 6 && strcmp(argv[1], "cleanup") == 0) {
        return cleanup_staging(argv[2], argv[3], argv[4], argv[5]);
    }
    return fail("usage: publisher publish <parent> <staging-name> <destination-name> | publisher cleanup <parent> <staging-name> <device> <inode>");
}
