#define __STDC_WANT_LIB_EXT1__ 1

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int fail(const char *message) {
    fprintf(stderr, "Fulmar ephemeral Keychain helper: %s\n", message);
    return 1;
}

static bool read_password(unsigned char password[514], size_t *length) {
    const int descriptor = 196;
    struct stat details;
    if (fstat(descriptor, &details) != 0 || !S_ISREG(details.st_mode)
        || details.st_nlink != 0 || details.st_uid != getuid()
        || (details.st_mode & 0777) != 0600 || details.st_size < 2 || details.st_size > 513) {
        return false;
    }
    size_t used = 0;
    while (used < 514) {
        ssize_t count = read(descriptor, password + used, 514 - used);
        if (count == 0) break;
        if (count < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        used += (size_t)count;
    }
    unsigned char extra;
    if (read(descriptor, &extra, 1) != 0 || used < 2 || used > 513
        || password[used - 1] != '\n') return false;
    --used;
    for (size_t index = 0; index < used; ++index) {
        if (password[index] == '\0' || password[index] == '\r' || password[index] == '\n') return false;
    }
    *length = used;
    return true;
}

static void clear_password(unsigned char password[514]) {
    (void)memset_s(password, 514, 0, 514);
}

#ifdef FULMAR_TEST_SECRET_READER
int main(int argc, char **argv) {
    (void)argv;
    const char *marker = getenv("FULMAR_SIGNING_SECRET_FD_V1");
    if (argc != 1 || marker == NULL || strcmp(marker, "196") != 0) {
        return fail("requires an authenticated descriptor invocation");
    }
    unsigned char password[514] = {0};
    size_t passwordLength = 0;
    bool valid = read_password(password, &passwordLength);
    clear_password(password);
    if (!valid || passwordLength < 1 || lseek(196, 0, SEEK_SET) != 0) {
        return fail("could not consume and rewind the bounded signing secret");
    }
    return 0;
}
#else
int main(int argc, char **argv) {
    const char *marker = getenv("FULMAR_SIGNING_SECRET_FD_V1");
    if (argc != 2 || marker == NULL || strcmp(marker, "196") != 0) {
        return fail("requires an authenticated descriptor invocation");
    }
    const char *keychainPath = argv[1];
    if (keychainPath[0] != '/' || strlen(keychainPath) >= PATH_MAX
        || strchr(keychainPath, '\n') != NULL || strchr(keychainPath, '\r') != NULL) {
        return fail("received a malformed Keychain path");
    }
    const char *slash = strrchr(keychainPath, '/');
    if (slash == NULL || strcmp(slash + 1, "fulmar-ci.keychain-db") != 0) {
        return fail("requires the exact ephemeral CI Keychain filename");
    }
    size_t parentLength = (size_t)(slash - keychainPath);
    if (parentLength == 0 || parentLength >= PATH_MAX) return fail("received an unsafe Keychain parent");
    char parent[PATH_MAX];
    memcpy(parent, keychainPath, parentLength);
    parent[parentLength] = '\0';
    char canonicalParent[PATH_MAX];
    struct stat parentDetails;
    if (lstat(parent, &parentDetails) != 0 || !S_ISDIR(parentDetails.st_mode)
        || parentDetails.st_uid != getuid() || realpath(parent, canonicalParent) == NULL
        || strcmp(parent, canonicalParent) != 0) {
        return fail("refused an unsafe ephemeral Keychain parent");
    }
    struct stat absentProbe;
    if (lstat(keychainPath, &absentProbe) == 0 || errno != ENOENT) {
        return fail("refused to replace an existing Keychain path");
    }

    unsigned char password[514] = {0};
    size_t passwordLength = 0;
    if (!read_password(password, &passwordLength) || passwordLength < 1) {
        clear_password(password);
        return fail("could not consume the bounded signing secret");
    }

    SecKeychainRef keychain = NULL;
    OSStatus status = SecKeychainCreate(
        keychainPath, (UInt32)passwordLength, password, false, NULL, &keychain
    );
    if (status == errSecSuccess) {
        SecKeychainSettings settings = {
            .version = SEC_KEYCHAIN_SETTINGS_VERS1,
            .lockOnSleep = true,
            .useLockInterval = true,
            .lockInterval = 7200
        };
        status = SecKeychainSetSettings(keychain, &settings);
    }
    if (status == errSecSuccess) {
        status = SecKeychainUnlock(keychain, (UInt32)passwordLength, password, true);
    }
    if (status == errSecSuccess) status = SecKeychainSetDefault(keychain);
    CFArrayRef searchList = NULL;
    if (status == errSecSuccess) {
        const void *values[] = { keychain };
        searchList = CFArrayCreate(NULL, values, 1, &kCFTypeArrayCallBacks);
        status = searchList == NULL ? errSecAllocate : SecKeychainSetSearchList(searchList);
    }

    clear_password(password);
    bool rewound = lseek(196, 0, SEEK_SET) == 0;
    if (searchList != NULL) CFRelease(searchList);
    if (status != errSecSuccess || !rewound) {
        if (keychain != NULL) (void)SecKeychainDelete(keychain);
        if (keychain != NULL) CFRelease(keychain);
        return fail("could not create, unlock, and isolate the ephemeral Keychain");
    }
    struct stat created;
    bool safe = lstat(keychainPath, &created) == 0 && S_ISREG(created.st_mode)
        && created.st_nlink == 1 && created.st_uid == getuid();
    CFRelease(keychain);
    if (!safe) {
        (void)unlink(keychainPath);
        return fail("the new ephemeral Keychain has unsafe metadata");
    }
    return 0;
}
#endif
