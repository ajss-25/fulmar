#define __STDC_WANT_LIB_EXT1__ 1

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <util.h>

extern char **environ;

#ifdef FULMAR_TEST_SECRET_READER
#define FULMAR_TEST_UNUSED __attribute__((unused))
#else
#define FULMAR_TEST_UNUSED
#endif

static int fail(const char *message) {
    fprintf(stderr, "Fulmar signing ACL helper: %s\n", message);
    return 1;
}

static FULMAR_TEST_UNUSED long long monotonic_milliseconds(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return -1;
    return (long long)value.tv_sec * 1000 + value.tv_nsec / 1000000;
}

static bool read_password(unsigned char password[514], size_t *length) {
    const int descriptor = 196;
    struct stat details;
    if (fstat(descriptor, &details) != 0 || !S_ISREG(details.st_mode)
        || details.st_nlink != 0 || details.st_uid != getuid()
        || (details.st_mode & 0777) != 0600 || details.st_size < 1 || details.st_size > 513) {
        return false;
    }
    size_t used = 0;
    while (used < sizeof(unsigned char[514])) {
        ssize_t count = read(descriptor, password + used, sizeof(unsigned char[514]) - used);
        if (count == 0) break;
        if (count < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        used += (size_t)count;
    }
    unsigned char extra;
    if (read(descriptor, &extra, 1) != 0 || used < 1 || used > 513
        || password[used - 1] != '\n') return false;
    --used;
    for (size_t index = 0; index < used; ++index) {
        if (password[index] == '\0' || password[index] == '\r' || password[index] == '\n') return false;
    }
    *length = used;
    return true;
}

static FULMAR_TEST_UNUSED bool write_all(int descriptor, const unsigned char *bytes, size_t length) {
    size_t written = 0;
    while (written < length) {
        ssize_t count = write(descriptor, bytes + written, length - written);
        if (count < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        written += (size_t)count;
    }
    return true;
}

static FULMAR_TEST_UNUSED void terminate_child(pid_t child) {
    if (child <= 1) return;
    (void)kill(child, SIGTERM);
    long long deadline = monotonic_milliseconds() + 1000;
    while (monotonic_milliseconds() < deadline) {
        int status;
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child || result == -1) return;
        usleep(20000);
    }
    (void)kill(child, SIGKILL);
    deadline = monotonic_milliseconds() + 1000;
    while (monotonic_milliseconds() < deadline) {
        int status;
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child || result == -1) return;
        usleep(20000);
    }
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
    (void)passwordLength;
    (void)memset_s(password, sizeof(password), 0, sizeof(password));
    close(196);
    return valid ? 0 : fail("could not consume the bounded signing secret");
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
    struct stat pathDetails;
    char canonical[PATH_MAX];
    if (lstat(keychainPath, &pathDetails) != 0 || !S_ISREG(pathDetails.st_mode)
        || pathDetails.st_nlink != 1 || pathDetails.st_uid != getuid()
        || realpath(keychainPath, canonical) == NULL || strcmp(canonical, keychainPath) != 0) {
        return fail("refused an unsafe signing Keychain path");
    }

    unsigned char password[514] = {0};
    size_t passwordLength = 0;
    if (!read_password(password, &passwordLength)) {
        (void)memset_s(password, sizeof(password), 0, sizeof(password));
        return fail("could not consume the bounded signing secret");
    }
    unsetenv("FULMAR_SIGNING_SECRET_FD_V1");
    close(196);

    int master = -1;
    pid_t child = forkpty(&master, NULL, NULL, NULL);
    if (child < 0) {
        (void)memset_s(password, sizeof(password), 0, sizeof(password));
        return fail("could not create a private signing pseudo-terminal");
    }
    if (child == 0) {
        static char *emptyEnvironment[] = { NULL };
        environ = emptyEnvironment;
        setenv("PATH", "/usr/bin:/bin:/usr/sbin:/sbin", 1);
        setenv("LANG", "en_US.UTF-8", 1);
        setenv("LC_CTYPE", "UTF-8", 1);
        execl("/usr/bin/security", "/usr/bin/security", "set-key-partition-list",
            "-S", "apple-tool:,apple:", "-s", keychainPath, (char *)NULL);
        _exit(127);
    }

    int flags = fcntl(master, F_GETFL);
    if (flags < 0 || fcntl(master, F_SETFL, flags | O_NONBLOCK) != 0) {
        terminate_child(child);
        close(master);
        (void)memset_s(password, sizeof(password), 0, sizeof(password));
        return fail("could not bound the signing pseudo-terminal");
    }
    bool passwordSent = false;
    size_t transcriptBytes = 0;
    int childStatus = 0;
    bool childReaped = false;
    long long deadline = monotonic_milliseconds() + 10000;
    while (monotonic_milliseconds() >= 0 && monotonic_milliseconds() < deadline) {
        int status;
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child) { childStatus = status; childReaped = true; break; }
        if (result == -1) break;

        struct pollfd watched = { .fd = master, .events = POLLIN | POLLHUP };
        int ready = poll(&watched, 1, 100);
        if (ready < 0 && errno != EINTR) break;
        if (ready > 0 && (watched.revents & (POLLIN | POLLHUP)) != 0) {
            unsigned char buffer[512];
            ssize_t count = read(master, buffer, sizeof(buffer));
            if (count > 0) {
                transcriptBytes += (size_t)count;
                if (transcriptBytes > 4096) break;
                if (!passwordSent) {
                    unsigned char frame[513];
                    memcpy(frame, password, passwordLength);
                    frame[passwordLength] = '\n';
                    if (!write_all(master, frame, passwordLength + 1)) break;
                    (void)memset_s(frame, sizeof(frame), 0, sizeof(frame));
                    passwordSent = true;
                    (void)memset_s(password, sizeof(password), 0, sizeof(password));
                }
            } else if (count < 0 && errno != EAGAIN && errno != EINTR && errno != EIO) {
                break;
            }
        }
    }
    (void)memset_s(password, sizeof(password), 0, sizeof(password));
    close(master);
    if (!childReaped) {
        terminate_child(child);
        return fail("the signing ACL command exceeded its bounded interaction");
    }
    if (!passwordSent || !WIFEXITED(childStatus) || WEXITSTATUS(childStatus) != 0) {
        return fail("the signing ACL command rejected its private credential");
    }
    return 0;
}
#endif
