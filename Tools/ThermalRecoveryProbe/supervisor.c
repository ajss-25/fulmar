#include <errno.h>
#include <mach/mach_time.h>
#include <mach-o/dyld.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

static const uint64_t watchdog_milliseconds = 1000;
static const uint64_t termination_grace_milliseconds = 1000;
static volatile sig_atomic_t received_signal = 0;

static void record_signal(int signal_number) {
    if (received_signal == 0) {
        received_signal = signal_number;
    }
}

static int monotonic_milliseconds(uint64_t *result) {
    mach_timebase_info_data_t timebase;
    if (result == NULL || mach_timebase_info(&timebase) != KERN_SUCCESS || timebase.denom == 0) {
        return -1;
    }
    const uint64_t ticks = mach_continuous_time();
    const uint64_t denominator = (uint64_t)timebase.denom;
    const uint64_t numerator = (uint64_t)timebase.numer;
    const uint64_t quotient = ticks / denominator;
    const uint64_t remainder = ticks % denominator;
    if (numerator != 0 && quotient > UINT64_MAX / numerator) {
        return -1;
    }
    const uint64_t whole_nanoseconds = quotient * numerator;
    if (numerator != 0 && remainder > UINT64_MAX / numerator) {
        return -1;
    }
    const uint64_t partial_nanoseconds = (remainder * numerator) / denominator;
    if (whole_nanoseconds > UINT64_MAX - partial_nanoseconds) {
        return -1;
    }
    *result = (whole_nanoseconds + partial_nanoseconds) / 1000000;
    return 0;
}

static int elapsed_at_least(uint64_t start, uint64_t limit, int *result) {
    uint64_t now;
    if (result == NULL || monotonic_milliseconds(&now) != 0 || now < start) {
        return -1;
    }
    *result = now - start >= limit;
    return 0;
}

static int poll_exact_child(pid_t child, int *status) {
    pid_t waited;
    do {
        waited = waitpid(child, status, WNOHANG);
    } while (waited == -1 && errno == EINTR);
    if (waited == child) {
        return 1;
    }
    if (waited == 0) {
        return 0;
    }
    return -1;
}

static int child_exit_code(int status) {
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }
    return 1;
}

static int kill_and_reap_exact_child(pid_t child) {
    uint64_t grace_start;
    int status = 0;
    if (kill(child, SIGTERM) != 0 && errno != ESRCH) {
        (void)kill(child, SIGKILL);
    }
    if (monotonic_milliseconds(&grace_start) == 0) {
        for (;;) {
            const int poll_result = poll_exact_child(child, &status);
            if (poll_result == 1) {
                return 0;
            }
            if (poll_result == -1) {
                return errno == ECHILD ? 0 : -1;
            }
            int grace_expired = 0;
            if (elapsed_at_least(grace_start, termination_grace_milliseconds, &grace_expired) != 0
                || grace_expired) {
                break;
            }
            const struct timespec pause = { .tv_sec = 0, .tv_nsec = 10000000 };
            (void)nanosleep(&pause, NULL);
        }
    }
    if (kill(child, SIGKILL) != 0 && errno != ESRCH) {
        return -1;
    }
    pid_t waited;
    do {
        waited = waitpid(child, &status, 0);
    } while (waited == -1 && errno == EINTR);
    return waited == child || (waited == -1 && errno == ECHILD) ? 0 : -1;
}

static int install_signal_handlers(struct sigaction old_actions[3]) {
    const int signals[3] = { SIGHUP, SIGINT, SIGTERM };
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = record_signal;
    if (sigemptyset(&action.sa_mask) != 0) {
        return -1;
    }
    for (size_t index = 0; index < 3; index += 1) {
        if (sigaction(signals[index], &action, &old_actions[index]) != 0) {
            while (index > 0) {
                index -= 1;
                (void)sigaction(signals[index], &old_actions[index], NULL);
            }
            return -1;
        }
    }
    return 0;
}

static void restore_signal_handlers(const struct sigaction old_actions[3]) {
    const int signals[3] = { SIGHUP, SIGINT, SIGTERM };
    for (size_t index = 0; index < 3; index += 1) {
        (void)sigaction(signals[index], &old_actions[index], NULL);
    }
}

static char *current_executable_path(void) {
    uint32_t size = 0;
    if (_NSGetExecutablePath(NULL, &size) != -1 || size == 0) {
        return NULL;
    }
    char *unresolved = malloc(size);
    if (unresolved == NULL || _NSGetExecutablePath(unresolved, &size) != 0) {
        free(unresolved);
        return NULL;
    }
    char *resolved = realpath(unresolved, NULL);
    free(unresolved);
    return resolved;
}

static int spawn_sample_child(
    const char *executable,
    const char *const child_arguments[],
    size_t child_argument_count,
    pid_t *child
) {
    char **arguments = calloc(child_argument_count + 2, sizeof(char *));
    if (arguments == NULL) {
        return -1;
    }
    arguments[0] = (char *)executable;
    for (size_t index = 0; index < child_argument_count; index += 1) {
        arguments[index + 1] = (char *)child_arguments[index];
    }

    posix_spawnattr_t attributes;
    if (posix_spawnattr_init(&attributes) != 0) {
        free(arguments);
        return -1;
    }
    sigset_t default_signals;
    sigset_t empty_mask;
    int configuration_error = sigemptyset(&default_signals);
    configuration_error |= sigaddset(&default_signals, SIGHUP);
    configuration_error |= sigaddset(&default_signals, SIGINT);
    configuration_error |= sigaddset(&default_signals, SIGTERM);
    configuration_error |= sigemptyset(&empty_mask);
    configuration_error |= posix_spawnattr_setsigdefault(&attributes, &default_signals);
    configuration_error |= posix_spawnattr_setsigmask(&attributes, &empty_mask);
    configuration_error |= posix_spawnattr_setflags(
        &attributes,
        (short)(POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK)
    );
    int spawn_error = configuration_error == 0
        ? posix_spawn(child, executable, NULL, &attributes, arguments, environ)
        : configuration_error;
    (void)posix_spawnattr_destroy(&attributes);
    free(arguments);
    return spawn_error == 0 ? 0 : -1;
}

int fulmar_run_supervisor(int argument_count, char *const arguments[]) {
    const char *child_arguments[3];
    size_t child_argument_count = 0;
    int emit_test_pid = 0;
    if (argument_count == 2 && strcmp(arguments[1], "--supervise-sample") == 0) {
        child_arguments[0] = "--sample";
        child_argument_count = 1;
    } else if (argument_count == 2 && strcmp(arguments[1], "--supervise-monotonic") == 0) {
        child_arguments[0] = "--monotonic";
        child_argument_count = 1;
    } else if (argument_count == 4 && strcmp(arguments[1], "--test-supervise-sample") == 0) {
        child_arguments[0] = "--test-sample";
        child_arguments[1] = arguments[2];
        child_arguments[2] = arguments[3];
        child_argument_count = 3;
        emit_test_pid = 1;
    } else if (argument_count == 4 && strcmp(arguments[1], "--test-supervise-monotonic") == 0) {
        child_arguments[0] = "--test-monotonic";
        child_arguments[1] = arguments[2];
        child_arguments[2] = arguments[3];
        child_argument_count = 3;
        emit_test_pid = 1;
    } else {
        return 64;
    }

    received_signal = 0;
    struct sigaction old_actions[3];
    if (install_signal_handlers(old_actions) != 0) {
        return 1;
    }
    char *executable = current_executable_path();
    pid_t child = -1;
    if (executable == NULL
        || spawn_sample_child(executable, child_arguments, child_argument_count, &child) != 0) {
        free(executable);
        restore_signal_handlers(old_actions);
        return 1;
    }
    free(executable);
    if (emit_test_pid != 0) {
        (void)fprintf(stderr, "TEST_PROBE_PID=%ld\n", (long)child);
        (void)fflush(stderr);
    }

    uint64_t watchdog_start;
    if (monotonic_milliseconds(&watchdog_start) != 0) {
        (void)kill_and_reap_exact_child(child);
        const int signal_number = received_signal;
        restore_signal_handlers(old_actions);
        if (signal_number == SIGHUP || signal_number == SIGINT || signal_number == SIGTERM) {
            return 128 + signal_number;
        }
        return 1;
    }
    for (;;) {
        int status = 0;
        const int poll_result = poll_exact_child(child, &status);
        if (poll_result == 1) {
            const int signal_number = received_signal;
            restore_signal_handlers(old_actions);
            if (signal_number == SIGHUP || signal_number == SIGINT || signal_number == SIGTERM) {
                return 128 + signal_number;
            }
            return child_exit_code(status);
        }
        if (poll_result == -1) {
            restore_signal_handlers(old_actions);
            return 1;
        }
        if (received_signal == SIGHUP || received_signal == SIGINT || received_signal == SIGTERM) {
            const int signal_number = received_signal;
            const int cleanup_status = kill_and_reap_exact_child(child);
            restore_signal_handlers(old_actions);
            return cleanup_status == 0 ? 128 + signal_number : 1;
        }
        int watchdog_expired = 0;
        if (elapsed_at_least(watchdog_start, watchdog_milliseconds, &watchdog_expired) != 0) {
            (void)kill_and_reap_exact_child(child);
            restore_signal_handlers(old_actions);
            return 1;
        }
        if (watchdog_expired != 0) {
            (void)fprintf(stderr, "The native thermal probe exceeded its one-second watchdog.\n");
            const int cleanup_status = kill_and_reap_exact_child(child);
            const int signal_number = received_signal;
            restore_signal_handlers(old_actions);
            if (signal_number == SIGHUP || signal_number == SIGINT || signal_number == SIGTERM) {
                return cleanup_status == 0 ? 128 + signal_number : 1;
            }
            return cleanup_status == 0 ? 124 : 1;
        }
        const struct timespec pause = { .tv_sec = 0, .tv_nsec = 10000000 };
        (void)nanosleep(&pause, NULL);
    }
}
