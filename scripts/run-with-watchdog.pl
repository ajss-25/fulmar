#!/usr/bin/perl
use strict;
use warnings;
use Fcntl qw(:mode F_DUPFD F_GETFD F_SETFD FD_CLOEXEC O_RDONLY O_WRONLY O_RDWR O_CREAT O_EXCL O_NOFOLLOW);
use FindBin qw($Bin);
use lib $Bin;
use FulmarWatchdogCapabilityJanitor qw(janitor_capabilities);
use FulmarWatchdogSample qw(parse_process_group_sample);
use IO::Select;
use POSIX qw(:sys_wait_h dup dup2 setsid);
use Socket qw(AF_UNIX SOCK_DGRAM PF_UNSPEC MSG_DONTWAIT MSG_PEEK);
use Time::HiRes qw(clock_gettime sleep CLOCK_MONOTONIC);

($ENV{FULMAR_WATCHDOG_CLEAN_LAUNCH_V1} // '') eq '1'
    or die "run-with-watchdog.pl is internal; invoke scripts/run-with-watchdog.sh so the supervisor starts in a clean environment.\n";
delete($ENV{FULMAR_WATCHDOG_CLEAN_LAUNCH_V1});

# The public launcher transmits its exact allowlist through one shell-created,
# owner-only, already-unlinked here-document descriptor. In particular, no
# caller-supplied secret is converted into a bootstrap argv assignment. Read a
# bounded snapshot, attest the open object before and after, then close it.
my $bootstrap_fd = delete($ENV{FULMAR_WATCHDOG_BOOTSTRAP_FD_V1}) // '';
$bootstrap_fd eq '9' or die "watchdog bootstrap descriptor is missing or malformed.\n";
my $bootstrap_dup = dup(9);
defined($bootstrap_dup) && $bootstrap_dup >= 0
    or die "watchdog bootstrap descriptor could not be duplicated.\n";
open(my $bootstrap_handle, "<&=$bootstrap_dup")
    or die "watchdog bootstrap descriptor could not be opened.\n";
POSIX::close(9) == 0
    or die "watchdog bootstrap descriptor could not be retired.\n";
my @bootstrap_before = stat($bootstrap_handle);
@bootstrap_before && S_ISREG($bootstrap_before[2]) && $bootstrap_before[3] == 0
    && $bootstrap_before[4] == $< && ($bootstrap_before[2] & 0777) == 0600
    && $bootstrap_before[7] >= 32 && $bootstrap_before[7] <= 65_536
    or die "watchdog bootstrap descriptor has unsafe metadata.\n";
defined(sysseek($bootstrap_handle, 0, 0))
    or die "watchdog bootstrap descriptor could not be rewound.\n";
my $bootstrap_bytes = '';
while (length($bootstrap_bytes) <= 65_536) {
    my $chunk = '';
    my $count = sysread($bootstrap_handle, $chunk, 8_192);
    defined($count) or die "watchdog bootstrap descriptor could not be read.\n";
    last if $count == 0;
    $bootstrap_bytes .= $chunk;
}
my @bootstrap_after = stat($bootstrap_handle);
close($bootstrap_handle);
@bootstrap_after
    && join(':', @bootstrap_before[0, 1, 2, 3, 4, 7]) eq
       join(':', @bootstrap_after[0, 1, 2, 3, 4, 7])
    && length($bootstrap_bytes) == $bootstrap_before[7]
    && length($bootstrap_bytes) <= 65_536
    or die "watchdog bootstrap descriptor changed while being consumed.\n";

my @forwarded_names = qw(
    CI GITHUB_ACTIONS DEVELOPER_DIR
    FULMAR_CI_REQUIRE_CURRENT_CANDIDATE_TESTS FULMAR_CLEAN_RELEASE_MODE
    FULMAR_INTERNAL_WATCHDOG_DEPTH FULMAR_RELEASE_EVIDENCE_TEST_KILL_AT
    FULMAR_RELEASE_EVIDENCE_TEST_ONLY FULMAR_RELEASE_EVIDENCE_TEST_VERIFIER
    FULMAR_ROOT_WATCHDOG_CAPABILITY_V1 FULMAR_ROOT_WATCHDOG_FD_V1
    FULMAR_ROOT_WATCHDOG_NONCE_V1 FULMAR_ROOT_WATCHDOG_PGID_V1
    FULMAR_ROOT_WATCHDOG_PID_V1 FULMAR_SWIFT_BUILD_JOBS
    FULMAR_SWIFT_WATCHDOG_EMERGENCY_RSS_BYTES FULMAR_SWIFT_WATCHDOG_RSS_BYTES
    FULMAR_SWIFT_WATCHDOG_RSS_GRACE_SECONDS FULMAR_SWIFT_WATCHDOG_SECONDS
    FULMAR_THERMAL_RECOVERY_TEST_PROBE_V1 FULMAR_AUTH_TOKEN_FD_V1
    FULMAR_SIGNING_SECRET_FD_V1 LOCAL_HARNESS_ALLOW_PRIVATE_ROOT
    LOCAL_HARNESS_AUTH_TOKEN LOCAL_HARNESS_CANARY_STATE
    LOCAL_HARNESS_CLEAN_RELEASE_ENVIRONMENT LOCAL_HARNESS_CLONED_DSH_SOURCE
    LOCAL_HARNESS_DSH_DIR LOCAL_HARNESS_NODE_BIN LOCAL_HARNESS_NOTARY_PROFILE
    LOCAL_HARNESS_READONLY_ROOTS LOCAL_HARNESS_REQUIRE_NONEMPTY_CLONE
    LOCAL_HARNESS_REQUIRE_STABLE_SIGNING LOCAL_HARNESS_SIGNING_KEYCHAIN
    LOCAL_HARNESS_SIGNING_KEYCHAIN_PASSWORD LOCAL_HARNESS_SIGN_IDENTITY
    LOCAL_HARNESS_SIGN_TIMESTAMP LOCAL_HARNESS_JS_TEST_ISOLATION_ROOT
    LOCAL_HARNESS_TEST_APP_PATH LOCAL_HARNESS_TEST_NODE
    LOCAL_HARNESS_UPDATE_ARCHIVE_TEST_PATH REQUESTED_BUILD_JOBS REQUESTED_PARALLELISM
);
my %forwarded_allowlist = map { $_ => 1 } @forwarded_names;
my @bootstrap_lines = split(/\n/, $bootstrap_bytes, -1);
pop(@bootstrap_lines) if @bootstrap_lines && $bootstrap_lines[-1] eq '';
shift(@bootstrap_lines) eq 'FULMAR_WATCHDOG_BOOTSTRAP_V2'
    or die "watchdog bootstrap descriptor has an invalid version.\n";
@bootstrap_lines == @forwarded_names * 3
    or die "watchdog bootstrap descriptor has an invalid field count.\n";
my %forwarded;
while (@bootstrap_lines) {
    my ($name, $present, $value) = splice(@bootstrap_lines, 0, 3);
    exists($forwarded_allowlist{$name}) && !exists($forwarded{$name})
        && ($present eq '' || $present eq 'x')
        && ($present eq 'x' || $value eq '')
        && $value !~ /[\r\n\0]/
        or die "watchdog bootstrap descriptor has a malformed field.\n";
    $forwarded{$name} = $value if $present eq 'x';
}
for my $name (@forwarded_names) {
    exists($forwarded_allowlist{$name}) or die "watchdog bootstrap allowlist changed unexpectedly.\n";
}
undef($bootstrap_bytes);

sub descriptor_is_private_secret {
    my ($descriptor) = @_;
    my $duplicate = dup($descriptor);
    return 0 unless defined($duplicate) && $duplicate >= 0;
    open(my $handle, "<&=$duplicate") or return 0;
    my @details = stat($handle);
    close($handle);
    return @details && S_ISREG($details[2]) && $details[3] == 0
        && $details[4] == $< && ($details[2] & 0777) == 0600
        && $details[7] >= 1 && $details[7] <= 4_097;
}

sub private_secret_failure {
    my ($message) = @_;
    print STDERR "$message\n";
    CORE::exit(126);
}

sub close_private_secret_descriptors {
    for my $entry (['FULMAR_AUTH_TOKEN_FD_V1', 195], ['FULMAR_SIGNING_SECRET_FD_V1', 196]) {
        my ($marker, $descriptor) = @$entry;
        next unless ($ENV{$marker} // '') eq "$descriptor";
        POSIX::close($descriptor);
        delete($ENV{$marker});
    }
}

sub install_private_secret_descriptor {
    my ($value, $descriptor, $marker) = @_;
    open(my $entropy, '<', '/dev/urandom')
        or private_secret_failure("watchdog could not open its private-secret entropy source.");
    my $random = '';
    sysread($entropy, $random, 16) == 16
        or private_secret_failure("watchdog could not read private-secret entropy.");
    close($entropy);
    my $path = "/private/tmp/fulmar-watchdog-secret.$$." . unpack('H*', $random);
    my $old_umask = umask(0077);
    my $created = sysopen(my $handle, $path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    umask($old_umask);
    $created or private_secret_failure("watchdog could not create a private secret descriptor.");
    my @before = stat($handle);
    @before && S_ISREG($before[2]) && $before[3] == 1 && $before[4] == $<
        && ($before[2] & 0777) == 0600 && $before[7] == 0
        or private_secret_failure("watchdog created a private secret descriptor with unsafe metadata.");
    unlink($path)
        or private_secret_failure("watchdog could not unlink its private secret descriptor.");
    my @unpublished = stat($handle);
    @unpublished
        && join(':', @before[0, 1, 2, 4]) eq join(':', @unpublished[0, 1, 2, 4])
        && $unpublished[3] == 0 && ($unpublished[2] & 0777) == 0600
        && $unpublished[7] == 0
        or private_secret_failure("watchdog private secret descriptor did not become anonymous.");
    my $frame = "$value\n";
    my $written = syswrite($handle, $frame);
    defined($written) && $written == length($frame)
        && defined(sysseek($handle, 0, 0))
        or private_secret_failure("watchdog could not publish a private secret frame.");
    my @after = stat($handle);
    @after && join(':', @unpublished[0, 1, 2, 4]) eq join(':', @after[0, 1, 2, 4])
        && $after[3] == 0 && ($after[2] & 0777) == 0600
        && $after[7] == length($frame)
        or private_secret_failure("watchdog private secret descriptor changed before publication.");
    fcntl($handle, F_SETFD, 0) == 0
        or private_secret_failure("watchdog could not prepare a private secret descriptor.");
    dup2(fileno($handle), $descriptor) >= 0
        or private_secret_failure("watchdog could not install a private secret descriptor.");
    close($handle) if fileno($handle) != $descriptor;
    $frame = "\0" x length($frame);
    $ENV{$marker} = "$descriptor";
}

my $signing_password = delete($forwarded{LOCAL_HARNESS_SIGNING_KEYCHAIN_PASSWORD});
if (defined($signing_password)) {
    length($signing_password) <= 512
        or private_secret_failure("watchdog signing secret exceeds its byte limit.");
    !exists($forwarded{FULMAR_SIGNING_SECRET_FD_V1})
        or private_secret_failure("watchdog received conflicting signing-secret transports.");
    install_private_secret_descriptor($signing_password, 196, 'FULMAR_SIGNING_SECRET_FD_V1');
    undef($signing_password);
} elsif (exists($forwarded{FULMAR_SIGNING_SECRET_FD_V1})) {
    $forwarded{FULMAR_SIGNING_SECRET_FD_V1} eq '196' && descriptor_is_private_secret(196)
        or private_secret_failure("watchdog inherited an invalid signing-secret descriptor.");
    $ENV{FULMAR_SIGNING_SECRET_FD_V1} = '196';
}

my $auth_token = delete($forwarded{LOCAL_HARNESS_AUTH_TOKEN});
if (defined($auth_token)) {
    length($auth_token) >= 1 && length($auth_token) <= 4_096
        or private_secret_failure("watchdog auth secret exceeds its byte limit.");
    !exists($forwarded{FULMAR_AUTH_TOKEN_FD_V1})
        or private_secret_failure("watchdog received conflicting auth-secret transports.");
    install_private_secret_descriptor($auth_token, 195, 'FULMAR_AUTH_TOKEN_FD_V1');
    undef($auth_token);
} elsif (exists($forwarded{FULMAR_AUTH_TOKEN_FD_V1})) {
    $forwarded{FULMAR_AUTH_TOKEN_FD_V1} eq '195' && descriptor_is_private_secret(195)
        or private_secret_failure("watchdog inherited an invalid auth-secret descriptor.");
    $ENV{FULMAR_AUTH_TOKEN_FD_V1} = '195';
}

for my $name (keys(%forwarded)) {
    next if $name eq 'FULMAR_SIGNING_SECRET_FD_V1' || $name eq 'FULMAR_AUTH_TOKEN_FD_V1';
    $ENV{$name} = $forwarded{$name};
}
undef(%forwarded);

sub usage {
    die "usage: run-with-watchdog.pl [--inherit-root] --seconds <1..21600> --max-rss-bytes <bytes> --rss-grace-seconds <0..300> --emergency-rss-bytes <bytes> [--status-file <absolute-path>] [--lock-dir </private/tmp/name.lock>] [--lock-wait-seconds <0..600>] [--lock-successor-pid <direct-parent-pid> --lock-successor-token <64hex>] --label <text> -- <command> [argument ...]\n";
}

sub bounded_inspector_status {
    my (@arguments) = @_;
    my $inspector_pid = fork();
    return undef unless defined($inspector_pid);
    if ($inspector_pid == 0) {
        # Infrastructure inspectors are never secret consumers. Close both
        # fixed transports before any exec, even during preflight when the
        # supervising Perl process still owns the intended command's copy.
        POSIX::close(195);
        POSIX::close(196);
        open(STDOUT, '>', '/dev/null') or CORE::exit(127);
        open(STDERR, '>', '/dev/null') or CORE::exit(127);
        exec {"$Bin/../VendorRuntime/node-v22.23.1-darwin-arm64/bin/node"}
            "$Bin/../VendorRuntime/node-v22.23.1-darwin-arm64/bin/node",
            "$Bin/bounded-process-group-inspector.mjs", @arguments;
        CORE::exit(127);
    }
    my $deadline = clock_gettime(CLOCK_MONOTONIC) + 2;
    while (clock_gettime(CLOCK_MONOTONIC) < $deadline) {
        my $result = waitpid($inspector_pid, WNOHANG);
        return WIFEXITED($?) ? WEXITSTATUS($?) : 126 if $result == $inspector_pid;
        return 126 if $result == -1;
        sleep(0.01);
    }
    kill(9, $inspector_pid);
    my $kill_deadline = clock_gettime(CLOCK_MONOTONIC) + 0.5;
    while (clock_gettime(CLOCK_MONOTONIC) < $kill_deadline) {
        my $result = waitpid($inspector_pid, WNOHANG);
        last if $result == $inspector_pid || $result == -1;
        sleep(0.01);
    }
    return 126;
}

my $inherit_root = @ARGV && $ARGV[0] eq '--inherit-root' ? 1 : 0;
shift(@ARGV) if $inherit_root;
@ARGV >= 12 or usage();
my @root_marker_names = qw(
    FULMAR_INTERNAL_WATCHDOG_DEPTH FULMAR_ROOT_WATCHDOG_PGID_V1
    FULMAR_ROOT_WATCHDOG_PID_V1 FULMAR_ROOT_WATCHDOG_CAPABILITY_V1
    FULMAR_ROOT_WATCHDOG_NONCE_V1 FULMAR_ROOT_WATCHDOG_FD_V1
);
my $capability_fd_number = 198;
my $inherited_capability_payload = '';
my $capability_dup = dup($capability_fd_number);
if (defined($capability_dup) && $capability_dup >= 0) {
    if (open(my $capability_probe, "+<&=$capability_dup")) {
        recv($capability_probe, $inherited_capability_payload, 512, MSG_PEEK | MSG_DONTWAIT);
        close($capability_probe);
    }
}
my $has_inherited_capability = $inherited_capability_payload =~ /\AFULMAR_ROOT_WATCHDOG_V1:/ ? 1 : 0;
my $has_any_root_marker = (grep { exists($ENV{$_}) } @root_marker_names) || $has_inherited_capability;
my $watchdog_depth = $ENV{FULMAR_INTERNAL_WATCHDOG_DEPTH} // 0;
shift(@ARGV) eq '--seconds' or usage();
my $seconds = shift(@ARGV);
$seconds =~ /\A[0-9]+\z/ && $seconds >= 1 && $seconds <= 21_600 or usage();
shift(@ARGV) eq '--max-rss-bytes' or usage();
my $maximum_rss_bytes = shift(@ARGV);
$maximum_rss_bytes =~ /\A[0-9]+\z/
    && $maximum_rss_bytes >= 64 * 1_024 * 1_024
    && $maximum_rss_bytes <= 48 * 1_024 * 1_024 * 1_024 or usage();
shift(@ARGV) eq '--rss-grace-seconds' or usage();
my $rss_grace_seconds = shift(@ARGV);
$rss_grace_seconds =~ /\A[0-9]+\z/ && $rss_grace_seconds <= 300 or usage();
shift(@ARGV) eq '--emergency-rss-bytes' or usage();
my $emergency_rss_bytes = shift(@ARGV);
$emergency_rss_bytes =~ /\A[0-9]+\z/
    && $emergency_rss_bytes >= $maximum_rss_bytes
    && $emergency_rss_bytes <= 48 * 1_024 * 1_024 * 1_024 or usage();
my $status_file;
if (@ARGV >= 2 && $ARGV[0] eq '--status-file') {
    shift(@ARGV);
    $status_file = shift(@ARGV);
    defined($status_file) && $status_file =~ m{\A/} && length($status_file) <= 1_024
        && $status_file !~ /[\r\n\0]/ or usage();
}
my $lock_dir;
my $lock_wait_seconds = 60;
if (@ARGV >= 2 && $ARGV[0] eq '--lock-dir') {
    shift(@ARGV);
    $lock_dir = shift(@ARGV);
    defined($lock_dir) && $lock_dir =~ m{\A/private/tmp/[A-Za-z0-9._-]{1,160}\.lock\z}
        && length($lock_dir) <= 220 or usage();
}
if (@ARGV >= 2 && $ARGV[0] eq '--lock-wait-seconds') {
    shift(@ARGV);
    $lock_wait_seconds = shift(@ARGV);
    defined($lock_wait_seconds) && $lock_wait_seconds =~ /\A[0-9]+\z/
        && $lock_wait_seconds <= 600 or usage();
}
my ($lock_successor_pid, $lock_successor_token);
if (@ARGV >= 4 && $ARGV[0] eq '--lock-successor-pid') {
    shift(@ARGV);
    $lock_successor_pid = shift(@ARGV);
    shift(@ARGV) eq '--lock-successor-token' or usage();
    $lock_successor_token = shift(@ARGV);
    defined($lock_dir) && defined($lock_successor_pid)
        && $lock_successor_pid =~ /\A[0-9]+\z/ && $lock_successor_pid > 1
        && $lock_successor_pid == getppid()
        && defined($lock_successor_token)
        && $lock_successor_token =~ /\A[a-f0-9]{64}\z/ or usage();
}
shift(@ARGV) eq '--label' or usage();
my $label = shift(@ARGV);
length($label) >= 1 && length($label) <= 128 && $label !~ /[\r\n\0]/ or usage();
shift(@ARGV) eq '--' or usage();
@ARGV >= 1 or usage();
my $owned_capability_path;
my $capability_published = 0;
my ($root_capability_socket, $child_capability_socket);
my $owned_lock_dir;
my $owned_lock_owner;
my $owned_lock_record = '';
my $root_group_proven_empty = 0;
my $tree_proof_fd_number = 197;
my $tree_proof_valid = 0;
my $tree_proof_status;
my ($tree_proof_reader, $tree_proof_writer);

sub finish {
    my ($code) = @_;
    my $final_code = $code;
    if ($capability_published && defined($owned_capability_path)
        && $owned_capability_path =~ m{\A/private/tmp/fulmar-watchdog-capability\.[0-9]+\.[a-f0-9]{64}\z}) {
        if (!$root_group_proven_empty) {
            print STDERR "$label retained its capability because group emptiness was not proven.\n";
            $final_code = 126;
        } elsif (!unlink($owned_capability_path)) {
            print STDERR "$label could not remove its drained root capability safely.\n";
            $final_code = 126;
        }
    }
    if (defined($owned_lock_dir)) {
        if (!$root_group_proven_empty) {
            print STDERR "$label retained its root lock because group emptiness was not proven.\n";
            $final_code = 126;
        } elsif (defined($owned_lock_owner)
            && sysopen(my $owner_handle, $owned_lock_owner, O_RDONLY | O_NOFOLLOW)) {
            my @details = stat($owner_handle);
            my $bytes = '';
            my $read_count = sysread($owner_handle, $bytes, 1_025);
            close($owner_handle);
            if (@details && $details[3] == 1 && $details[4] == $<
                && ($details[2] & 0777) == 0600 && $details[7] <= 1_024
                && defined($read_count) && $read_count == $details[7]
                && $bytes eq $owned_lock_record) {
                if (defined($lock_successor_pid) && $final_code == 0) {
                    my $successor_staging = "$owned_lock_dir/successor.staging";
                    my $successor_record = "FULMAR_LOCK_SUCCESSOR_V1\n$lock_successor_pid\n$lock_successor_token\n";
                    my $successor_handle;
                    if (!sysopen($successor_handle, $successor_staging,
                            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600)
                        || syswrite($successor_handle, $successor_record) != length($successor_record)
                        || !close($successor_handle) || !chmod(0600, $successor_staging)
                        || !rename($successor_staging, $owned_lock_owner)) {
                        close($successor_handle) if defined($successor_handle);
                        unlink($successor_staging);
                        print STDERR "$label could not transfer its drained root lock to the direct parent.\n";
                        $final_code = 126;
                    } else {
                        undef($owned_lock_dir);
                        undef($owned_lock_owner);
                    }
                } elsif (!unlink($owned_lock_owner) || !rmdir($owned_lock_dir)) {
                    print STDERR "$label could not remove its drained root lock safely.\n";
                    $final_code = 126;
                }
            } else {
                print STDERR "$label refused to remove a changed root-lock owner record.\n";
                $final_code = 126;
            }
        } else {
            print STDERR "$label could not reopen its root-lock owner record safely.\n";
            $final_code = 126;
        }
    }
    close($root_capability_socket) if defined($root_capability_socket);
    close($child_capability_socket) if defined($child_capability_socket);
    close($tree_proof_reader) if defined($tree_proof_reader);
    close($tree_proof_writer) if defined($tree_proof_writer);
    # The receipt is the final irreversible publication boundary. Nothing after
    # it may change the reported result.
    if (defined($status_file)) {
        my $status_handle;
        if (!sysopen($status_handle, $status_file, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600)) {
            print STDERR "$label could not publish its exclusive bounded status receipt: $!\n";
            CORE::exit(126);
        }
        my $bytes = "$final_code\n";
        if (syswrite($status_handle, $bytes) != length($bytes) || !close($status_handle)) {
            unlink($status_file);
            print STDERR "$label could not complete its bounded status receipt.\n";
            CORE::exit(126);
        }
    }
    CORE::exit($final_code);
}

if ($has_any_root_marker) {
    my $marker_set_is_valid = $watchdog_depth =~ /\A[0-9]+\z/ && $watchdog_depth >= 1 && $watchdog_depth <= 8
        && ($ENV{FULMAR_ROOT_WATCHDOG_PGID_V1} // '') =~ /\A[0-9]+\z/
        && ($ENV{FULMAR_ROOT_WATCHDOG_PID_V1} // '') =~ /\A[0-9]+\z/
        && ($ENV{FULMAR_ROOT_WATCHDOG_NONCE_V1} // '') =~ /\A[a-f0-9]{64}\z/
        && ($ENV{FULMAR_ROOT_WATCHDOG_FD_V1} // '') eq "$capability_fd_number"
        && ($ENV{FULMAR_ROOT_WATCHDOG_CAPABILITY_V1} // '') eq
            "/private/tmp/fulmar-watchdog-capability.$ENV{FULMAR_ROOT_WATCHDOG_PID_V1}.$ENV{FULMAR_ROOT_WATCHDOG_NONCE_V1}";
    if ($marker_set_is_valid) {
        my $expected_payload = "FULMAR_ROOT_WATCHDOG_V1:$ENV{FULMAR_ROOT_WATCHDOG_NONCE_V1}:$ENV{FULMAR_ROOT_WATCHDOG_PID_V1}:$ENV{FULMAR_ROOT_WATCHDOG_PGID_V1}";
        $marker_set_is_valid = $has_inherited_capability && $inherited_capability_payload eq $expected_payload;
    }
    if (!$marker_set_is_valid) {
        print STDERR "$label refused a partial or malformed root-watchdog capability.\n";
        finish(126);
    }
}
if (!$has_any_root_marker && !$inherit_root) {
    my $ancestor_status = bounded_inspector_status('detect-root', getpgrp());
    if (!defined($ancestor_status) || $ancestor_status != 1) {
        print STDERR "$label refused a stripped or ambiguous ancestor root-watchdog capability.\n";
        finish(126);
    }
}

# Watchdogs are process-group roots, never nestable wrappers. A nested setsid
# would escape the outer supervisor's RSS accounting and TERM/KILL boundary.
# Release orchestration must invoke each bounded gate directly instead.
if ($watchdog_depth > 0 && !$inherit_root) {
    print STDERR "$label refused unsafe nested watchdog composition.\n";
    finish(126);
}

my $forwarded_signal = 0;
$SIG{INT} = sub { $forwarded_signal = 2; };
$SIG{TERM} = sub { $forwarded_signal = 15; };
$SIG{HUP} = sub { $forwarded_signal = 1; };

if (!$inherit_root) {
    # Only a conclusively fresh root performs stale-capability recovery. The
    # janitor independently reattests every retained record and safe lock
    # reference; uncertainty leaves the record in place and blocks startup.
    my $janitor = janitor_capabilities(
        directory => '/private/tmp',
        effective_uid => $<,
        sample_group => sub { process_group_sample($_[0]) },
        interrupted => sub { $forwarded_signal != 0 },
    );
    if (!$janitor->{ok}) {
        print STDERR "$label refused ambiguous stale-capability recovery: $janitor->{message}.\n";
        finish($forwarded_signal ? 128 + $forwarded_signal : 126);
    }
    finish(128 + $forwarded_signal) if $forwarded_signal;
}

if ($inherit_root) {
    if (defined($lock_dir)) {
        print STDERR "$label refused lock ownership in a logical inherited watchdog.\n";
        finish(126);
    }
    if (defined($lock_successor_pid)) {
        print STDERR "$label refused lock transfer in a logical inherited watchdog.\n";
        finish(126);
    }
    my $root_pgid = $ENV{FULMAR_ROOT_WATCHDOG_PGID_V1} // '';
    my $root_pid = $ENV{FULMAR_ROOT_WATCHDOG_PID_V1} // '';
    my $capability = $ENV{FULMAR_ROOT_WATCHDOG_CAPABILITY_V1} // '';
    my $nonce = $ENV{FULMAR_ROOT_WATCHDOG_NONCE_V1} // '';
    my @record;
    if ($capability =~ m{\A/private/tmp/fulmar-watchdog-capability\.[0-9]+\.[a-f0-9]{64}\z}
        && sysopen(my $record_handle, $capability, O_RDONLY | O_NOFOLLOW)) {
        my @details = stat($record_handle);
        if (@details && $details[3] == 1 && $details[4] == $<
            && ($details[2] & 0777) == 0600 && $details[7] >= 68 && $details[7] <= 256) {
        @record = <$record_handle>;
        }
        close($record_handle);
        chomp(@record);
    }
    if ($watchdog_depth < 1 || $root_pgid !~ /\A[0-9]+\z/ || $root_pid !~ /\A[0-9]+\z/
        || $root_pgid <= 1 || $root_pid <= 1 || getpgrp() != $root_pgid || !kill(0, $root_pid)) {
        print STDERR "$label refused an unattested inherited watchdog group.\n";
        finish(126);
    }
    if (@record != 3 || $record[0] ne $root_pid || $record[1] ne $root_pgid || $record[2] ne $nonce) {
        print STDERR "$label refused a stale or replayed root-watchdog capability.\n";
        finish(126);
    }
    my $root_attestation = bounded_inspector_status(
        'root-attest', $root_pid, $root_pgid, $capability, $nonce
    );
    if (!defined($root_attestation) || $root_attestation != 0) {
        print STDERR "$label refused a forged root-watchdog parent relationship.\n";
        finish(126);
    }
    my $inherited_child = fork();
    defined($inherited_child) or do {
        print STDERR "$label could not fork its inherited command.\n";
        finish(126);
    };
    if ($inherited_child == 0) {
        exec { $ARGV[0] } @ARGV;
        die "inherited watchdog could not execute command: $!\n";
    }
    # The inherited command received its own forked copies. The logical-stage
    # supervisor must not retain a readable auth or signing secret while it
    # waits, samples RSS, or handles cancellation.
    close_private_secret_descriptors();
    my $inherited_deadline = clock_gettime(CLOCK_MONOTONIC) + $seconds;
    my $inherited_status;
    my $inherited_rss_over_limit_since;
    my $inherited_last_rss_sample = 0;
    my $inherited_sample_failures = 0;
    my $inherited_failure = '';
    my $inherited_failure_status = 0;
    while (1) {
        my $result = waitpid($inherited_child, WNOHANG);
        if ($result == $inherited_child) { $inherited_status = $?; last; }
        if ($result == -1) {
            print STDERR "$label lost its inherited command leader.\n";
            finish(126);
        }
        my $now = clock_gettime(CLOCK_MONOTONIC);
        if ($now - $inherited_last_rss_sample >= 0.25) {
            # A logical stage does not create a nested session. Its conservative
            # bound samples the complete authenticated root PGID, so every byte
            # remains visible to both this tighter stage profile and the outer
            # aggregate supervisor.
            my $sample = process_group_sample($root_pgid);
            if (!defined($sample)) {
                ++$inherited_sample_failures;
                if ($inherited_sample_failures >= 3) {
                    $inherited_failure = 'root-group RSS sampling failed three consecutive times';
                    $inherited_failure_status = 126;
                }
            } else {
                $inherited_sample_failures = 0;
                if ($sample->{rss_bytes} >= $emergency_rss_bytes) {
                    $inherited_failure = "root-group RSS reached the stage emergency limit of $emergency_rss_bytes bytes";
                    $inherited_failure_status = 125;
                } elsif ($sample->{rss_bytes} > $maximum_rss_bytes) {
                    $inherited_rss_over_limit_since = $now unless defined($inherited_rss_over_limit_since);
                    if ($now - $inherited_rss_over_limit_since >= $rss_grace_seconds) {
                        $inherited_failure = "root-group RSS remained above the stage limit of $maximum_rss_bytes bytes for $rss_grace_seconds seconds";
                        $inherited_failure_status = 125;
                    }
                } else {
                    undef($inherited_rss_over_limit_since);
                }
            }
            $inherited_last_rss_sample = $now;
        }
        last if $inherited_failure ne '' || $forwarded_signal || $now >= $inherited_deadline;
        sleep(0.05);
    }
    if (!defined($inherited_status)) {
        my $signal = $forwarded_signal || 15;
        kill($signal, $inherited_child);
        my $term_deadline = clock_gettime(CLOCK_MONOTONIC) + 3;
        while (clock_gettime(CLOCK_MONOTONIC) < $term_deadline) {
            my $result = waitpid($inherited_child, WNOHANG);
            if ($result == $inherited_child) { $inherited_status = $?; last; }
            if ($result == -1) { last; }
            sleep(0.05);
        }
        if (!defined($inherited_status)) {
            kill(9, $inherited_child);
            my $kill_deadline = clock_gettime(CLOCK_MONOTONIC) + 2;
            while (clock_gettime(CLOCK_MONOTONIC) < $kill_deadline) {
                my $result = waitpid($inherited_child, WNOHANG);
                if ($result == $inherited_child) { $inherited_status = $?; last; }
                if ($result == -1) { last; }
                sleep(0.05);
            }
        }
        if (!defined($inherited_status)) {
            print STDERR "$label could not reap its inherited command after bounded TERM/KILL cleanup.\n";
            finish(126);
        }
        if ($forwarded_signal) { finish(128 + $forwarded_signal); }
        if ($inherited_failure ne '') {
            print STDERR "$label failed its inherited supervisor: $inherited_failure; final group drain remains owned by the outer root.\n";
            finish($inherited_failure_status);
        }
        print STDERR "$label exceeded its ${seconds}-second inherited watchdog; root-group cleanup remains owned by the outer supervisor.\n";
        finish(124);
    }
    if (WIFEXITED($inherited_status)) { finish(WEXITSTATUS($inherited_status)); }
    if (WIFSIGNALED($inherited_status)) { finish(128 + WTERMSIG($inherited_status)); }
    finish(1);
}

# Never signal a negative PID until the child proves that the same numeric ID
# is now an isolated process-group ID. FD_CLOEXEC keeps the readiness channel
# out of the supervised command after a successful exec.
pipe(my $ready_reader, my $ready_writer) or die "watchdog could not create its readiness pipe: $!\n";
fcntl($ready_writer, F_SETFD, FD_CLOEXEC) or die "watchdog could not protect its readiness pipe: $!\n";
open(my $random_handle, '<', '/dev/urandom') or die "watchdog could not open its capability entropy source: $!\n";
my $random_bytes = '';
read($random_handle, $random_bytes, 32) == 32 or die "watchdog could not read capability entropy: $!\n";
close($random_handle);
my $capability_nonce = unpack('H*', $random_bytes);
my $watchdog_pid = $$;
$owned_capability_path = "/private/tmp/fulmar-watchdog-capability.$watchdog_pid.$capability_nonce";
socketpair($root_capability_socket, $child_capability_socket, AF_UNIX, SOCK_DGRAM, PF_UNSPEC)
    or die "watchdog could not create its inherited capability socket: $!\n";
pipe($tree_proof_reader, $tree_proof_writer)
    or die "watchdog could not create its tree-drain proof pipe: $!\n";
my $child = fork();
defined($child) or die "watchdog could not fork: $!\n";
if ($child == 0) {
    close($root_capability_socket);
    close($tree_proof_reader);
    # Relocate every source above both fixed targets before installing either
    # one. A caller may legitimately enter with 0...210 open; sequential dup2
    # must never clobber the other source handle.
    my $capability_source_fd = fcntl($child_capability_socket, F_DUPFD, 199);
    my $proof_source_fd = fcntl($tree_proof_writer, F_DUPFD, 199);
    my $ready_source_fd = fcntl($ready_writer, F_DUPFD, 199);
    defined($capability_source_fd) && defined($proof_source_fd) && defined($ready_source_fd)
        or die "watchdog child could not relocate its fixed-descriptor sources: $!\n";
    open(my $capability_source, "+<&=$capability_source_fd")
        or die "watchdog child could not reopen its capability source: $!\n";
    open(my $proof_source, ">&=$proof_source_fd")
        or die "watchdog child could not reopen its proof source: $!\n";
    open(my $ready_source, ">&=$ready_source_fd")
        or die "watchdog child could not reopen its readiness source: $!\n";
    fcntl($capability_source, F_SETFD, FD_CLOEXEC)
        && fcntl($proof_source, F_SETFD, FD_CLOEXEC)
        && fcntl($ready_source, F_SETFD, FD_CLOEXEC)
        or die "watchdog child could not protect its relocated descriptors: $!\n";
    close($child_capability_socket);
    close($tree_proof_writer);
    close($ready_writer);
    close($ready_reader);
    dup2(fileno($capability_source), $capability_fd_number) >= 0
        or die "watchdog child could not install its inherited capability descriptor: $!\n";
    dup2(fileno($proof_source), $tree_proof_fd_number) >= 0
        or die "watchdog child could not install its tree-drain proof descriptor: $!\n";
    close($capability_source);
    close($proof_source);
    setsid() >= 0 or die "watchdog child could not create a process group: $!\n";
    syswrite($ready_source, "READY\n") == 6 or die "watchdog child could not report process-group readiness: $!\n";
    close($ready_source);
    my $capability_deadline = clock_gettime(CLOCK_MONOTONIC) + $lock_wait_seconds + 10;
    while (!-f $owned_capability_path && clock_gettime(CLOCK_MONOTONIC) < $capability_deadline) {
        sleep(0.01);
    }
    -f $owned_capability_path or die "watchdog child did not receive its root capability: $!\n";
    $ENV{FULMAR_INTERNAL_WATCHDOG_DEPTH} = $watchdog_depth + 1;
    $ENV{FULMAR_ROOT_WATCHDOG_PGID_V1} = $$;
    $ENV{FULMAR_ROOT_WATCHDOG_PID_V1} = $watchdog_pid;
    $ENV{FULMAR_ROOT_WATCHDOG_CAPABILITY_V1} = $owned_capability_path;
    $ENV{FULMAR_ROOT_WATCHDOG_NONCE_V1} = $capability_nonce;
    $ENV{FULMAR_ROOT_WATCHDOG_FD_V1} = $capability_fd_number;
    $ENV{FULMAR_TREE_DRAIN_PROOF_FD_V1} = $tree_proof_fd_number;
    $ENV{FULMAR_TREE_DRAIN_PROOF_NONCE_V1} = $capability_nonce;
    # The isolated PGID is the coarse containment boundary.  The independent
    # process-tree monitor is also the direct command parent and continuously
    # records descendant PID + birth identities, so a descendant observed in
    # this group remains owned after setsid()/setpgid() changes its group.
    # macOS has no unprivileged descendant namespace, so a fork+setsid+reparent
    # entirely between samples remains a documented trusted-source residual.
    my $tree_node = "$Bin/../VendorRuntime/node-v22.23.1-darwin-arm64/bin/node";
    my $tree_monitor = "$Bin/run-process-tree-watchdog.mjs";
    exec {$tree_node} $tree_node, $tree_monitor,
        '--seconds', $seconds,
        '--max-rss-bytes', $maximum_rss_bytes,
        '--rss-grace-seconds', $rss_grace_seconds,
        '--emergency-rss-bytes', $emergency_rss_bytes,
        '--label', $label,
        '--', @ARGV;
    die "watchdog could not execute its process-tree monitor: $!\n";
}
# The process-tree monitor received the only child-side copies. Retire the
# root supervisor's descriptors before it publishes capabilities, launches
# process inspectors, waits, or emits any diagnostics.
close_private_secret_descriptors();
close($child_capability_socket);
close($tree_proof_writer);
my $capability_payload = "FULMAR_ROOT_WATCHDOG_V1:$capability_nonce:$watchdog_pid:$child";
send($root_capability_socket, $capability_payload, 0) == length($capability_payload)
    or die "watchdog could not publish its inherited capability payload: $!\n";
close($ready_writer);

my $ready = '';
my $readiness_deadline = clock_gettime(CLOCK_MONOTONIC) + 5;
my $selector = IO::Select->new($ready_reader);
while (clock_gettime(CLOCK_MONOTONIC) < $readiness_deadline && $ready ne "READY\n") {
    my @readable = $selector->can_read(0.05);
    if (@readable) {
        my $chunk = '';
        my $count = sysread($ready_reader, $chunk, 64 - length($ready));
        last unless defined($count) && $count > 0;
        $ready .= $chunk;
        last if length($ready) > 16;
    }
}
close($ready_reader);
if ($ready ne "READY\n") {
    # No negative-PID signal is safe here: setsid readiness was never attested.
    kill(15, $child);
    my $deadline = clock_gettime(CLOCK_MONOTONIC) + 1;
    my $reaped = 0;
    while (clock_gettime(CLOCK_MONOTONIC) < $deadline) {
        my $result = waitpid($child, WNOHANG);
        if ($result == $child || $result == -1) { $reaped = 1; last; }
        sleep(0.05);
    }
    if (!$reaped) {
        kill(9, $child);
        my $kill_deadline = clock_gettime(CLOCK_MONOTONIC) + 1;
        while (clock_gettime(CLOCK_MONOTONIC) < $kill_deadline) {
            my $result = waitpid($child, WNOHANG);
            last if $result == $child || $result == -1;
            sleep(0.05);
        }
    }
    $root_group_proven_empty = $reaped ? 1 : 0;
    if ($forwarded_signal) { finish(128 + $forwarded_signal); }
    print STDERR "$label could not establish an isolated process group within five seconds.\n";
    finish(126);
}

if (defined($lock_dir)) {
    my $lock_status = acquire_root_lock(
        $lock_dir, $watchdog_pid, $child, $owned_capability_path,
        $capability_nonce, $lock_wait_seconds
    );
    if ($lock_status != 0) {
        my (undef, $drained) = terminate_and_drain_group($child, $child, 0, 9);
        $root_group_proven_empty = $drained ? 1 : 0;
        print STDERR "$label could not acquire its supervisor-owned root lock.\n";
        finish($drained ? $lock_status : 126);
    }
}

my $capability_staging = "$owned_capability_path.staging";
my $capability_handle;
if (!sysopen($capability_handle, $capability_staging, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600)) {
    my (undef, $drained) = terminate_and_drain_group($child, $child, 0, 9);
    $root_group_proven_empty = $drained ? 1 : 0;
    print STDERR "$label could not exclusively create its root capability.\n";
    if (!$drained) {
        print STDERR "$label also could not prove its ready child group empty after capability creation failed.\n";
    }
    finish(126);
}
my $capability_bytes = "$watchdog_pid\n$child\n$capability_nonce\n";
if (syswrite($capability_handle, $capability_bytes) != length($capability_bytes)
    || !close($capability_handle) || !rename($capability_staging, $owned_capability_path)) {
    unlink($capability_staging);
    my (undef, $drained) = terminate_and_drain_group($child, $child, 0, 9);
    $root_group_proven_empty = $drained ? 1 : 0;
    print STDERR "$label could not publish its root capability atomically.\n";
    if (!$drained) {
        print STDERR "$label also could not prove its ready child group empty after capability publication failed.\n";
    }
    finish(126);
}
$capability_published = 1;

sub process_group_sample {
    my ($process_group) = @_;
    pipe(my $ps_reader, my $ps_writer) or return undef;
    my $ps_pid = fork();
    if (!defined($ps_pid)) {
        close($ps_reader);
        close($ps_writer);
        return undef;
    }
    if ($ps_pid == 0) {
        close($ps_reader);
        # Infrastructure sampling during fresh-root janitor preflight can run
        # before the supervisor gives its command the private descriptors.
        # The sampler must never inherit either secret transport across exec.
        POSIX::close(195);
        POSIX::close(196);
        open(STDOUT, '>&', $ps_writer) or CORE::exit(127);
        close($ps_writer);
        open(STDERR, '>', '/dev/null') or CORE::exit(127);
        exec {'/bin/ps'} '/bin/ps', '-axo', 'pgid=,rss=';
        CORE::exit(127);
    }
    close($ps_writer);

    # The sampler is infrastructure too: a wedged `ps` must never defeat the
    # command's wall/RSS watchdog. Bound both its output and its elapsed time,
    # then reap it without a blocking wait.
    my $selector = IO::Select->new($ps_reader);
    my $sample_deadline = clock_gettime(CLOCK_MONOTONIC) + 0.75;
    my $output = '';
    my $saw_eof = 0;
    while (clock_gettime(CLOCK_MONOTONIC) < $sample_deadline) {
        my @readable = $selector->can_read(0.05);
        next unless @readable;
        my $chunk = '';
        my $count = sysread($ps_reader, $chunk, 64 * 1_024);
        if (!defined($count)) { last; }
        if ($count == 0) { $saw_eof = 1; last; }
        $output .= $chunk;
        if (length($output) > 2 * 1_024 * 1_024) { last; }
    }
    close($ps_reader);

    my $ps_reaped = 0;
    my $ps_status;
    my $reap_deadline = clock_gettime(CLOCK_MONOTONIC) + 0.25;
    while (clock_gettime(CLOCK_MONOTONIC) < $reap_deadline) {
        my $result = waitpid($ps_pid, WNOHANG);
        if ($result == $ps_pid) { $ps_status = $?; $ps_reaped = 1; last; }
        if ($result == -1) { $ps_reaped = 1; last; }
        sleep(0.01);
    }
    if (!$ps_reaped) {
        kill(9, $ps_pid);
        my $kill_deadline = clock_gettime(CLOCK_MONOTONIC) + 0.25;
        while (clock_gettime(CLOCK_MONOTONIC) < $kill_deadline) {
            my $result = waitpid($ps_pid, WNOHANG);
            if ($result == $ps_pid) { $ps_status = $?; $ps_reaped = 1; last; }
            if ($result == -1) { $ps_reaped = 1; last; }
            sleep(0.01);
        }
    }
    return undef unless $saw_eof && $ps_reaped && defined($ps_status) && WIFEXITED($ps_status)
        && WEXITSTATUS($ps_status) == 0 && length($output) <= 2 * 1_024 * 1_024;

    return parse_process_group_sample($output, $process_group);
}

sub acquire_root_lock {
    my ($directory, $root_pid, $root_pgid, $capability, $nonce, $wait_seconds) = @_;
    my $owner = "$directory/owner.pid";
    my $record = "$root_pid\n$root_pgid\n$capability\n$nonce\n";
    my $deadline = clock_gettime(CLOCK_MONOTONIC) + $wait_seconds;
    my $owner_publication_deadline;
    while (1) {
        my $old_umask = umask(0077);
        my $created = mkdir($directory, 0700);
        umask($old_umask);
        if ($created) {
            my @directory_details = lstat($directory);
            if (!@directory_details || !-d _ || -l _ || $directory_details[4] != $<
                || ($directory_details[2] & 0777) != 0700) {
                rmdir($directory);
                return 126;
            }
            # Publish the owner record atomically. Another contender may observe
            # the already-acquired directory, but it must never parse a partial
            # record and misclassify an ordinary acquisition race as corruption.
            my $owner_staging = "$directory/owner.staging";
            my $owner_handle;
            if (!sysopen($owner_handle, $owner_staging,
                    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600)) {
                rmdir($directory);
                return 126;
            }
            my $written = syswrite($owner_handle, $record);
            my $closed = close($owner_handle);
            if (!defined($written) || $written != length($record) || !$closed
                || !chmod(0600, $owner_staging) || !rename($owner_staging, $owner)) {
                unlink($owner_staging);
                rmdir($directory);
                return 126;
            }
            my @owner_details = lstat($owner);
            if (!@owner_details || !-f _ || -l _ || $owner_details[3] != 1
                || $owner_details[4] != $< || ($owner_details[2] & 0777) != 0600
                || $owner_details[7] != length($record)) {
                unlink($owner);
                rmdir($directory);
                return 126;
            }
            $owned_lock_dir = $directory;
            $owned_lock_owner = $owner;
            $owned_lock_record = $record;
            return 0;
        }

        my @directory_details = lstat($directory);
        return 126 unless @directory_details && -d _ && !-l _
            && $directory_details[4] == $< && ($directory_details[2] & 0777) == 0700;
        my $owner_handle;
        if (!sysopen($owner_handle, $owner, O_RDONLY | O_NOFOLLOW)) {
            # mkdir is the ownership boundary, so a correctly behaving winner
            # needs one short bounded interval to atomically publish owner.pid.
            # A persistent ownerless directory still fails closed as unsafe.
            $owner_publication_deadline //= clock_gettime(CLOCK_MONOTONIC) + 0.5;
            return 126 if clock_gettime(CLOCK_MONOTONIC) >= $owner_publication_deadline;
            sleep(0.01);
            next;
        }
        undef($owner_publication_deadline);
        my @owner_details = stat($owner_handle);
        my $existing = '';
        my $read_count = sysread($owner_handle, $existing, 1_025);
        close($owner_handle);
        return 126 unless @owner_details && $owner_details[3] == 1
            && $owner_details[4] == $< && ($owner_details[2] & 0777) == 0600
            && $owner_details[7] >= 72 && $owner_details[7] <= 1_024
            && defined($read_count) && $read_count == $owner_details[7];
        my @fields = split(/\n/, $existing, -1);
        pop(@fields) if @fields && $fields[-1] eq '';
        if (@fields == 3 && $fields[0] eq 'FULMAR_LOCK_SUCCESSOR_V1'
            && $fields[1] =~ /\A[0-9]+\z/ && $fields[1] > 1
            && $fields[2] =~ /\A[a-f0-9]{64}\z/) {
            if (!kill(0, $fields[1])) {
                return 126 unless unlink($owner) && rmdir($directory);
                next;
            }
            return 75 if clock_gettime(CLOCK_MONOTONIC) >= $deadline;
            sleep(0.1);
            next;
        }
        return 126 unless @fields == 4 && $fields[0] =~ /\A[0-9]+\z/
            && $fields[1] =~ /\A[0-9]+\z/ && $fields[0] > 1 && $fields[1] > 1
            && $fields[2] =~ m{\A/private/tmp/fulmar-watchdog-capability\.[0-9]+\.[a-f0-9]{64}\z}
            && $fields[3] =~ /\A[a-f0-9]{64}\z/;
        if (!kill(0, $fields[0])) {
            # A capability deliberately survives whenever cross-session drain
            # proof is missing. Its presence makes this a manual-recovery lock,
            # not a stale PGID-only lock that another run may auto-remove.
            if (-e $fields[2] || -l $fields[2]) {
                my $retained_handle;
                return 126 unless sysopen($retained_handle, $fields[2], O_RDONLY | O_NOFOLLOW);
                my @retained_details = stat($retained_handle);
                my $retained_bytes = '';
                my $retained_count = sysread($retained_handle, $retained_bytes, 257);
                close($retained_handle);
                my $expected_retained = "$fields[0]\n$fields[1]\n$fields[3]\n";
                return 126 unless @retained_details && $retained_details[3] == 1
                    && $retained_details[4] == $< && ($retained_details[2] & 0777) == 0600
                    && $retained_details[7] == length($expected_retained)
                    && defined($retained_count) && $retained_count == $retained_details[7]
                    && $retained_bytes eq $expected_retained;
                return 126;
            }
            my $sample = process_group_sample($fields[1]);
            return 126 unless defined($sample);
            if ($sample->{members} == 0) {
                return 126 unless unlink($owner) && rmdir($directory);
                next;
            }
        }
        return 75 if clock_gettime(CLOCK_MONOTONIC) >= $deadline;
        sleep(0.1);
    }
}

sub terminate_and_drain_group {
    my ($process_group, $leader, $leader_reaped, $initial_signal) = @_;
    kill($initial_signal, -$process_group);
    my $leader_status;
    my $deadline = clock_gettime(CLOCK_MONOTONIC) + 3;
    while (clock_gettime(CLOCK_MONOTONIC) < $deadline) {
        if (!$leader_reaped) {
            my $result = waitpid($leader, WNOHANG);
            if ($result == $leader) { $leader_status = $?; $leader_reaped = 1; }
            elsif ($result == -1) { $leader_reaped = 1; }
        }
        my $sample = process_group_sample($process_group);
        return ($leader_status, 1) if defined($sample) && $sample->{members} == 0 && $leader_reaped;
        sleep(0.05);
    }

    kill(9, -$process_group);
    my $kill_deadline = clock_gettime(CLOCK_MONOTONIC) + 2;
    while (clock_gettime(CLOCK_MONOTONIC) < $kill_deadline) {
        if (!$leader_reaped) {
            my $result = waitpid($leader, WNOHANG);
            if ($result == $leader) { $leader_status = $?; $leader_reaped = 1; }
            elsif ($result == -1) { $leader_reaped = 1; }
        }
        my $sample = process_group_sample($process_group);
        return ($leader_status, 1) if defined($sample) && $sample->{members} == 0 && $leader_reaped;
        sleep(0.05);
    }
    # Never fall back to a blocking reap. A task stuck in uninterruptible I/O
    # may remain unreapable even after KILL; the bounded supervisor must return
    # a fail-closed status instead of hanging indefinitely.
    return ($leader_status, 0);
}

sub consume_tree_drain_proof {
    my ($expected_status) = @_;
    return 0 unless defined($tree_proof_reader) && defined($expected_status)
        && $expected_status =~ /\A[0-9]+\z/ && $expected_status <= 255;
    my $selector = IO::Select->new($tree_proof_reader);
    my $deadline = clock_gettime(CLOCK_MONOTONIC) + 2;
    my $bytes = '';
    my $saw_eof = 0;
    while (clock_gettime(CLOCK_MONOTONIC) < $deadline) {
        my @readable = $selector->can_read(0.05);
        next unless @readable;
        my $chunk = '';
        my $count = sysread($tree_proof_reader, $chunk, 256 - length($bytes));
        return 0 unless defined($count);
        if ($count == 0) { $saw_eof = 1; last; }
        $bytes .= $chunk;
        return 0 if length($bytes) >= 256;
    }
    my $expected = "TREE_DRAIN_V1:$capability_nonce:$expected_status\n";
    if ($saw_eof && $bytes eq $expected) {
        close($tree_proof_reader);
        undef($tree_proof_reader);
        $tree_proof_valid = 1;
        $tree_proof_status = $expected_status;
        return 1;
    }
    return 0;
}

my $deadline = clock_gettime(CLOCK_MONOTONIC) + $seconds + 15;
my $status;
my $leader_reaped = 0;
my $termination_reason = '';
my $termination_exit = 0;

while (1) {
    my $result = waitpid($child, WNOHANG);
    if ($result == $child) {
        $status = $?;
        $leader_reaped = 1;
        my $post_exit_sample;
        for (1 .. 3) {
            $post_exit_sample = process_group_sample($child);
            last if defined($post_exit_sample);
            sleep(0.05);
        }
        if (!defined($post_exit_sample)) {
            $termination_reason = 'process-group inspection failed after the leader exited';
            $termination_exit = 126;
        } elsif ($post_exit_sample->{members} > 0) {
            $termination_reason = 'the command leader exited while descendants were still running';
            $termination_exit = 126;
        } elsif (WIFEXITED($status)
            && consume_tree_drain_proof(WEXITSTATUS($status))) {
            $root_group_proven_empty = 1;
        } else {
            $termination_reason = 'the process-tree monitor did not publish an exact drain proof';
            $termination_exit = 126;
        }
        last;
    }
    if ($result == -1) {
        $termination_reason = "the watchdog lost its command leader: $!";
        $termination_exit = 126;
        last;
    }

    my $now = clock_gettime(CLOCK_MONOTONIC);
    # The direct child is the reviewed process-tree monitor. It owns the exact
    # wall/RSS policy and cross-session TERM/KILL drain. The Perl root remains a
    # later coarse bound only; killing its PGID at the same deadline would kill
    # the monitor while it was draining an observed setsid() descendant.
    last if $forwarded_signal || $now >= $deadline;
    sleep(0.05);
}

if ($termination_reason ne '') {
    my (undef, $drained) = terminate_and_drain_group($child, $child, $leader_reaped, 9);
    # Original-PGID emptiness is only best-effort cleanup after the authoritative
    # cross-session monitor became untrustworthy. It cannot prove an already
    # observed setsid descendant empty, so retain the lock/capability fail-closed.
    $root_group_proven_empty = 0;
    print STDERR "$label failed closed after its process-tree monitor boundary: $termination_reason.\n";
    finish(126);
}

if (!$leader_reaped && ($forwarded_signal || clock_gettime(CLOCK_MONOTONIC) >= $deadline)) {
    my $signal = $forwarded_signal || 15;
    kill($signal, $child);
    # The Node owner has a 3-second TERM phase, 2-second KILL phase, and
    # bounded one-second process-table calls that can overrun each phase and
    # the final proof. Twelve seconds is a strict later outer allowance.
    my $monitor_deadline = clock_gettime(CLOCK_MONOTONIC) + 12;
    while (clock_gettime(CLOCK_MONOTONIC) < $monitor_deadline) {
        my $result = waitpid($child, WNOHANG);
        if ($result == $child) { $status = $?; $leader_reaped = 1; last; }
        if ($result == -1) { last; }
        sleep(0.05);
    }
    if (!$leader_reaped) {
        my (undef, $drained) = terminate_and_drain_group($child, $child, 0, 9);
        $root_group_proven_empty = 0;
        print STDERR "$label process-tree monitor missed its later coarse cleanup bound.\n";
        finish(126);
    }
    my $sample = process_group_sample($child);
    if (!defined($sample) || $sample->{members} != 0) {
        print STDERR "$label process-tree monitor exited without an empty root group.\n";
        finish(126);
    }
    if (!WIFEXITED($status) || !consume_tree_drain_proof(WEXITSTATUS($status))) {
        print STDERR "$label process-tree monitor exited without an authenticated drain proof.\n";
        finish(126);
    }
    $root_group_proven_empty = 1;
    if ($forwarded_signal && WEXITSTATUS($status) == 128 + $signal) {
        finish(128 + $signal);
    }
    print STDERR "$label process-tree monitor did not preserve the expected bounded result.\n";
    finish(126);
}

if (WIFEXITED($status)) { finish(WEXITSTATUS($status)); }
if (WIFSIGNALED($status)) { finish(128 + WTERMSIG($status)); }
finish(1);
