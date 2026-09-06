package FulmarWatchdogCapabilityJanitor;

use strict;
use warnings;
use Errno qw(ENOENT ESRCH);
use Exporter qw(import);
use Fcntl qw(:mode O_RDONLY O_NOFOLLOW);
use Time::HiRes qw(clock_gettime sleep CLOCK_MONOTONIC);

our @EXPORT_OK = qw(janitor_capabilities);

my $PRODUCTION_DIRECTORY = '/private/tmp';
my $MAXIMUM_ENTRIES = 16_384;
my $MAXIMUM_CAPABILITIES = 256;
my $MAXIMUM_LOCKS = 2_048;
my $MINIMUM_AGE_SECONDS = 30;
my $MAXIMUM_AGE_SECONDS = 30 * 24 * 60 * 60;
my $MAXIMUM_ELAPSED_SECONDS = 10;

sub _result {
    my ($ok, $removed, $message) = @_;
    return { ok => $ok ? 1 : 0, removed => $removed, message => $message };
}

sub _same_identity {
    my ($left, $right) = @_;
    return 0 unless @$left && @$right;
    for my $index (0, 1, 2, 3, 4, 5, 7, 9, 10) {
        return 0 unless $left->[$index] == $right->[$index];
    }
    return 1;
}

sub _directory_identity_is_stable {
    my ($before, $after) = @_;
    return 0 unless @$before && @$after;
    for my $index (0, 1, 2, 3, 4, 5, 9, 10) {
        return 0 unless $before->[$index] == $after->[$index];
    }
    return 1;
}

sub _deadline_expired {
    my ($deadline, $interrupted) = @_;
    return 1 if defined($interrupted) && $interrupted->();
    return clock_gettime(CLOCK_MONOTONIC) > $deadline;
}

sub _is_process_id {
    my ($value) = @_;
    return defined($value) && $value =~ /\A[1-9][0-9]{0,9}\z/
        && $value > 1 && $value <= 2_147_483_647;
}

sub _read_attested_file {
    my ($path, $effective_uid, $minimum_size, $maximum_size) = @_;
    my @path_before = lstat($path);
    if (!@path_before) {
        return $!{ENOENT} ? { absent => 1 } : { error => "could not inspect $path" };
    }
    return { error => "$path has unsafe metadata" }
        unless S_ISREG($path_before[2]) && !S_ISLNK($path_before[2])
        && $path_before[3] == 1 && $path_before[4] == $effective_uid
        && ($path_before[2] & 0777) == 0600
        && $path_before[7] >= $minimum_size && $path_before[7] <= $maximum_size;

    my $handle;
    if (!sysopen($handle, $path, O_RDONLY | O_NOFOLLOW)) {
        return $!{ENOENT} ? { absent => 1 } : { error => "could not safely open $path" };
    }
    my @opened_before = stat($handle);
    my $bytes = '';
    my $read_count = sysread($handle, $bytes, $maximum_size + 1);
    my @opened_after = stat($handle);
    close($handle);
    my @path_after = lstat($path);
    return { error => "$path changed while it was read" }
        unless @opened_before && @opened_after && @path_after
        && _same_identity(\@path_before, \@opened_before)
        && _same_identity(\@opened_before, \@opened_after)
        && _same_identity(\@opened_after, \@path_after)
        && defined($read_count) && $read_count == $opened_before[7]
        && length($bytes) == $opened_before[7];
    return { bytes => $bytes, identity => \@opened_before };
}

sub _scan_names {
    my ($directory, $maximum_entries, $maximum_capabilities, $maximum_locks,
        $deadline, $interrupted, $scan_attempt_hook) = @_;
    for my $attempt (1 .. 3) {
        return { error => "watchdog capability janitor was interrupted or exceeded its deadline" }
            if _deadline_expired($deadline, $interrupted);
        opendir(my $handle, $directory)
            or return { error => "could not open the watchdog janitor directory" };
        my @opened_before = stat($handle);
        my (@capabilities, @locks);
        my $entries = 0;
        while (defined(my $name = readdir($handle))) {
            next if $name eq '.' || $name eq '..';
            ++$entries;
            if ($entries > $maximum_entries) {
                closedir($handle);
                return { error => "watchdog janitor directory entry bound was exceeded" };
            }
            if ($name =~ /\Afulmar-watchdog-capability\.([0-9]+)\.([a-f0-9]{64})\z/) {
                push(@capabilities, [$name, $1, $2]);
                if (@capabilities > $maximum_capabilities) {
                    closedir($handle);
                    return { error => "watchdog capability candidate bound was exceeded" };
                }
            }
            if ($name =~ /\A[A-Za-z0-9._-]{1,160}\.lock\z/) {
                push(@locks, $name);
                if (@locks > $maximum_locks) {
                    closedir($handle);
                    return { error => "watchdog lock candidate bound was exceeded" };
                }
            }
        }
        $scan_attempt_hook->() if defined($scan_attempt_hook);
        my @opened_after = stat($handle);
        closedir($handle);
        return { capabilities => \@capabilities, locks => \@locks }
            if _directory_identity_is_stable(\@opened_before, \@opened_after);
        sleep(0.01) if $attempt < 3;
    }
    return { error => "watchdog janitor directory changed during three bounded enumeration attempts" };
}

sub _safe_lock_references_once {
    my ($directory, $effective_uid, $candidate_path, $maximum_entries,
        $maximum_capabilities, $maximum_locks, $deadline, $interrupted,
        $scan_attempt_hook) = @_;
    my @directory_before = lstat($directory);
    return { error => "could not attest the watchdog janitor directory before lock inspection" }
        unless @directory_before;
    my $scan = _scan_names(
        $directory, $maximum_entries, $maximum_capabilities, $maximum_locks,
        $deadline, $interrupted, $scan_attempt_hook
    );
    return $scan if exists($scan->{error});
    for my $name (@{$scan->{locks}}) {
        return { error => "watchdog capability janitor was interrupted or exceeded its deadline" }
            if _deadline_expired($deadline, $interrupted);
        my $lock_path = "$directory/$name";
        my @lock_before = lstat($lock_path);
        if (!@lock_before) {
            next if $!{ENOENT};
            return { error => "could not inspect watchdog lock $lock_path" };
        }
        # Other programs legitimately use regular .lock files. A same-user
        # directory or link that resembles the watchdog ownership boundary but
        # is not exactly owner-private is ambiguous and must retain candidates.
        next unless S_ISDIR($lock_before[2]) || S_ISLNK($lock_before[2]);
        next if $lock_before[4] != $effective_uid;
        return { error => "watchdog lock $lock_path has unsafe directory metadata" }
            unless S_ISDIR($lock_before[2]) && !S_ISLNK($lock_before[2])
            && ($lock_before[2] & 0777) == 0700;
        my $owner_path = "$lock_path/owner.pid";
        my $owner = _read_attested_file($owner_path, $effective_uid, 1, 1_024);
        if ($owner->{absent}) {
            my @lock_after = lstat($lock_path);
            return { error => "watchdog lock changed around an absent owner record" }
                unless @lock_after && _same_identity(\@lock_before, \@lock_after);
            next;
        }
        return $owner if exists($owner->{error});

        my @lock_after = lstat($lock_path);
        return { error => "watchdog lock changed while its owner record was read" }
            unless @lock_after && _same_identity(\@lock_before, \@lock_after);

        my @fields = split(/\n/, $owner->{bytes}, -1);
        pop(@fields) if @fields && $fields[-1] eq '';
        if (@fields == 3 && $fields[0] eq 'FULMAR_LOCK_SUCCESSOR_V1'
            && _is_process_id($fields[1])
            && $fields[2] =~ /\A[a-f0-9]{64}\z/) {
            next;
        }
        my ($owner_capability_pid, $owner_capability_nonce) = @fields == 4
            ? ($fields[2] =~ m{\A\Q$directory\E/fulmar-watchdog-capability\.([0-9]+)\.([a-f0-9]{64})\z})
            : ();
        return { error => "watchdog lock $lock_path has an ambiguous owner record" }
            unless @fields == 4 && _is_process_id($fields[0])
            && _is_process_id($fields[1])
            && defined($owner_capability_pid) && $fields[3] =~ /\A[a-f0-9]{64}\z/
            && $fields[0] == $owner_capability_pid
            && $fields[3] eq $owner_capability_nonce;
        return { referenced => 1 } if $fields[2] eq $candidate_path;
    }
    my @directory_after = lstat($directory);
    return { retryable => 1 }
        unless @directory_after
        && _directory_identity_is_stable(\@directory_before, \@directory_after);
    return { referenced => 0 };
}

sub _safe_lock_references {
    my @arguments = @_;
    my $deadline = $arguments[6];
    my $interrupted = $arguments[7];
    for my $attempt (1 .. 3) {
        my $result = _safe_lock_references_once(@arguments);
        return $result unless $result->{retryable};
        return { error => "watchdog capability janitor was interrupted or exceeded its deadline" }
            if _deadline_expired($deadline, $interrupted);
        sleep(0.01) if $attempt < 3;
    }
    return { error => "watchdog janitor directory changed during three bounded lock inspections" };
}

sub _pid_state {
    my ($pid, $pid_is_live) = @_;
    return $pid_is_live->($pid) if defined($pid_is_live);
    local $! = 0;
    return 1 if kill(0, $pid);
    return 0 if $!{ESRCH};
    return undef;
}

sub janitor_capabilities {
    my (%arguments) = @_;
    my $allow_test_directory = delete($arguments{allow_test_directory}) ? 1 : 0;
    my $directory = delete($arguments{directory}) // $PRODUCTION_DIRECTORY;
    my $effective_uid = delete($arguments{effective_uid});
    $effective_uid = $< unless defined($effective_uid);
    my $sample_group = delete($arguments{sample_group});
    my $pid_is_live = delete($arguments{pid_is_live});
    my $interrupted = delete($arguments{interrupted});
    my $before_unlink = delete($arguments{before_unlink});
    my $scan_attempt_hook = delete($arguments{scan_attempt_hook});

    my $maximum_entries = $MAXIMUM_ENTRIES;
    my $maximum_capabilities = $MAXIMUM_CAPABILITIES;
    my $maximum_locks = $MAXIMUM_LOCKS;
    my $minimum_age_seconds = $MINIMUM_AGE_SECONDS;
    my $maximum_age_seconds = $MAXIMUM_AGE_SECONDS;
    my $maximum_elapsed_seconds = $MAXIMUM_ELAPSED_SECONDS;
    if ($allow_test_directory) {
        $maximum_entries = delete($arguments{maximum_entries}) // $maximum_entries;
        $maximum_capabilities = delete($arguments{maximum_capabilities}) // $maximum_capabilities;
        $maximum_locks = delete($arguments{maximum_locks}) // $maximum_locks;
        $minimum_age_seconds = delete($arguments{minimum_age_seconds}) // $minimum_age_seconds;
        $maximum_age_seconds = delete($arguments{maximum_age_seconds}) // $maximum_age_seconds;
        $maximum_elapsed_seconds = delete($arguments{maximum_elapsed_seconds}) // $maximum_elapsed_seconds;
    }
    return _result(0, 0, 'watchdog janitor received unexpected arguments') if keys(%arguments);
    return _result(0, 0, 'watchdog janitor production directory changed')
        if !$allow_test_directory && $directory ne $PRODUCTION_DIRECTORY;
    return _result(0, 0, 'watchdog janitor has no bounded process-group sampler')
        unless ref($sample_group) eq 'CODE';
    return _result(0, 0, 'watchdog janitor test hook escaped its isolated directory')
        if (defined($before_unlink) || defined($scan_attempt_hook)) && !$allow_test_directory;
    return _result(0, 0, 'watchdog janitor received unsafe numeric bounds')
        unless $maximum_entries =~ /\A[0-9]+\z/ && $maximum_entries >= 1
        && $maximum_capabilities =~ /\A[0-9]+\z/ && $maximum_capabilities >= 1
        && $maximum_locks =~ /\A[0-9]+\z/ && $maximum_locks >= 1
        && $minimum_age_seconds =~ /\A[0-9]+\z/
        && $maximum_age_seconds =~ /\A[0-9]+\z/ && $maximum_age_seconds > $minimum_age_seconds
        && $maximum_elapsed_seconds =~ /\A[0-9]+\z/ && $maximum_elapsed_seconds >= 1;

    my @directory_path = lstat($directory);
    return _result(0, 0, 'watchdog janitor directory is unavailable') unless @directory_path;
    my $directory_is_safe = S_ISDIR($directory_path[2]) && !S_ISLNK($directory_path[2]);
    if ($allow_test_directory) {
        $directory_is_safe &&= $directory_path[4] == $effective_uid
            && ($directory_path[2] & 0777) == 0700;
    } else {
        $directory_is_safe &&= $directory_path[4] == 0
            && ($directory_path[2] & 01777) == 01777;
    }
    return _result(0, 0, 'watchdog janitor directory has unsafe metadata') unless $directory_is_safe;

    my $deadline = clock_gettime(CLOCK_MONOTONIC) + $maximum_elapsed_seconds;
    my $initial = _scan_names(
        $directory, $maximum_entries, $maximum_capabilities, $maximum_locks,
        $deadline, $interrupted, $scan_attempt_hook
    );
    return _result(0, 0, $initial->{error}) if exists($initial->{error});
    my $removed = 0;
    CANDIDATE: for my $entry (@{$initial->{capabilities}}) {
        return _result(0, $removed, 'watchdog capability janitor was interrupted or exceeded its deadline')
            if _deadline_expired($deadline, $interrupted);
        my ($name, $filename_pid, $filename_nonce) = @$entry;
        my $path = "$directory/$name";
        my $record = _read_attested_file($path, $effective_uid, 69, 128);
        next if $record->{absent};
        return _result(0, $removed, $record->{error}) if exists($record->{error});
        my $payload = $record->{bytes};
        my ($root_pid, $process_group, $nonce) =
            $payload =~ /\A([0-9]+)\n([0-9]+)\n([a-f0-9]{64})\n\z/;
        return _result(0, $removed, "$path has an invalid capability schema")
            unless _is_process_id($root_pid) && _is_process_id($process_group)
            && $root_pid eq $filename_pid && $nonce eq $filename_nonce;
        my $age = time() - $record->{identity}->[9];
        return _result(0, $removed, "$path has an invalid capability age") if $age < 0;
        next if $age < $minimum_age_seconds;
        return _result(0, $removed, "$path exceeded the automatic capability recovery age")
            if $age > $maximum_age_seconds;
        my $pid_state = _pid_state($root_pid, $pid_is_live);
        return _result(0, $removed, "$path root PID state is ambiguous") unless defined($pid_state);
        next if $pid_state;

        my $references = _safe_lock_references(
            $directory, $effective_uid, $path, $maximum_entries, $maximum_capabilities,
            $maximum_locks, $deadline, $interrupted, $scan_attempt_hook
        );
        return _result(0, $removed, $references->{error}) if exists($references->{error});
        next if $references->{referenced};

        $before_unlink->($path, $payload) if defined($before_unlink);
        my $current = _read_attested_file($path, $effective_uid, 69, 128);
        next if $current->{absent};
        return _result(0, $removed, $current->{error}) if exists($current->{error});
        return _result(0, $removed, "$path identity or bytes changed before removal")
            unless _same_identity($record->{identity}, $current->{identity})
            && $current->{bytes} eq $payload;
        $pid_state = _pid_state($root_pid, $pid_is_live);
        return _result(0, $removed, "$path root PID state became ambiguous") unless defined($pid_state);
        next if $pid_state;
        my $sample = $sample_group->($process_group);
        return _result(0, $removed, "$path process-group state is ambiguous")
            unless defined($sample) && ref($sample) eq 'HASH'
            && defined($sample->{members}) && $sample->{members} =~ /\A[0-9]+\z/;
        next if $sample->{members} != 0;

        $references = _safe_lock_references(
            $directory, $effective_uid, $path, $maximum_entries, $maximum_capabilities,
            $maximum_locks, $deadline, $interrupted, $scan_attempt_hook
        );
        return _result(0, $removed, $references->{error}) if exists($references->{error});
        next if $references->{referenced};
        my $last = _read_attested_file($path, $effective_uid, 69, 128);
        next if $last->{absent};
        return _result(0, $removed, $last->{error}) if exists($last->{error});
        return _result(0, $removed, "$path changed at its removal boundary")
            unless _same_identity($record->{identity}, $last->{identity}) && $last->{bytes} eq $payload;
        $pid_state = _pid_state($root_pid, $pid_is_live);
        return _result(0, $removed, "$path root PID state became ambiguous") unless defined($pid_state);
        next if $pid_state;
        return _result(0, $removed, 'watchdog capability janitor was interrupted or exceeded its deadline')
            if _deadline_expired($deadline, $interrupted);
        # Perl exposes no conditional inode unlink. Repeated O_NOFOLLOW reads
        # and the final exact leaf identity/byte check bound the remaining
        # same-user race to the syscall-sized path-unlink window; unlink never
        # follows a substituted symlink to its target. Any observed change is
        # retained and blocks the fresh root.
        if (!unlink($path)) {
            next if $!{ENOENT};
            return _result(0, $removed, "could not remove unchanged watchdog capability $path");
        }
        my @removed_path = lstat($path);
        return _result(0, $removed, "watchdog capability $path remained after removal")
            if @removed_path || !$!{ENOENT};
        ++$removed;
    }
    my @directory_after = lstat($directory);
    return _result(0, $removed, 'watchdog janitor directory identity changed')
        unless @directory_after && $directory_path[0] == $directory_after[0]
        && $directory_path[1] == $directory_after[1] && $directory_path[2] == $directory_after[2]
        && $directory_path[4] == $directory_after[4] && $directory_path[5] == $directory_after[5];
    return _result(1, $removed, '');
}

1;
