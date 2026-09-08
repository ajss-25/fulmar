#!/usr/bin/perl
use strict;
use warnings;
use Errno qw(EINTR);
use Fcntl qw(F_DUPFD F_GETFD F_SETFD SEEK_SET);
use File::Temp qw(tempfile);
use POSIX qw(dup2 geteuid);

# Test-only launcher for source-tree shell probes. It accepts the private frame
# over a pipe, converts it to the same owner-only, already-unlinked regular
# descriptor used by the Swift app, and then execs the exact requested target.
# Authentication material is never an argument, environment value, pathname, or
# diagnostic.
#
# Default mode reproduces the app's input boundary: the record is on stdin, ready
# for the native runtime lease, which performs the descriptor handoff itself.
# `--fulmar-post-handoff` reproduces the boundary the runtime sees after that
# lease has run: the record is on a dedicated descriptor above stderr, stdin
# holds the null device, and only the descriptor number is published. Use it for
# probes that launch the runtime directly, never in front of the native lease,
# which would otherwise transform an already-transformed input.
my $post_handoff = 0;
if (@ARGV && $ARGV[0] eq '--fulmar-post-handoff') {
    $post_handoff = 1;
    shift(@ARGV);
}
my $descriptor_variable = 'LOCAL_HARNESS_RUNTIME_AUTH_FD';
delete $ENV{$descriptor_variable};
my $maximum = 384;
my $frame = q{};
while (length($frame) <= $maximum) {
    my $chunk = q{};
    my $count = sysread(STDIN, $chunk, $maximum + 1 - length($frame));
    if (!defined($count)) {
        next if $! == EINTR;
        die "runtime authentication relay could not read its private input\n";
    }
    last if $count == 0;
    $frame .= $chunk;
}
die "runtime authentication relay refused a malformed private input\n"
    if length($frame) > $maximum
    || $frame !~ /\AFULMAR_RUNTIME_AUTH_V1:[A-Za-z0-9_-]{22,128}:[A-Za-z0-9_-]{22,128}\n\z/;
die "runtime authentication relay requires an exact executable\n"
    if !@ARGV || $ARGV[0] !~ m{\A/} || index($ARGV[0], "\0") >= 0;

my ($authentication, $path) = tempfile(
    'fulmar-runtime-auth-test.XXXXXX',
    DIR => '/private/tmp',
    UNLINK => 0,
);
chmod(0600, $authentication)
    or die "runtime authentication relay could not secure its descriptor\n";
my @before = stat($authentication);
die "runtime authentication relay refused unsafe descriptor metadata\n"
    if !@before || (($before[2] & 0170000) != 0100000) || $before[3] != 1
    || $before[4] != geteuid() || (($before[2] & 0777) != 0600) || $before[7] != 0;
unlink($path) or die "runtime authentication relay could not unlink its descriptor\n";

my $written = 0;
while ($written < length($frame)) {
    my $count = syswrite($authentication, $frame, length($frame) - $written, $written);
    if (!defined($count)) {
        next if $! == EINTR;
        die "runtime authentication relay could not write its private descriptor\n";
    }
    die "runtime authentication relay could not complete its private descriptor\n" if $count == 0;
    $written += $count;
}
sysseek($authentication, 0, SEEK_SET)
    or die "runtime authentication relay could not rewind its private descriptor\n";
my @after = stat($authentication);
die "runtime authentication relay detected changed descriptor metadata\n"
    if !@after || $after[0] != $before[0] || $after[1] != $before[1]
    || (($after[2] & 0170000) != 0100000) || $after[3] != 0
    || $after[4] != $before[4] || (($after[2] & 0777) != 0600)
    || $after[7] != length($frame);

my $source_descriptor = fileno($authentication);
defined($source_descriptor)
    or die "runtime authentication relay lost its private descriptor\n";

my $published_handle;
if ($post_handoff) {
    # The kernel picks the lowest free descriptor at or above three, so no live
    # handle is overwritten. F_DUPFD also clears close-on-exec; prove it.
    my $published_descriptor = fcntl($authentication, F_DUPFD, 3);
    defined($published_descriptor) && $published_descriptor >= 3
        or die "runtime authentication relay could not preserve its private descriptor\n";
    open($published_handle, '<&=', $published_descriptor)
        or die "runtime authentication relay lost its preserved descriptor\n";
    fcntl($published_handle, F_SETFD, 0)
        or die "runtime authentication relay could not share its preserved descriptor\n";
    my $preserved_flags = fcntl($published_handle, F_GETFD, 0);
    defined($preserved_flags) && $preserved_flags == 0
        or die "runtime authentication relay refused a non-inheritable descriptor\n";

    open(my $null, '<', '/dev/null')
        or die "runtime authentication relay could not open the null device\n";
    dup2(fileno($null), 0) == 0
        or die "runtime authentication relay could not install the null device\n";
    close($null)
        or die "runtime authentication relay could not close the null device\n";
    close($authentication)
        or die "runtime authentication relay could not close its duplicate descriptor\n"
        if $source_descriptor != $published_descriptor;

    my @installed = stat(STDIN);
    die "runtime authentication relay refused its published standard input\n"
        if !@installed || ($installed[2] & 0170000) != 0020000;

    my @published = stat($published_handle);
    my $offset = sysseek($published_handle, 0, SEEK_SET);
    die "runtime authentication relay refused its preserved descriptor\n"
        if !@published || !defined($offset) || $offset != 0
        || $published[0] != $before[0] || $published[1] != $before[1]
        || (($published[2] & 0170000) != 0100000) || $published[3] != 0
        || $published[4] != $before[4] || (($published[2] & 0777) != 0600)
        || $published[7] != length($frame);
    $ENV{$descriptor_variable} = $published_descriptor;
} else {
    dup2($source_descriptor, 0) == 0
        or die "runtime authentication relay could not install its private descriptor\n";
    fcntl(STDIN, F_SETFD, 0)
        or die "runtime authentication relay could not preserve its private descriptor\n";
    close($authentication)
        or die "runtime authentication relay could not close its duplicate descriptor\n"
        if $source_descriptor != 0;

    my @published = stat(STDIN);
    my $offset = sysseek(STDIN, 0, SEEK_SET);
    die "runtime authentication relay refused its published descriptor\n"
        if !@published || !defined($offset) || $offset != 0
        || $published[0] != $before[0] || $published[1] != $before[1]
        || (($published[2] & 0170000) != 0100000) || $published[3] != 0
        || $published[4] != $before[4] || (($published[2] & 0777) != 0600)
        || $published[7] != length($frame);
}

$frame = "\0" x length($frame);
exec { $ARGV[0] } @ARGV;
die "runtime authentication relay could not execute its exact target\n";
