#!/usr/bin/perl
use strict;
use warnings;
use POSIX qw(dup);
use Socket qw(MSG_DONTWAIT MSG_PEEK);

@ARGV == 4 or exit(2);
my ($fd, $nonce, $root_pid, $root_pgid) = @ARGV;
$fd =~ /\A[0-9]+\z/ && $fd == 198
    && $nonce =~ /\A[a-f0-9]{64}\z/
    && $root_pid =~ /\A[0-9]+\z/ && $root_pid > 1
    && $root_pgid =~ /\A[0-9]+\z/ && $root_pgid > 1 or exit(2);
my $duplicate = dup($fd);
defined($duplicate) && $duplicate >= 0 or exit(2);
open(my $socket, "+<&=$duplicate") or exit(2);
my $payload = '';
recv($socket, $payload, 512, MSG_PEEK | MSG_DONTWAIT);
close($socket);
exit($payload eq "FULMAR_ROOT_WATCHDOG_V1:$nonce:$root_pid:$root_pgid" ? 0 : 2);
