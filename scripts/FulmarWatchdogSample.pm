package FulmarWatchdogSample;

use strict;
use warnings;
use Exporter qw(import);

our @EXPORT_OK = qw(parse_process_group_sample);

sub parse_process_group_sample {
    my ($output, $process_group) = @_;
    return undef unless defined($output) && defined($process_group)
        && $process_group =~ /\A[0-9]+\z/ && $process_group > 1
        && length($output) <= 2 * 1_024 * 1_024;
    return undef if length($output) > 0 && $output !~ /\n\z/;

    my $total_kib = 0;
    my $members = 0;
    my @lines = split(/\n/, $output, -1);
    pop(@lines) if @lines && $lines[-1] eq '';
    return undef if !@lines || @lines > 16_384;
    for my $line (@lines) {
        return undef if length($line) > 128;
        return undef unless $line =~ /\A\s*([0-9]+)\s+([0-9]+)\s*\z/;
        next unless $1 == $process_group;
        ++$members;
        $total_kib += $2;
        return undef if $total_kib > 50 * 1_024 * 1_024;
    }
    return { members => $members, rss_bytes => $total_kib * 1_024 };
}

1;
