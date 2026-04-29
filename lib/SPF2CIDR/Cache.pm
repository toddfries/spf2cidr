package SPF2CIDR::Cache;

use strict;
use warnings;
use Time::HiRes qw(time);

our %CACHE;   # key => { val => $data, expires => $epoch }
our %STATS = (
    hits      => 0,
    misses    => 0,
    sets      => 0,
    evictions => 0,
);

=head1 NAME

SPF2CIDR::Cache - Simple in-memory DNS lookup cache for SPF2CIDR

=head1 SYNOPSIS

    use SPF2CIDR::Cache;

    SPF2CIDR::Cache->set("TXT:example.com", ["v=spf1 ..."], 3600);
    my $txt = SPF2CIDR::Cache->get("TXT:example.com");

    SPF2CIDR::Cache->clear();
    my $stats = SPF2CIDR::Cache->stats();

=head1 DESCRIPTION

Process-wide in-memory cache for DNS results (TXT, A, AAAA, MX).
Keys are typically "TYPE:domain" (e.g. "TXT:example.com", "ADDR:mail.google.com").

Automatically expires entries based on TTL. Designed to eliminate
duplicate DNS lookups during a single SPF walk (very common with
large providers that appear in many includes).

No forking, threading, or external dependencies beyond core Perl.

=cut

sub get {
    my ($class, $key) = @_;
    return unless defined $key && length $key;

    my $ent = $CACHE{$key};
    if ($ent && time() < $ent->{expires}) {
        $STATS{hits}++;
        return $ent->{val};
    }

    if ($ent) {
        delete $CACHE{$key};
        $STATS{evictions}++;
    }
    $STATS{misses}++;
    return;
}

sub set {
    my ($class, $key, $val, $ttl) = @_;
    return unless defined $key && length $key;

    $ttl ||= 3600;  # default 1 hour
    $ttl = 1 if $ttl < 1;  # minimum 1 second

    $CACHE{$key} = {
        val     => $val,
        expires => time() + $ttl,
    };
    $STATS{sets}++;
}

sub clear {
    %CACHE = ();
    %STATS = (hits => 0, misses => 0, sets => 0, evictions => 0);
}

sub size {
    return scalar keys %CACHE;
}

sub stats {
    return {
        %STATS,
        size => scalar keys %CACHE,
    };
}

1;

__END__

=head1 METHODS

=over 4

=item get($key)

Returns cached value or undef if missing/expired.

=item set($key, $value, $ttl_seconds?)

Stores value with optional TTL (default 3600).

=item clear()

Empties the cache and resets statistics.

=item size()

Number of entries currently in cache.

=item stats()

Returns hashref with hits, misses, sets, evictions, and current size.

=back

=cut
