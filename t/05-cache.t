#!/usr/bin/perl
use strict;
use warnings;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use SPF2CIDR::Cache;
use SPF2CIDR;
use Test::More;
package main;

# ============================================================
# BASIC FUNCTIONALITY
# ============================================================

SPF2CIDR::Cache->clear();
is( SPF2CIDR::Cache->size(), 0, 'cache starts empty' );

SPF2CIDR::Cache->set('TXT:example.com', ['v=spf1 ip4:1.2.3.4 ~all']);
is( SPF2CIDR::Cache->size(), 1, 'set increases size' );
is_deeply( SPF2CIDR::Cache->get('TXT:example.com'),
           ['v=spf1 ip4:1.2.3.4 ~all'],
           'get returns stored value' );

# ============================================================
# EXPIRATION
# ============================================================

SPF2CIDR::Cache->set('short', 'value', 1);   # 1 second TTL
sleep 2;
is( SPF2CIDR::Cache->get('short'), undef, 'entry expires after TTL' );
is( SPF2CIDR::Cache->size(), 1, 'expired entry is removed on get' );

# ============================================================
# SHARED ACROSS INSTANCES (process-wide)
# ============================================================

my $s1 = SPF2CIDR->new();
my $s2 = SPF2CIDR->new();

SPF2CIDR::Cache->set('SHARED:google.com', ['v=spf1 include:_spf.google.com ~all']);
is_deeply( $s1->stats(), $s2->stats(), 'stats shared (via module)' );

# ============================================================
# STATS
# ============================================================

SPF2CIDR::Cache->clear();
SPF2CIDR::Cache->set('a', 1);
SPF2CIDR::Cache->get('a');           # hit
SPF2CIDR::Cache->get('b');           # miss
my $stats = SPF2CIDR::Cache->stats();
is( $stats->{hits}, 1, 'hit counted' );
is( $stats->{misses}, 1, 'miss counted' );
is( $stats->{sets}, 1, 'set counted' );
is( $stats->{size}, 1, 'size correct' );

# ============================================================
# BROKEN USAGE / EDGE CASES
# ============================================================

# undef key
SPF2CIDR::Cache->set(undef, 'bad');
is( SPF2CIDR::Cache->size(), 1, 'undef key ignored (no crash)' );

# empty key
SPF2CIDR::Cache->set('', 'also bad');
is( SPF2CIDR::Cache->size(), 1, 'empty key ignored' );

# very long key (should still work)
my $long_key = 'A' x 1000;
SPF2CIDR::Cache->set($long_key, 'ok');
is( SPF2CIDR::Cache->get($long_key), 'ok', 'very long key works' );

# negative TTL (should be treated as 1 second minimum)
SPF2CIDR::Cache->set('neg', 'x', -5);
sleep 2;
is( SPF2CIDR::Cache->get('neg'), undef, 'negative TTL treated as minimum 1s' );

# clear
SPF2CIDR::Cache->clear();
is( SPF2CIDR::Cache->size(), 0, 'clear empties cache' );
is_deeply( SPF2CIDR::Cache->stats(),
             { hits => 0, misses => 0, sets => 0, evictions => 0, size => 0 },
             'clear resets stats' );

done_testing();
