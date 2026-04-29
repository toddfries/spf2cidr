#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use SPF2CIDR;

my $s = SPF2CIDR->new(verbose => 0);

# parse_spf_record
my $mechs = $s->parse_spf_record('v=spf1 ip4:192.0.2.0/24 include:_spf.example.com -all');
is_deeply $mechs, ['ip4:192.0.2.0/24', 'include:_spf.example.com', '-all'], 'parse basic';

$mechs = $s->parse_spf_record('"v=spf1 ip6:2001:db8::/32 ~all"');
is_deeply $mechs, ['ip6:2001:db8::/32', '~all'], 'parse quoted';

# Real-world malformed SPF (about.com and others omit the colon after ip4/include)
$mechs = $s->parse_spf_record('v=spf1 ip4 64.125.213.247 ip4 216.223.13.247 include _spf.salesforce.com include _spf.google.com ~all');
is_deeply $mechs, ['ip4:64.125.213.247', 'ip4:216.223.13.247', 'include:_spf.salesforce.com', 'include:_spf.google.com', '~all'],
    'parse malformed space-separated ip4/include (about.com style)';

# normalize_cidr
is $s->normalize_cidr('192.0.2.1'), '192.0.2.1/32', 'bare IPv4 -> /32';
is $s->normalize_cidr('2001:db8::1/64'), '2001:db8::1/64', 'IPv6 kept';
is $s->normalize_cidr('10.0.0.5/24'), '10.0.0.5/24', 'CIDR kept';

# is_ip_authorized (simple cases)
my $cidrs = ['192.0.2.0/24', '2001:db8::/32', '10.0.0.1/32'];
ok $s->is_ip_authorized('192.0.2.99', $cidrs), 'IP in /24';
ok $s->is_ip_authorized('10.0.0.1', $cidrs), 'exact /32';
ok !$s->is_ip_authorized('192.0.3.1', $cidrs), 'not in range (naive)';

done_testing();
