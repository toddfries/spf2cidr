#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use SPF2CIDR;

# Mock resolver that returns canned DNS answers without Net::DNS
package MockResolver;
sub new { bless { canned => {} }, shift }
sub send {
    my ($self, $name, $type) = @_;
    my $key = "$type:$name";
    my $data = $self->{canned}{$key} || [];
    my $reply = bless { _answers => [] }, 'MockReply';
    for my $d (@$data) {
        push @{ $reply->{_answers} }, bless $d, 'MockRR';
    }
    return $reply;
}
sub errorstring { 'no error (mock)' }

package MockReply;
sub answer { @{ shift->{_answers} } }

package MockRR;
sub type { shift->{type} }
sub txtdata { @{ shift->{txtdata} || [] } }
sub address { shift->{address} }
sub exchange { shift->{exchange} }
sub cname { shift->{cname} }

package main;

# Create SPF instance with mock resolver
my $mock = MockResolver->new();
my $s = SPF2CIDR->new(resolver => $mock, verbose => 0, cache_ttl => 0);

# Seed canned responses for entrykeyid.com (static + macro include)
$mock->{canned}{'TXT:entrykeyid.com'} = [
    { type => 'TXT', txtdata => ['v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com ip4:91.209.104.0/25 -all'] }
];
# The expanded include for our test IP
$mock->{canned}{'TXT:238.46.70.156.in-addr.entrykeyid.com.spf.has.pphosted.com'} = [
    { type => 'TXT', txtdata => ['v=spf1 ip4:156.70.46.238/32 ip4:156.70.46.0/24 -all'] }
];

my $cidrs = $s->resolve_spf_cidrs('entrykeyid.com', '156.70.46.238');
ok @$cidrs >= 2, 'got CIDRs from macro include';
ok grep(/156.70.46/, @$cidrs), 'includes the sending IP range';
ok grep(/91.209.104/, @$cidrs), 'includes static ip4 from top SPF';

# Another static domain
$mock->{canned}{'TXT:example.com'} = [
    { type => 'TXT', txtdata => ['v=spf1 ip4:203.0.113.0/24 mx:mail.example.com -all'] }
];
$mock->{canned}{'MX:mail.example.com'} = [
    { type => 'MX', exchange => 'mail1.example.com' }
];
$mock->{canned}{'A:mail1.example.com'} = [
    { type => 'A', address => '203.0.113.10' }
];
$mock->{canned}{'AAAA:mail1.example.com'} = [];

$cidrs = $s->resolve_spf_cidrs('example.com');
ok grep(/203.0.113.0\/24/, @$cidrs), 'static ip4';
ok grep(/203.0.113.10\/32/, @$cidrs), 'mx resolved to IP';

# ============================================================
# INCLUDE FOLLOWING TEST (movietickets.com style - verifies fix for recursion/seen bug)
# ============================================================
# This ensures includes are properly recursed into (previously broken by post-increment
# seen check that caused _resolve_domain to skip processing the included domain's SPF).
# Also tests multiple includes + direct ip4/a/mx, matching real-world complex SPF.
$mock->{canned}{'TXT:movietickets.com'} = [
    { type => 'TXT', txtdata => ['v=spf1 a mx ip4:216.52.167.192/26 include:amazonses.com include:spf.protection.outlook.com include:sendgrid.net ~all'] }
];
$mock->{canned}{'TXT:amazonses.com'} = [
    { type => 'TXT', txtdata => ['v=spf1 ip4:199.127.232.0/22 ip4:199.255.192.0/22 ip4:206.55.144.0/20 -all'] }
];
$mock->{canned}{'TXT:spf.protection.outlook.com'} = [
    { type => 'TXT', txtdata => ['v=spf1 ip4:40.107.0.0/16 ip4:52.100.0.0/15 ip6:2a01:111:f400::/48 -all'] }
];
$mock->{canned}{'TXT:sendgrid.net'} = [
    { type => 'TXT', txtdata => ['v=spf1 ip4:167.89.0.0/17 -all'] }
];
# Bare a/mx on movietickets would normally need A/MX seeds, but we test the includes + direct ip4 here
# (full a/mx would add more but not required for this regression test)

$cidrs = $s->resolve_spf_cidrs('movietickets.com');
ok @$cidrs >= 8, 'got many CIDRs including from includes (not just direct)';
ok grep(/216.52.167.192/, @$cidrs), 'direct ip4 from movietickets.com';
ok grep(/199.127.232/, @$cidrs), 'CIDR from included amazonses.com';
ok grep(/40.107.0.0/, @$cidrs), 'CIDR from included spf.protection.outlook.com';
ok grep(/2a01:111:f400/, @$cidrs), 'IPv6 CIDR from included outlook';
ok grep(/167.89.0.0/, @$cidrs), 'CIDR from included sendgrid.net';
# Ensure no duplicates and all normalized
is( (grep { $_ eq '216.52.167.192/26' } @$cidrs), 1, 'no duplicate CIDRs' );

# Test loop detection still works (self-include should not infinite loop)
$mock->{canned}{'TXT:loop.com'} = [
    { type => 'TXT', txtdata => ['v=spf1 include:loop.com ip4:10.0.0.0/8 -all'] }
];
$cidrs = $s->resolve_spf_cidrs('loop.com');
ok grep(/10.0.0.0/, @$cidrs), 'loop detected, still got direct ip4';
ok @$cidrs < 5, 'no explosion from include loop';

done_testing();
