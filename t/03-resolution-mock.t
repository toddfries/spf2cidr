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

# Test lookup limit protection (would need more includes, but mock simple)
# Test loop detection via seen

done_testing();
