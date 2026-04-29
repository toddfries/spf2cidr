#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use SPF2CIDR;

my $s = SPF2CIDR->new(verbose => 0);  # no DNS needed

# Basic macro tests
is $s->expand_spf_macros('v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com -all',
    { ip => '156.70.46.238', domain => 'entrykeyid.com' }),
   'v=spf1 include:238.46.70.156.in-addr.entrykeyid.com.spf.has.pphosted.com -all',
   'Proofpoint pphosted macro expansion (IPv4)';

is $s->expand_spf_macros('%{ir}.%{v}.%{d}.spf.has.pphosted.com',
    { ip => '2001:db8::1', domain => 'example.com' }),
   '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.example.com.spf.has.pphosted.com',
   'IPv6 ir macro expansion';

is $s->expand_spf_macros('%{d}', { domain => 'Foo.Bar.COM.' }),
   'Foo.Bar.COM.', 'domain macro (lowercasing done in resolve path)';

is $s->expand_spf_macros('%{l}@%{o}', { sender => 'user+tag@example.co.uk' }),
   'user+tag@example.co.uk', 'l and o macros';

is $s->expand_spf_macros('%{d2}', { domain => 'a.b.c.d.example.com' }),
   'example.com', 'keep rightmost 2 labels (of 6-part domain)';

is $s->expand_spf_macros('%{dr}', { domain => 'a.b.c.example.com' }),
   'com.example.c.b.a', 'reverse labels';

is $s->expand_spf_macros('ip=%{i}', { ip => '192.0.2.1' }),
   'ip=192.0.2.1', 'plain i macro';

# IPv6 full
is $s->_expand_ipv6('2001:db8::1'), '20010db8000000000000000000000001', 'expand_ipv6 ::';
is $s->_expand_ipv6('::ffff:192.0.2.1'), '000000000000000000000000ffff192.0.2.1', 'expand_ipv6 IPv4-mapped (current impl keeps dotted for IPv4 part in ::ffff)';

# Reverse IP
is $s->_reverse_ip('156.70.46.238'), '238.46.70.156', 'reverse IPv4';
is $s->_reverse_ip('2001:db8::1'), '1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2', 'reverse IPv6 nibbles';

# Complex with sender
is $s->expand_spf_macros('%{l}.%{o}', { sender => 'bounces-123@bounce.entrykeyid.com', domain => 'entrykeyid.com' }),
   'bounces-123.bounce.entrykeyid.com', 'l + o with bounce address';

done_testing();
