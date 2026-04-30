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

# Embedded quotes + mixed bare keywords and colon-qualified mechanisms (movietickets.com case)
$mechs = $s->parse_spf_record('"\"v=spf1 a mx ptr a:mx0a-00176a04.pphosted.com a:mx0b-00176a04.pphosted.com ip4:64.18.0.0/20 a:dacrelay.fandango.com include:amazonses.com ip4:216.52.167.192/26 include:spf.protection.outlook.com include:sendgrid.net ~all\""');
is_deeply $mechs,
    ['a', 'mx', 'ptr', 'a:mx0a-00176a04.pphosted.com', 'a:mx0b-00176a04.pphosted.com', 'ip4:64.18.0.0/20', 'a:dacrelay.fandango.com', 'include:amazonses.com', 'ip4:216.52.167.192/26', 'include:spf.protection.outlook.com', 'include:sendgrid.net', '~all'],
    'parse embedded quotes + mixed bare/colon-qualified (movietickets.com style)';

# Ensure bare "a" and "mx" are NOT turned into "a:mx" etc.
$mechs = $s->parse_spf_record('v=spf1 a mx include:_spf.example.com a:mail.example.com ~all');
is_deeply $mechs, ['a', 'mx', 'include:_spf.example.com', 'a:mail.example.com', '~all'],
    'parse does not add colon to bare a/mx keywords';

# Additional real-world malformed SPF patterns from research
$mechs = $s->parse_spf_record("v=spf1\tip4   1.2.3.4  include\n_spf.foo.com  ~all");
is_deeply $mechs, ['ip4:1.2.3.4', 'include:_spf.foo.com', '~all'],
    'parse handles tabs, multiple spaces, and newlines';

$mechs = $s->parse_spf_record('"v=spf1 ip4:1.2.3.4 " "include:_spf.foo.com ~all"');
is_deeply $mechs, ['ip4:1.2.3.4', 'include:_spf.foo.com', '~all'],
    'parse handles split TXT strings (common in long records)';

$mechs = $s->parse_spf_record('v=spf1 spf2.0/pra ip4:1.2.3.4 foo:bar ~all');
is_deeply $mechs, ['ip4:1.2.3.4', 'foo:bar', '~all'],
    'parse handles old spf2.0 syntax and unknown mechanisms';

$mechs = $s->parse_spf_record('v=spf1 include: _spf.example.com ~all');
is_deeply $mechs, ['include:_spf.example.com', '~all'],
    'parse handles space after include: keyword';

$mechs = $s->parse_spf_record('v=spf1 a: mail.example.com mx: backup.example.com ~all');
is_deeply $mechs, ['a:mail.example.com', 'mx:backup.example.com', '~all'],
    'parse handles space after a:/mx: keywords';

# normalize_cidr
is $s->normalize_cidr('192.0.2.1'), '192.0.2.1/32', 'bare IPv4 -> /32';
is $s->normalize_cidr('2001:db8::1/64'), '2001:db8::1/64', 'IPv6 kept';
is $s->normalize_cidr('10.0.0.5/24'), '10.0.0.5/24', 'CIDR kept';

# is_ip_authorized (simple cases)
my $cidrs = ['192.0.2.0/24', '2001:db8::/32', '10.0.0.1/32'];
ok $s->is_ip_authorized('192.0.2.99', $cidrs), 'IP in /24';
ok $s->is_ip_authorized('10.0.0.1', $cidrs), 'exact /32';
ok !$s->is_ip_authorized('192.0.3.1', $cidrs), 'not in range (naive)';

# Sanitize domain (handles leading dots from macro expansion with no IP, underscores, etc.)
is $s->_sanitize_domain('._spf.mta.salesforce.com'), '_spf.mta.salesforce.com',
    'sanitize strips leading dot but keeps _spf (Salesforce mta pattern)';
is $s->_sanitize_domain('..double..dot..'), 'double.dot',
    'sanitize collapses multiple leading/trailing dots';
is $s->_sanitize_domain('foo.'), undef, 'sanitize rejects trailing-dot only after cleanup';
is $s->_sanitize_domain('_dmarc.example.com'), '_dmarc.example.com', 'sanitize preserves underscores';
is $s->_sanitize_domain(''), undef, 'sanitize rejects empty';
is $s->_sanitize_domain(undef), undef, 'sanitize rejects undef';

# Macro expansion with missing IP context (common when running without client IP)
# e.g. Salesforce-style include:%{ir}._spf.mta.%{d} when no IP → leading dot
my $bad = $s->expand_spf_macros('%{ir}._spf.mta.salesforce.com', { domain => 'salesforce.com' });
is $bad, '._spf.mta.salesforce.com', 'macro with no IP produces leading-dot name';
is $s->_sanitize_domain($bad), '_spf.mta.salesforce.com',
    'sanitize turns it into valid domain (no crash, no empty label)';

done_testing();
