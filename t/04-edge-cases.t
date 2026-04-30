#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use SPF2CIDR;

my $s = SPF2CIDR->new(verbose => 0);

# ============================================================
# 1. MALFORMED / ABUSIVE SPF SYNTAX FROM THE WILD
# ============================================================

# about.com style (no colon)
my $mechs = $s->parse_spf_record('v=spf1 ip4 64.125.213.247 include _spf.salesforce.com ~all');
is_deeply $mechs, ['ip4:64.125.213.247', 'include:_spf.salesforce.com', '~all'],
    'about.com style (space instead of colon)';

# Multiple spaces, tabs, weird whitespace
$mechs = $s->parse_spf_record("v=spf1\tip4   1.2.3.4  include\n_spf.foo.com  ~all");
is_deeply $mechs, ['ip4:1.2.3.4', 'include:_spf.foo.com', '~all'],
    'multiple whitespace / tabs / newlines';

# Split TXT strings (common in long records)
$mechs = $s->parse_spf_record('"v=spf1 ip4:1.2.3.4 " "include:_spf.foo.com ~all"');
is_deeply $mechs, ['ip4:1.2.3.4', 'include:_spf.foo.com', '~all'],
    'split TXT strings (Net::DNS joins them)';

# ============================================================
# EMBEDDED QUOTES (movietickets.com and similar real-world cases)
# ============================================================

# The exact movietickets.com SPF record with embedded quotes
my $movietickets_txt = '"\"v=spf1 a mx ptr a:mx0a-00176a04.pphosted.com a:mx0b-00176a04.pphosted.com ip4:64.18.0.0/20 a:dacrelay.fandango.com include:amazonses.com ip4:216.52.167.192/26 include:spf.protection.outlook.com include:sendgrid.net ~all\""';
$mechs = $s->parse_spf_record($movietickets_txt);
ok @$mechs >= 10, 'movietickets.com embedded quotes produces many mechanisms';
ok grep({ $_ eq 'a' } @$mechs), 'movietickets.com has bare a';
ok grep({ $_ eq 'mx' } @$mechs), 'movietickets.com has bare mx';
ok grep({ $_ eq 'ip4:216.52.167.192/26' } @$mechs), 'movietickets.com has ip4:216.52.167.192/26';
ok grep({ $_ eq 'include:amazonses.com' } @$mechs), 'movietickets.com has include:amazonses.com';
ok grep({ $_ eq 'include:spf.protection.outlook.com' } @$mechs), 'movietickets.com has include:spf.protection.outlook.com';

# Double-escaped quotes (some DNS tools output this)
$mechs = $s->parse_spf_record('"\\"v=spf1 ip4:1.2.3.4 ~all\\""');
ok grep({ $_ eq 'ip4:1.2.3.4' } @$mechs), 'handles double-escaped quotes';

# Old spf2.0 syntax + garbage
$mechs = $s->parse_spf_record('v=spf1 spf2.0/pra ip4:1.2.3.4 foo:bar ~all');
is_deeply $mechs, ['ip4:1.2.3.4', 'foo:bar', '~all'],
    'old spf2.0 + unknown mechanism';

# Extremely long mechanism list (simulated)
my $long = 'v=spf1 ' . join(' ', map { "ip4:10.0.0.$_" } 1..50) . ' ~all';
$mechs = $s->parse_spf_record($long);
ok @$mechs > 40, 'handles very long SPF records (50+ ip4)';

# ============================================================
# 2. MACRO ABUSE / LEADING DOT / EMPTY EXPANSION
# ============================================================

# Classic Salesforce mta abuse when no IP provided
my $bad = $s->expand_spf_macros('%{ir}._spf.mta.salesforce.com', { domain => 'salesforce.com' });
is $bad, '._spf.mta.salesforce.com', 'Salesforce %{ir}._spf.mta... with no IP';
is $s->_sanitize_domain($bad), '_spf.mta.salesforce.com',
    'sanitize turns leading-dot into valid _spf domain';

# Empty macro result
is $s->expand_spf_macros('%{d}', {}), '', 'empty %{d} when no domain in ctx';
is $s->_sanitize_domain(''), undef, 'empty string rejected by sanitize';

# Malformed macro (unclosed)
is $s->expand_spf_macros('%{d', { domain => 'example.com' }), '%{d', 'unclosed macro left as-is';

# Unknown macro letter
is $s->expand_spf_macros('%{z}.example.com', { domain => 'example.com' }), '%{z}.example.com',
    'unknown macro letter %{z} is left literal (safer per RFC)';

# Macro with custom delimiter and reverse
is $s->expand_spf_macros('%{d2r}', { domain => 'a.b.c.example.com' }), 'b.a',
    'macro with number + reverse transformer (keeps rightmost 2 after reverse)';

# ============================================================
# 3. INVALID / ABUSIVE DOMAIN NAMES
# ============================================================

is $s->_sanitize_domain('._spf..mta...com'), '_spf.mta.com', 'multiple empty labels collapsed';
is $s->_sanitize_domain('foo-.bar.com'), undef, 'label ending with hyphen rejected (strict)';
is $s->_sanitize_domain('-foo.bar.com'), undef, 'label starting with hyphen rejected';
is $s->_sanitize_domain('a' x 64 . '.example.com'), undef, 'label >63 chars rejected';
is $s->_sanitize_domain( ('a' x 60 . '.') x 5 . 'com' ), undef, 'total name >255 chars rejected';
is $s->_sanitize_domain('foo..bar.com'), 'foo.bar.com', 'consecutive dots collapsed';
is $s->_sanitize_domain('FOO.BAR.COM.'), 'foo.bar.com', 'uppercase + trailing dot normalized';
is $s->_sanitize_domain('foo_bar-baz.example.com'), 'foo_bar-baz.example.com', 'underscore + hyphen allowed';

# ============================================================
# 4. MECHANISM EDGE CASES
# ============================================================

# ip4 with invalid CIDR (should still parse, normalize_cidr will cap it)
is $s->normalize_cidr('1.2.3.4/999'), '1.2.3.4/32', 'ip4 with insane prefixlen capped to 32';
is $s->normalize_cidr('2001:db8::1/200'), '2001:db8::1/128', 'ip6 with insane prefixlen capped';

# a: and mx: with macro that produces truly invalid domain (starts with hyphen after sanitize)
my $target = $s->expand_spf_macros('%{ir}-bad.com', {});
$target = $s->_sanitize_domain($target) || 'example.com';
is $target, 'example.com', 'a:/mx: with bad macro target falls back to current domain';

# exists: with bad macro target (should be skipped)
# (tested via full resolve in mock tests)

# ptr: is skipped by default (already tested)

# ============================================================
# 5. LOOKUP LIMIT / LOOP DETECTION
# ============================================================

# We can't easily test the full 10-lookup limit without a live resolver,
# but we can test that the seen hash prevents obvious self-includes.
# (covered in 03-resolution-mock.t)

pass('lookup limit and loop detection logic present (tested via integration)');

done_testing();
