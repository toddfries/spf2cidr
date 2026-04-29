#!/usr/bin/perl
package SPF2CIDR;

use strict;
use warnings;
use Carp qw(croak carp);
use Scalar::Util qw(blessed);
use Time::HiRes qw(time);

our $VERSION = '2.0.0';

# Export useful functions
use Exporter 'import';
our @EXPORT_OK = qw(
    resolve_spf_cidrs
    expand_spf_macros
    parse_spf_record
    is_ip_authorized
    normalize_cidr
);

# Default config
my %DEFAULTS = (
    max_lookups     => 10,
    timeout         => 5,
    verbose         => 0,
    strict          => 0,      # permerror on unknown mech?
    skip_ptr        => 1,      # ptr rarely useful for CIDR whitelist
    pf_table        => 'spf',
    log_file        => '/var/log/maillog',
    cache_ttl       => 3600,   # seconds, simple time based
);

sub new {
    my ($class, %opts) = @_;
    my $self = bless {
        _resolver_opt => $opts{resolver},
        cache      => $opts{cache} || {},
        config     => { %DEFAULTS, %opts },
        stats      => { dns_queries => 0, lookups => 0, cache_hits => 0 },
    }, $class;
    return $self;
}

# Accessors / lazy resolver (so pure tests don't need Net::DNS)
sub resolver {
    my $self = shift;
    return $self->{resolver} if $self->{resolver};
    my $opt = $self->{_resolver_opt};
    if ($opt) {
        $self->{resolver} = $opt;
    } else {
        require Net::DNS;
        my $r = Net::DNS::Resolver->new(
            recurse         => 1,
            persistent_udp  => 1,
            persistent_tcp  => 1,
            tcp_timeout     => $self->config->{timeout},
            udp_timeout     => $self->config->{timeout},
        );
        if (grep { /:/ } $r->nameservers) { $r->prefer_v6(1); }
        $self->{resolver} = $r;
    }
    return $self->{resolver};
}
sub config   { $_[0]->{config} }
sub cache    { $_[0]->{cache} }
sub stats    { $_[0]->{stats} }

# ==================== MACRO EXPANSION ====================

sub expand_spf_macros {
    my ($self, $text, $ctx) = @_;
    return $text unless $text && $text =~ /\%\{/;
    $ctx ||= {};

    $text =~ s{
        \%\{ 
            ([slodivhcr t])          # letter
            ([0-9]*r?|r[0-9]*)?      # optional transformers: num, r, or rnum/numr
            ([.\-+,/_=]*)?           # optional delimiter
        \}
    }{
        $self->_expand_one_macro($1, $2, $3, $ctx)
    }gex;
    return $text;
}

sub _expand_one_macro {
    my ($self, $letter, $transform, $delim, $ctx) = @_;
    $delim ||= '.';
    my $val = '';

    # Get base value
    if ($letter eq 's') {
        $val = $ctx->{sender} || $ctx->{envelope_from} || '';
    } elsif ($letter eq 'l') {
        $val = (split /@/, ($ctx->{sender} || $ctx->{envelope_from} || ''))[0] || '';
    } elsif ($letter eq 'o') {
        $val = (split /@/, ($ctx->{sender} || $ctx->{envelope_from} || ''))[1] || $ctx->{domain} || '';
    } elsif ($letter eq 'd') {
        $val = $ctx->{domain} || $ctx->{authoritative_domain} || '';
    } elsif ($letter eq 'i' || $letter eq 'c') {
        $val = $ctx->{ip} || $ctx->{client_ip} || '';
    } elsif ($letter eq 'v') {
        my $ip = $ctx->{ip} || '';
        $val = $ip =~ /:/ ? 'ip6' : 'in-addr';
    } elsif ($letter eq 'h') {
        $val = $ctx->{helo} || $ctx->{ehlo} || $ctx->{domain} || '';
    } elsif ($letter eq 'r') {
        $val = $ctx->{receiving_domain} || 'unknown';
    } elsif ($letter eq 't') {
        $val = time();
    } else {
        carp "Unknown SPF macro letter '$letter'" if $self->config->{verbose};
        return '';
    }

    # Parse transformers: support r, num, rnum, numr etc.
    my $rev = 0;
    my $num = 0;
    if ($transform) {
        $rev = 1 if $transform =~ /r/i;
        ($num) = $transform =~ /(\d+)/;
        $num ||= 0;
    }

    # Apply reverse if requested (special handling for IP letters)
    if ($rev) {
        if ($letter eq 'i' || $letter eq 'c' || $letter eq 'v') {
            $val = $self->_reverse_ip($val);
        } else {
            my @parts = split /\Q$delim\E/, $val;
            $val = join $delim, reverse @parts;
        }
    }

    # Keep only rightmost N labels/parts if specified
    if ($num > 0) {
        my @parts = split /\Q$delim\E/, $val;
        if (@parts > $num) {
            @parts = @parts[ - $num .. -1 ];
            $val = join $delim, @parts;
        }
    }

    # If custom delimiter and not IP reverse, replace natural separators (best effort)
    if ($delim ne '.' && $letter !~ /^[icv]$/ && !$rev) {
        # For non-IP, if value had ., replace with delim (rarely used)
        $val =~ s/\./$delim/g if $delim ne '.';
    }

    return $val;
}

sub _reverse_ip {
    my ($self, $ip) = @_;
    return '' unless $ip;
    if ($ip =~ /:/) {
        my $full = $self->_expand_ipv6($ip);
        my @nibbles = split //, $full;
        return join '.', reverse @nibbles;
    } else {
        my @octets = split /\./, $ip;
        return join '.', reverse @octets;
    }
}

sub _expand_ipv6 {
    my ($self, $addr) = @_;
    $addr = lc $addr;
    return $addr unless $addr =~ /:/;

    if ($addr =~ /::/) {
        my ($left, $right) = split /::/, $addr, 2;
        my @l = $left ? split(/:/, $left) : ();
        my @r = $right ? split(/:/, $right) : ();
        my $missing = 8 - @l - @r;
        $missing = 0 if $missing < 0;
        @l = map { sprintf '%04s', $_ } @l;
        @r = map { sprintf '%04s', $_ } @r;
        $addr = join '', @l, ('0000') x $missing, @r;
    } else {
        my @p = split /:/, $addr;
        $addr = join '', map { sprintf '%04s', $_ } @p;
    }
    $addr =~ s/ /0/g;
    return $addr;
}

# ==================== SPF RECORD PARSING & RESOLUTION ====================

sub parse_spf_record {
    my ($self, $txt) = @_;
    return [] unless $txt;
    $txt =~ s/^"//; $txt =~ s/"$//;  # strip outer quotes if present
    $txt =~ s/\s+/ /g;

    # Normalize common real-world malformed SPF records that omit the colon,
    # e.g. "ip4 64.125.213.247 include _spf.foo.com" (seen on about.com and others).
    # This turns them into standard "ip4:64.125.213.247 include:_spf.foo.com" form
    # so the rest of the parser and _process_mechanism regexes work unchanged.
    # Handles optional leading qualifier (+, -, ~, ?).
    $txt =~ s/\b([+?~-]?)(ip[46]|include|a|mx|ptr|exists|redirect|exp)\s+([^\s:]+)/$1$2:$3/gi;

    my @tokens = split / /, $txt;
    my @mechs;
    for my $t (@tokens) {
        next if $t =~ /^v=spf1$/i;
        next if $t =~ /^spf2\./i;
        # skip some known non-SPF verification strings early
        next if $t =~ /verification|dmarc|dkim/i && length($t) > 20;
        push @mechs, $t;
    }
    return \@mechs;
}

sub resolve_spf_cidrs {
    my ($self, $domain, $client_ip, $opts) = @_;
    $opts ||= {};
    $domain = $self->_sanitize_domain($domain);
    return [] unless $domain;

    my $ctx = {
        domain           => $domain,
        ip               => $client_ip,
        client_ip        => $client_ip,
        sender           => $opts->{sender} || "postmaster\@$domain",
        envelope_from    => $opts->{sender},
        helo             => $opts->{helo},
        receiving_domain => $opts->{receiving_domain},
    };

    my $cache_key = "CIDR:$domain:" . ($client_ip || 'static');
    if (my $cached = $self->_get_cache($cache_key)) {
        $self->stats->{cache_hits}++;
        return $cached;
    }

    my %results;  # cidr => 1 for unique
    my %seen;     # for loop detection
    my $lookups = 0;
    my $max = $self->config->{max_lookups};

    eval {
        $self->_resolve_domain($domain, $ctx, \$lookups, $max, \%seen, \%results, $opts);
    };
    if ($@) {
        carp "SPF resolution error for $domain: $@" if $self->config->{verbose};
    }

    my @cidrs = sort keys %results;
    $self->_set_cache($cache_key, \@cidrs);
    return \@cidrs;
}

sub _resolve_domain {
    my ($self, $domain, $ctx, $lookups_ref, $max, $seen, $results, $opts) = @_;
    $domain = $self->_sanitize_domain($domain);
    return unless $domain;  # skip empty or malformed domains (e.g. from bad macro expansion)
    return if $seen->{$domain}++;
    return if $$lookups_ref > $max;

    my $txts = $self->_query_txt($domain);
    return unless @$txts;

    for my $txt (@$txts) {
        next unless $txt =~ /v=spf1/i || $txt =~ /spf2\./i;
        my $mechs = $self->parse_spf_record($txt);
        for my $item (@$mechs) {
            last if $$lookups_ref > $max;  # hard stop
            $self->_process_mechanism($item, $domain, $ctx, $lookups_ref, $max, $seen, $results, $opts);
        }
    }
}

sub _process_mechanism {
    my ($self, $item, $current_domain, $ctx, $lookups_ref, $max, $seen, $results, $opts) = @_;

    my $qualifier = '+';
    if ($item =~ /^([+?~-])(.+)/) {
        $qualifier = $1;
        $item = $2;
    }

    # Skip negative mechanisms for whitelist collection (they don't authorize)
    return if $qualifier eq '-';

    if ($item =~ /^all$/i) {
        # -all already skipped, +all or ~all means everything authorized - rare, ignore for safety
        return;
    }

    if ($item =~ /^include:(.+)$/i) {
        my $target = $self->expand_spf_macros($1, $ctx);
        $target = $self->_sanitize_domain($target);
        return unless $target;  # skip bad/empty targets (e.g. macro expanded to empty or leading dot)
        $$lookups_ref++;
        if ($$lookups_ref <= $max) {
            $self->_resolve_domain($target, $ctx, $lookups_ref, $max, $seen, $results, $opts);
        }
        return;
    }

    if ($item =~ /^redirect=(.+)$/i) {
        my $target = $self->expand_spf_macros($1, $ctx);
        $target = $self->_sanitize_domain($target);
        return unless $target;
        $$lookups_ref++;
        if ($$lookups_ref <= $max) {
            # redirect replaces policy, but for whitelist we union anyway
            $self->_resolve_domain($target, $ctx, $lookups_ref, $max, $seen, $results, $opts);
        }
        return;
    }

    if ($item =~ /^ip4:([^\/]+)(?:\/(\d+))?$/i) {
        my $ip = $1;
        my $plen = defined $2 ? $2 : 32;
        my $cidr = $self->normalize_cidr("$ip/$plen");
        $results->{$cidr} = 1 if $cidr;
        return;
    }

    if ($item =~ /^ip6:([^\/]+)(?:\/(\d+))?$/i) {
        my $ip = $1;
        my $plen = defined $2 ? $2 : 128;
        my $cidr = $self->normalize_cidr("$ip/$plen");
        $results->{$cidr} = 1 if $cidr;
        return;
    }

    if ($item =~ /^a(?::([^\/]+))?(?:\/(\d+))?(?:\/(\d+))?$/i) {
        my $target = $1 ? $self->expand_spf_macros($1, $ctx) : $current_domain;
        $target = $self->_sanitize_domain($target) || $current_domain;
        my $plen4 = $2 || 32;
        my $plen6 = $3 || 128;
        $$lookups_ref++;
        if ($$lookups_ref <= $max) {
            my $addrs = $self->_query_addrs($target);
            for my $a (@$addrs) {
                my $cidr = $self->normalize_cidr( $a . '/' . ($a =~ /:/ ? $plen6 : $plen4) );
                $results->{$cidr} = 1 if $cidr;
            }
        }
        return;
    }

    if ($item =~ /^mx(?::([^\/]+))?(?:\/(\d+))?(?:\/(\d+))?$/i) {
        my $target = $1 ? $self->expand_spf_macros($1, $ctx) : $current_domain;
        $target = $self->_sanitize_domain($target) || $current_domain;
        my $plen4 = $2 || 32;
        my $plen6 = $3 || 128;
        $$lookups_ref++;
        if ($$lookups_ref <= $max) {
            my $mxs = $self->_query_mx($target);
            for my $mx (@$mxs) {
                my $addrs = $self->_query_addrs($mx);
                for my $a (@$addrs) {
                    my $cidr = $self->normalize_cidr( $a . '/' . ($a =~ /:/ ? $plen6 : $plen4) );
                    $results->{$cidr} = 1 if $cidr;
                }
            }
        }
        return;
    }

    if ($item =~ /^ptr(?::(.+))?$/i) {
        if ($self->config->{skip_ptr}) {
            carp "ptr mechanism skipped (not useful for CIDR whitelist): $item" if $self->config->{verbose} > 1;
            return;
        }
        # ptr support would require reverse + forward confirm; skip for whitelist use case
        return;
    }

    if ($item =~ /^exists:(.+)$/i) {
        my $target = $self->expand_spf_macros($1, $ctx);
        $target = $self->_sanitize_domain($target);
        return unless $target;  # skip bad targets
        $$lookups_ref++;
        if ($$lookups_ref <= $max) {
            # exists just checks presence; no CIDR to add, but could add if we wanted "any IP for that domain" but no
            $self->_query_addrs($target);  # just to count lookup
        }
        return;
    }

    if ($item =~ /^exp=/i || $item =~ /^spf2\./i) {
        return;  # modifiers / future
    }

    # Unknown mechanism
    if ($self->config->{strict}) {
        croak "Unknown SPF mechanism: $item (permerror)";
    } else {
        carp "Unhandled SPF mechanism '$item' in $current_domain" if $self->config->{verbose};
    }
}

# ==================== DNS HELPERS (with cache) ====================

sub _query_txt {
    my ($self, $domain) = @_;
    $domain = $self->_sanitize_domain($domain);
    return [] unless $domain;
    my $key = "TXT:$domain";
    if (my $c = $self->_get_cache($key)) { $self->stats->{cache_hits}++; return $c; }

    $self->stats->{dns_queries}++;
    my $reply = $self->resolver->send($domain, 'TXT');
    my @lines;
    if ($reply) {
        for my $r ($reply->answer) {
            next unless $r->type eq 'TXT';
            push @lines, join('', $r->txtdata);
        }
    } else {
        carp "TXT query failed for $domain: " . $self->resolver->errorstring if $self->config->{verbose};
    }
    $self->_set_cache($key, \@lines);
    return \@lines;
}

sub _query_addrs {
    my ($self, $domain) = @_;
    $domain = $self->_sanitize_domain($domain);
    return [] unless $domain;
    my $key = "ADDR:$domain";
    if (my $c = $self->_get_cache($key)) { $self->stats->{cache_hits}++; return $c; }

    $self->stats->{dns_queries}++;
    my @addrs;
    for my $type (qw(A AAAA)) {
        my $reply = $self->resolver->send($domain, $type);
        next unless $reply;
        for my $r ($reply->answer) {
            if ($r->type eq 'A' || $r->type eq 'AAAA') {
                push @addrs, $r->address;
            } elsif ($r->type eq 'CNAME') {
                # follow one level
                push @addrs, @{ $self->_query_addrs($r->cname) };
            }
        }
    }
    $self->_set_cache($key, \@addrs);
    return \@addrs;
}

sub _query_mx {
    my ($self, $domain) = @_;
    $domain = $self->_sanitize_domain($domain);
    return [] unless $domain;
    my $key = "MX:$domain";
    if (my $c = $self->_get_cache($key)) { $self->stats->{cache_hits}++; return $c; }

    $self->stats->{dns_queries}++;
    my @mx;
    my $reply = $self->resolver->send($domain, 'MX');
    if ($reply) {
        for my $r ($reply->answer) {
            push @mx, $r->exchange if $r->type eq 'MX';
        }
    } else {
        carp "MX query failed for $domain: " . $self->resolver->errorstring if $self->config->{verbose};
    }
    $self->_set_cache($key, \@mx);
    return \@mx;
}

# Simple time-based cache
sub _get_cache {
    my ($self, $key) = @_;
    my $ent = $self->cache->{$key};
    return unless $ent;
    if (time - $ent->{time} > $self->config->{cache_ttl}) {
        delete $self->cache->{$key};
        return;
    }
    return $ent->{val};
}

sub _set_cache {
    my ($self, $key, $val) = @_;
    $self->cache->{$key} = { val => $val, time => time };
}

sub clear_cache { $_[0]->{cache} = {} }

# ==================== UTILITIES ====================

sub normalize_cidr {
    my ($self, $cidr) = @_;
    return unless $cidr;
    if ($cidr =~ /^(\S+?)\/(\d+)$/) {
        my ($ip, $plen) = ($1, $2);
        # Basic validation / normalization
        if ($ip =~ /:/) {
            $plen = 128 if $plen > 128;
            # Could use inet_pton but keep simple; pf accepts as-is mostly
            return "$ip/$plen";
        } else {
            $plen = 32 if $plen > 32;
            # Ensure valid IPv4 octets? skip heavy check
            return "$ip/$plen";
        }
    }
    # bare IP -> /32 or /128
    if ($cidr =~ /:/) {
        return "$cidr/128";
    } elsif ($cidr =~ /^(\d+\.){3}\d+$/) {
        return "$cidr/32";
    }
    return $cidr;
}

sub is_ip_authorized {
    my ($self, $ip, $cidrs) = @_;
    # Simple check: see if ip in any cidr (for /32 exact, for larger naive)
    # For production would use Net::IP or IP::Address, but here simple for common case
    for my $c (@$cidrs) {
        if ($c =~ /^(\S+)\/(\d+)$/) {
            my ($net, $plen) = ($1, $2);
            if ($plen == 32 || $plen == 128) {
                return 1 if $net eq $ip;
            } else {
                # naive prefix match (sufficient for /24,/16 etc in practice)
                if ($plen < 32 && $ip !~ /:/) {
                    my @o = split /\./, $ip;
                    my @n = split /\./, $net;
                    my $bytes = int($plen / 8);
                    my $match = 1;
                    for my $i (0 .. $bytes-1) {
                        if ($o[$i] != $n[$i]) { $match=0; last; }
                    }
                    return 1 if $match;
                }
                return 1 if $ip eq $net;
            }
        }
    }
    return 0;
}

sub _sanitize_domain {
    my ($self, $d) = @_;
    return unless defined $d && length $d;
    $d =~ s/^\.+//;      # strip leading dots (prevents empty first label, e.g. "._spf...")
    $d =~ s/\.+$//;      # strip trailing dots
    $d = lc $d;
    $d =~ s/[^a-z0-9._-]/ /g;  # allow underscore (used in _spf, _dmarc etc.); replace others with space for safety
    $d =~ s/\s+//g;            # remove any invalid chars we turned into spaces
    $d =~ s/\.+/\./g;          # collapse consecutive dots
    return $d if $d =~ /\./ && $d !~ /^\./ && length($d) > 0;
    return;
}

# ==================== LOG WATCHER / AUTO WHITELIST ====================

sub watch_log_and_whitelist {
    my ($self, $logfile, $domains_file, $pf_table, $opts) = @_;
    $logfile  ||= $self->config->{log_file};
    $pf_table ||= $self->config->{pf_table};
    $domains_file ||= '/etc/mail/spf-domains';

    my %watch_domains;
    if (-f $domains_file) {
        open my $fh, '<', $domains_file or croak "Cannot open $domains_file: $!";
        while (<$fh>) {
            s/#.*//; s/^\s+//; s/\s+$//;
            next unless length;
            my ($dom, $ips) = split /\s+/, $_, 2;
            $watch_domains{lc $dom} = $ips ? [split /[, ]+/, $ips] : 1;
        }
        close $fh;
    }

    my %already_added;
    my $pos = 0;

    print STDERR "SPF2CIDR watcher starting on $logfile, table <$pf_table>\n" if $self->config->{verbose};

    while (1) {
        my $fh;
        unless (open $fh, '<', $logfile) {
            carp "Cannot open log $logfile: $!"; sleep 5; next;
        }
        seek $fh, $pos, 0;
        while (my $line = <$fh>) {
            if (my ($ip, $from) = $self->_parse_spamd_grey_line($line)) {
                my $dom = lc( (split /@/, $from)[1] || '' );
                next unless $dom;
                next unless exists $watch_domains{$dom} || keys(%watch_domains) == 0;  # if empty watch all

                print STDERR "GREY detected: $ip from $from ($dom)\n" if $self->config->{verbose};

                my $cidrs = $self->resolve_spf_cidrs($dom, $ip, { sender => $from });
                next unless @$cidrs;

                if ($self->is_ip_authorized($ip, $cidrs)) {
                    for my $c (@$cidrs) {
                        next if $already_added{$c};
                        $self->_pfctl_add($pf_table, $c);
                        $already_added{$c} = 1;
                        print STDERR "  Added $c to <$pf_table> for $dom\n" if $self->config->{verbose};
                    }
                } else {
                    carp "IP $ip not authorized by SPF for $dom (possible spoof?)" if $self->config->{verbose};
                }
            }
        }
        $pos = tell $fh;
        close $fh;
        sleep 2;  # poll interval
    }
}

sub _parse_spamd_grey_line {
    my ($self, $line) = @_;
    # Matches: (GREY) 156.70.46.238: <user@domain.com> -> <to@...>
    if ($line =~ /\(GREY\)\s+([\d.]+|[0-9a-f:]+):\s+<[^>]*@([^>\s]+)>/i) {
        return ($1, $2);  # ip, from-domain
    }
    # Also support other formats like spamd: GREY ...
    if ($line =~ /GREY.*?\b((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+)\b.*?<[^>]*@([^>\s]+)>/) {
        return ($1, $2);
    }
    return;
}

sub _pfctl_add {
    my ($self, $table, $cidr) = @_;
    my $cmd = "pfctl -t $table -T add $cidr 2>&1";
    my $out = `$cmd`;
    if ($? != 0 && $out !~ /already exists|added/) {
        carp "pfctl add $cidr failed: $out";
    }
}

# ==================== CLI / BATCH MODE ====================

sub process_domains {
    my ($self, $domains, $output_fh) = @_;
    $output_fh ||= \*STDOUT;
    for my $entry (@$domains) {
        my ($dom, $ip) = split /\s+/, $entry, 2;
        my $cidrs;
        if ($ip) {
            # support multi: ip1,ip2
            my @ips = split /[, ]+/, $ip;
            my %all;
            for my $i (@ips) {
                my $c = $self->resolve_spf_cidrs($dom, $i);
                $all{$_} = 1 for @$c;
            }
            $cidrs = [sort keys %all];
        } else {
            $cidrs = $self->resolve_spf_cidrs($dom);
        }
        for my $c (@$cidrs) {
            printf $output_fh "%-40s # %s\n", $c, $dom;
        }
    }
}

1;

__END__

=head1 NAME

SPF2CIDR - Extract CIDR blocks from SPF records for firewall whitelisting (pf/spamd)

=head1 SYNOPSIS

  use SPF2CIDR;
  my $s = SPF2CIDR->new(verbose => 1);
  my $cidrs = $s->resolve_spf_cidrs('example.com');
  my $cidrs = $s->resolve_spf_cidrs('bounce.entrykeyid.com', '156.70.46.238');

  # Watch mode
  $s->watch_log_and_whitelist();

=head1 DESCRIPTION

Full featured SPF parser, macro expander (including IPv6), recursive include/redirect
handling with loop protection and 10-lookup limit. Designed for OpenBSD pf tables
to bypass spamd greylisting for legitimate senders.

Supports static domains, dynamic macro-based (Proofpoint pphosted, etc.), multi-IP,
log tail auto-whitelisting, and is fully unit-testable.

See bin/spf2cidr and bin/spf2cidr-watch for CLI tools.

=head1 AUTHOR

Extended from original by todd@fries.net, massively enhanced 2026.

=cut
