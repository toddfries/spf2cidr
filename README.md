spf2cidr was inspired by a shell script called 'getwhite' provided by
WEiRDJE on mindcry/#openbsd irc.

One might add something similar to this in /etc/daily.local on OpenBSD:

<pre>
cd /etc/mail && {
        ./spf2cidr -o whitelist=nl > .whitelist.spf2cidr
        {
                cat whitelist.top
                grep "^#" .whitelist.spf2cidr
                grep -v "^#" .whitelist.spf2cidr | sort +2
        } > .whitelist.txt
        if [ $? -eq 0 ]; then
                [ -s .whitelist.txt ] && cmp -s .whitelist.txt whitelist.txt || {
                        mv .whitelist.txt whitelist.txt
                        pfctl -f /etc/pf.conf
                }
        fi
}
</pre>

I always am interested in feedback and especially suggestions or tweaks in
the form of 'diff -u'.  Please contact todd@fries.net if you have any of the
above.

Prereq:

```
  Net::DNS
```

If you find this useful and wish to donate, I accept donations:

- BTC: [1Bkbew38fKiLRiis9kMWJnUf9Eozp5yY6S](bitcoin:1Bkbew38fKiLRiis9kMWJnUf9Eozp5yY6S)

- DCR: [DsY8PiyHEbFKPD3SmKpUM2Wx8XJsT5VcxSr](decred:DsY8PiyHEbFKPD3SmKpUM2Wx8XJsT5VcxSr)
