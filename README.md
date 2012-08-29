spf2cidr was inspired by a shell script called 'getwhite' provided by
WEiRDJE on mindcry/#openbsd irc.

One might add something similar to this in /etc/daily.local on OpenBSD:

cd /etc/mail && {
        ./spf2cidr > .whitelist.spf2cidr
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
