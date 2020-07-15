Let Me Out (LMO) of your .net is a Egress testing and verification frame work.

The resources in this repository are publicly available as well as the server (LetMeOutOfYour.net).


# lmo-oob.py
LetMeOutOfYour.net OOB

This is an out of band (via DNS) checker to see if a host can talk outbound to LetMeOutOfYour.net

It uses Base32 in order to make the DNS requests work and converts the qual signs to "-A" to
ensure that the DNS hostname ends in a alphanumeric character.

This script also adds on a tail at the beginning that is randomized to make sure caching doesn't
stop multiple runs from working.

Here is an example run inside a network that only allows 80 and 443 out, with verbosity turned on:
(this also shows that the network doesn't do protocol matching so it's possible SSH can be sent out 80/443)

```
$ ./lmo-oob.py
Testing: http://letmeoutofyour.net:80
w00tw00t
wtsvmufbpr.NB2HI4B2F4XWYZLUNVSW65LUN5THS33VOIXG4ZLUHI4DA-A-A-A.malicious.link
Testing: https://letmeoutofyour.net:80
w00tw00t
wtsvmufbpr.NB2HI4DTHIXS63DFORWWK33VORXWM6LPOVZC43TFOQ5DQMA-A.malicious.link
Testing: http://letmeoutofyour.net:443
w00tw00t
wtsvmufbpr.NB2HI4B2F4XWYZLUNVSW65LUN5THS33VOIXG4ZLUHI2DIMY-A.malicious.link
Testing: https://letmeoutofyour.net:443
w00tw00t
wtsvmufbpr.NB2HI4DTHIXS63DFORWWK33VORXWM6LPOVZC43TFOQ5DINBT.malicious.link
Testing: http://letmeoutofyour.net:445
Failed to connect
Testing: https://letmeoutofyour.net:445
Failed to connect
Testing: http://letmeoutofyour.net:8080
Failed to connect
Testing: https://letmeoutofyour.net:8080
Failed to connect
Testing: http://letmeoutofyour.net:3389
Failed to connect
Testing: https://letmeoutofyour.net:3389
Failed to connect
Testing: http://letmeoutofyour.net:22
Failed to connect
Testing: https://letmeoutofyour.net:22
Failed to connect
Testing: http://letmeoutofyour.net:21
Failed to connect
Testing: https://letmeoutofyour.net:21
Failed to connect
```
