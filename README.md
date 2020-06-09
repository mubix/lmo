# lmo-oob
LetMeOutOfYour.net OOB

This is an out of band (via DNS) checker to see if a host can talk outbound to LetMeOutOfYour.net

It uses Base32 in order to make the DNS requests work and converts the qual signs to "-A" to
ensure that the DNS hostname ends in a alphanumeric character.

This script also adds on a tail at the beginning that is randomized to make sure caching doesn't
stop multiple runs from working.
