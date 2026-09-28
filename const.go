package protocol

/*
ServicePortLDAP defines the LDAP/TCP service port number as a string.
This port covers both unencrypted and encrypted requests.
*/
const ServicePortLDAP = "389"

/*
ServicePortLDAPS defines the legacy LDAPS/TCP port number as a string.
This port only covers traditional SSLv3 requests.

Note that this port is considered deprecated. Avoid use of this port
wherever possible.

For encrypted traffic, use of StartTLS is always preferred, whether
opportunistic or with positive criticality.
*/
const ServicePortLDAPS = "636"
