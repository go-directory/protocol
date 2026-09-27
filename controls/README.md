# controls

Package controls contains core **Control** types, codecs and other facilities. It is given its own dedicated package subdirectory simply because it is both large (and getting larger), and is a likely candidate for community contributions going forward.

For information on LDAP Controls, see [RFC 4511](https://datatracker.ietf.org/doc/html/rfc4511).

Under most circumstances, this package need not be used directly by the end user. The parent _protocol_ package maintains linkages to all pertinent types and functions in this package.
