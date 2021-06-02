# Anonymization
A golang module that offers data anonymization support for privacy protection.

# IP address anonymization
IP address anonymization is implemented using the "ipcipher" specification. See:
https://powerdns.org/ipcipher/ipcipher.md.html

# SIP URI anonymization
See SIP RFC https://datatracker.ietf.org/doc/html/rfc3261 for a formal description of SIP URIs.

SIP URIs are anonymized using a specification that preserves the format.

There are 2 main modes of operation:
1. Everything on the right hand side of `@` sign is anonymized. e.g.:
  * plain URI: `sip:foo:pass@bar.com:5060;ttl=1`
  * anonymized URI: `sip:7FIQTTVPC65OONS0H7B1O9EAE8------@G8K7BRIJU51JVFLRSSCBEV2RCQVF6O3T1HK09GQGH3M33D30ILBG----`
2. Only the host information on the right hand side of `@` sign is anonymized. e.g.:
  * plain URI: `sip:foo:pass@bar.com:5060;ttl=1`
  * anonymized URI: `sip:7FIQTTVPC65OONS0H7B1O9EAE8------@86O14ERFB383DT1IOALB79L798------:5060;ttl=1`

`@` left handside (user and password) and `@` right handside (host information, port, parameters & headers) are anonymized in the following manner:

1. one IV and two unique 16 byte (128 bits) AES-CBC keys (one for `@` lhs, one for `@` rhs) are derived from a common master key using PBKDF2 (see https://datatracker.ietf.org/doc/html/rfc2898#section-5.2)
1. `@` lhs and `@` rhs are encrypted, separately, using 16 byte (128 bits) AES-CBC block cipher and the keys derived at step 1.
2. finally they are encoded using base32 encoding ("Base 32 Encoding with Extended Hex Alphabet", with `-` used as pad character). See https://datatracker.ietf.org/doc/html/rfc4648#section-7 for details on base32 encoding.
