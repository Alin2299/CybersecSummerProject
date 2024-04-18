import sys
import re

file = sys.argv[1]
#d = {}
#keys = []

ciphers = {}

#Read in the data, first line is a header
with open(file) as f:
    next(f)
    for line in f:
        line.strip()
        ciphers[line] = "1, Starting value"

#Score the keys based on string matches
for key in ciphers:
#    print(type(key))
    if re.search("TLS_RSA_", key, re.I):
        ciphers[key] = "2, RSA authentication, which does not allow for PFS"
    if re.search("_ECDH_", key, re.I):
        ciphers[key] = "2, ECDH authentication, which does not allow for PFS"

    if re.search("_CBC_", key, re.I):
        ciphers[key] = "2, CBC encryption mode support"
    if re.search("SEED", key, re.I):
        ciphers[key] = "2, SEED cipher"
    if re.search("CAMELLIA", key, re.I):
        ciphers[key] = "2, CAMELLIA cipher"
    if re.search("IDEA", key, re.I):
        ciphers[key] = "2, IDEA cipher"
    if re.search("ARIA", key, re.I):
        ciphers[key] = "2, ARIA cipher"

    if re.search("PSK", key, re.I):
        ciphers[key] = "3, PSK authentication"
    if re.search("RC4", key, re.I):
        ciphers[key] = "3, RC4 cipher"
    if re.search("MD5", key, re.I):
        ciphers[key] = "3, MD5 MAC"

    if re.search("anon", key, re.I):
        ciphers[key] = "6, Anonymous"
    if re.search("export", key, re.I):
        ciphers[key] = "6, EXPORT cipher"
    if re.search("ssl2", key, re.I):
        ciphers[key] = "6, SSLv2"
    if re.search("null", key, re.I):
        ciphers[key] = "6, NULL cipher"
    if re.search("des", key, re.I):
        ciphers[key] = "6, DES cipher"

#print(type(ciphers))
#print(ciphers)

for key in ciphers:
#    print(key, end=" ")
#    print(ciphers[key])
    print(key.strip(), "     ", ciphers[key])
    print()
