#!/usr/bin/python3

# Takes a socket file (IP address and port, space delimited) as argv[1] and a
# directory containing Nmap scan .txt files as argv[2] and scores each target
# based on TLS version, key exchange, authentication, cipher support, MAC used
# etc. Output is to stdout, and is a comma-separated list of IP address,
# socket, score, and flaws found that contribute to the score.

import sys
import re
import os.path

socketsFile = sys.argv[1]
resultsFolder = sys.argv[2]

sockets = []

with open(socketsFile) as f:
    for line in f:
        sockets.append(line.split())

for i in sockets:
    dhFile = resultsFolder+"/"+i[0]+"-"+i[1]+"-"+"dh-params.txt"
    hbFile = resultsFolder+"/"+i[0]+"-"+i[1]+"-"+"heartbleed.txt"
    sslv2File = resultsFolder+"/"+i[0]+"-"+i[1]+"-"+"sslv2.txt"
    resultsFile = resultsFolder+"/"+i[0]+"-"+i[1]+".txt"

#    print(dhFile)
#    print(hbFile)
#    print(sslv2File)
#    print(resultsFile)
#    print()

#    if not os.path.exists(dhFile):
#        print(dhFile)
#    if not os.path.exists(hbFile):
#        print(hbFile)
#    if not os.path.exists(sslv2File):
#        print(sslv2File)
#    if not os.path.exists(resultsFile):
#        print(resultsFile)

    score = 1
    reasons = ""

# Check for weak DH key negotiation
    with open(dhFile) as f:
        dhString = f.read().replace('\n', ' ')
        if re.search("State: VULNERABLE", dhString):
            score = max (score, 3)
            reasons = reasons + "Weak DH;"

# Check for HeartBleed vulnerability
    with open(hbFile) as f:
        hbString = f.read().replace('\n', ' ')
        if re.search("State: VULNERABLE", hbString):
            score = max (score, 6)
            reasons = reasons + "Heartbleed;"

# Check for SSLv2 support
    with open(sslv2File) as f:
        sslv2String = f.read().replace('\n', ' ')
        if re.search("SSLv2 supported", sslv2String):
            score = max (score, 6)
            reasons = reasons + "SSLv2;"

    with open(resultsFile) as f:
        resultsString = f.read().replace('\n', ' ')
#        print(resultsString)
# Filtered - target didn't respond, score as 100
#        if re.search("filtered", resultsString):
#            score = max (score, 100)
#            reasons = reasons + "Filtered - host did not respond to probing attempt"
# Open - target didn't respond as expected, score as 100
#        if re.search("tcp open ", resultsString):
#            score = max (score, 100)
# ssl-enum-ciphers script didn't return results - not scanned?
        if not re.search("ssl-enum-ciphers:", resultsString):
            score = max (score, 100)
            reasons = reasons + "No result from ssl-enum-ciphers script logged"
# Protocol Support
        if re.search("SSLv3:", resultsString):
            score = max (score, 6)
            reasons = reasons + "SSLv3;"
        if re.search("TLSv1.0:", resultsString):
            score = max (score, 3)
            reasons = reasons + "TLSv1.0;"
        if re.search("TLSv1.1:", resultsString):
            score = max (score, 3)
            reasons = reasons + "TLSv1.1;"
# Compression Support
        if re.search("DEFLATE", resultsString):
            score = max (score, 3)
            reasons = reasons + "Compression;"
# Key Exchange
        if re.search("TLS_RSA_", resultsString):
            score = max (score, 2)
            reasons = reasons + "RSA doesn't offer PFS;"
        if re.search("TLS_ECDH_RSA_", resultsString):
            score = max (score, 2)
            reasons = reasons + "ECDH_RSA doesn't offer PFS;"
        if re.search("TLS_ECDH_ECDSA_", resultsString):
            score = max (score, 2)
            reasons = reasons + "ECDH_ECDSA doesn't offer PFS;"
        if re.search("_PSK", resultsString):
            score = max (score, 3)
            reasons = reasons + "PSK doesn't offer PFS and susceptible to brute force;"
# Authentication
        if re.search("DH_anon", resultsString):
            score = max (score, 6)
            reasons = reasons + "Anon authentication;"
        if re.search("TLS_NULL_", resultsString):
            score = max (score, 6)
            reasons = reasons + "NULL authentication;"
# Ciphers
        if re.search("_CBC_", resultsString):
            score = max (score, 2)
            reasons = reasons + "CBC mode;"
        if re.search("SEED", resultsString):
            score = max (score, 2)
            reasons = reasons + "SEED cipher;"
        if re.search("CAMELLIA", resultsString):
            score = max (score, 2)
            reasons = reasons + "CAMELLIA cipher;"
        if re.search("IDEA", resultsString):
            score = max (score, 2)
            reasons = reasons + "IDEA cipher;"
        if re.search("ARIA", resultsString):
            score = max (score, 2)
            reasons = reasons + "ARIA cipher;"
        if re.search("RC2", resultsString):
            score = max (score, 2)
            reasons = reasons + "RC2 cipher;"
        if re.search("RC4", resultsString):
            score = max (score, 3)
            reasons = reasons + "RC4 cipher;"
        if re.search("_WITH_NULL_", resultsString):
            score = max (score, 6)
            reasons = reasons + "NULL cipher;"
        if re.search("EXPORT", resultsString):
            score = max (score, 6)
            reasons = reasons + "EXPORT cipher;"
        if re.search("_WITH_DES", resultsString):
            score = max (score, 6)
            reasons = reasons + "DES cipher;"
        if re.search("_WITH_3DES_", resultsString):
            score = max (score, 6)
            reasons = reasons + "3DES cipher;"
# MAC
        if re.search("MD5", resultsString):
            score = max (score, 3)
            reasons = reasons + "MD5 MAC;"
# Other checks
#
# Client cipher preference
        if re.search("cipher preference: client", resultsString):
            score = max (score, 2)
            reasons = reasons + "Client cipher prefer;"
        if re.search("cipher preference: indeterminate", resultsString):
            score = max (score, 2)
            reasons = reasons + "Indeterminate cipher prefer;"

# Good things, that get recorded but don't downgrade the score
        if re.search("TLS_AKE", resultsString):
            reasons = reasons + "**TLS_AKE**;"
        if re.search("DHE", resultsString):
            reasons = reasons + "**DHE**;"
        if re.search("AES", resultsString):
            reasons = reasons + "**AES**;"
        if re.search("CHACHA20_POLY1305", resultsString):
            reasons = reasons + "**CHACHA20_POLY1305**;"
        if re.search("TLSv1.2", resultsString):
            reasons = reasons + "**TLSv1.2**;"
        if re.search("TLSv1.3", resultsString):
            reasons = reasons + "**TLSv1.3**;"

# If score < 10 (ie, there is data for that particular target and Nmap didn't return "filtered") then print the result for this record
#    if score < 10:
#        print(i[0] + "," + i[1] + "," + str(score) + "," + reasons)
    print(i[0] + "," + i[1] + "," + str(score) + "," + reasons)
