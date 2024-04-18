#!/usr/bin/python3

# Takes a socket file (IP address and port, space delimited) as argv[1] and a
# directory containing Nmap scan .txt files as argv[2] and finds 512-bit DH
# keys. Output is to stdout

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

#        print(dhFile)
#        print()

#        if not os.path.exists(dhFile):
#            print(dhFile)

# Check for weak DH key negotiation
    with open(dhFile) as f:
        dhString = f.read().replace('\n', ' ')
        if re.search("Public Key Length: 512", dhString):
            print(i)
