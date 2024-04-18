#!/usr/bin/python3

# Takes a socket file (IP address and port, space delimited) as argv[1] and a
# directory containing Nmap scan .txt files as argv[2] and compares how the
# HTTPS services are configured on non-standard ports vs TCP/443. Output is
# to stdout.

import sys
import re
import os.path

socketsFile = sys.argv[1]
resultsFolder = sys.argv[2]

sockets = []

filtered = 0
TotalCount = 0

SSLv2On443 = 0
SSLv2OnOther = 0
SSLv2On443Only = 0
SSLv2OnOtherOnly = 0
SSLv2OnBoth = 0
SSLv2OnNeither = 0

SSLv3On443 = 0
SSLv3OnOther = 0
SSLv3On443Only = 0
SSLv3OnOtherOnly = 0
SSLv3OnBoth = 0
SSLv3OnNeither = 0

TLSv10On443 = 0
TLSv10OnOther = 0
TLSv10On443Only = 0
TLSv10OnOtherOnly = 0
TLSv10OnBoth = 0
TLSv10OnNeither = 0

TLSv11On443 = 0
TLSv11OnOther = 0
TLSv11On443Only = 0
TLSv11OnOtherOnly = 0
TLSv11OnBoth = 0
TLSv11OnNeither = 0

TLSv12On443 = 0
TLSv12OnOther = 0
TLSv12On443Only = 0
TLSv12OnOtherOnly = 0
TLSv12OnBoth = 0
TLSv12OnNeither = 0

TLSv13On443 = 0
TLSv13OnOther = 0
TLSv13On443Only = 0
TLSv13OnOtherOnly = 0
TLSv13OnBoth = 0
TLSv13OnNeither = 0

EXPORTOn443 = 0
EXPORTOnOther = 0
EXPORTOn443Only = 0
EXPORTOnOtherOnly = 0
EXPORTOnBoth = 0
EXPORTOnNeither = 0

DESOn443 = 0
DESOnOther = 0
DESOn443Only = 0
DESOnOtherOnly = 0
DESOnBoth = 0
DESOnNeither = 0

TripleDESOn443 = 0
TripleDESOnOther = 0
TripleDESOn443Only = 0
TripleDESOnOtherOnly = 0
TripleDESOnBoth = 0
TripleDESOnNeither = 0

MD5On443 = 0
MD5OnOther = 0
MD5On443Only = 0
MD5OnOtherOnly = 0
MD5OnBoth = 0
MD5OnNeither = 0

CompressionOn443 = 0
CompressionOnOther = 0
CompressionOn443Only = 0
CompressionOnOtherOnly = 0
CompressionOnBoth = 0
CompressionOnNeither = 0

HbOn443 = 0
HbOnOther = 0
HbOn443Only = 0
HbOnOtherOnly = 0
HbOnBoth = 0
HbOnNeither = 0

with open(socketsFile) as f:
    for line in f:
        sockets.append(line.split())

for i in sockets:
#    dhFile = resultsFolder+"/"+i[0]+"-"+i[1]+"-"+"dh-params.txt"
#    hbFile = resultsFolder+"/"+i[0]+"-"+i[1]+"-"+"heartbleed.txt"
#    sslv2File = resultsFolder+"/"+i[0]+"-"+i[1]+"-"+"sslv2.txt"
#    resultsFile = resultsFolder+"/"+i[0]+"-"+i[1]+".txt"

    if i[1] != "443":
#    if i[1] == "7443":
#        print(i[1])
        dhFile = resultsFolder+"/"+i[0]+"-"+i[1]+"-"+"dh-params.txt"
        hbFile = resultsFolder+"/"+i[0]+"-"+i[1]+"-"+"heartbleed.txt"
        sslv2File = resultsFolder+"/"+i[0]+"-"+i[1]+"-"+"sslv2.txt"
        resultsFile = resultsFolder+"/"+i[0]+"-"+i[1]+".txt"
        dhFile443 = resultsFolder+"/"+i[0]+"-443-dh-params.txt"
        hbFile443 = resultsFolder+"/"+i[0]+"-443-heartbleed.txt"
        sslv2File443 = resultsFolder+"/"+i[0]+"-443-sslv2.txt"
        resultsFile443 = resultsFolder+"/"+i[0]+"-443.txt"

#        print(dhFile)
#        print(hbFile)
#        print(sslv2File)
#        print(resultsFile)
#        print(dhFile443)
#        print(hbFile443)
#        print(sslv2File443)
#        print(resultsFile443)
#        print()

#        if not os.path.exists(dhFile):
#            print(dhFile)
#        if not os.path.exists(hbFile):
#            print(hbFile)
#        if not os.path.exists(sslv2File):
#            print(sslv2File)
#        if not os.path.exists(resultsFile):
#            print(resultsFile)
#        if not os.path.exists(dhFile443):
#            print(dhFile443)
#        if not os.path.exists(hbFile443):
#            print(hbFile443)
#        if not os.path.exists(sslv2File443):
#            print(sslv2File443)
#        if not os.path.exists(resultsFile443):
#            print(resultsFile443)

#Check for SSLv2 support
        with open(sslv2File) as f:
            sslv2String = f.read().replace('\n', ' ')
        with open(sslv2File443) as g:
            sslv2String443 = g.read().replace('\n', ' ')
        if re.search("SSLv2 supported", sslv2String):
            SSLv2OnOther = SSLv2OnOther + 1
        if re.search("SSLv2 supported", sslv2String443):
            SSLv2On443 = SSLv2On443 + 1
        if re.search("SSLv2 supported", sslv2String443) and not re.search("SSLv2 supported", sslv2String):
            SSLv2On443Only = SSLv2On443Only + 1
        if re.search("SSLv2 supported", sslv2String) and not re.search("SSLv2 supported", sslv2String443):
            SSLv2OnOtherOnly = SSLv2OnOtherOnly + 1
        if re.search("SSLv2 supported", sslv2String443) and re.search("SSLv2 supported", sslv2String):
            SSLv2OnBoth = SSLv2OnBoth + 1
        if not re.search("SSLv2 supported", sslv2String443) and not re.search("SSLv2 supported", sslv2String):
            SSLv2OnNeither = SSLv2OnNeither + 1

        with open(resultsFile) as f:
            resultsString = f.read().replace('\n', ' ')
        with open(resultsFile443) as g:
            resultsString443 = g.read().replace('\n', ' ')



        if not re.search("ssl-enum-ciphers:", resultsString) and not re.search("ssl-enum-ciphers:", resultsString443):
#            print(resultsFile)
#            print(resultsFile443)
#            print()
#            print()
            filtered = filtered + 1
            continue

        TotalCount = TotalCount + 1

#Check for SSLv3 support
        if re.search("SSLv3:", resultsString):
            SSLv3OnOther = SSLv3OnOther + 1
        if re.search("SSLv3:", resultsString443):
            SSLv3On443 = SSLv3On443 + 1
        if re.search("SSLv3:", resultsString443) and not re.search("SSLv3:", resultsString):
            SSLv3On443Only = SSLv3On443Only + 1
        if re.search("SSLv3:", resultsString) and not re.search("SSLv3:", resultsString443):
            SSLv3OnOtherOnly = SSLv3OnOtherOnly + 1
        if re.search("SSLv3:", resultsString443) and re.search("SSLv3:", resultsString):
            SSLv3OnBoth = SSLv3OnBoth + 1
        if not re.search("SSLv3:", resultsString443) and not re.search("SSLv3:", resultsString):
            SSLv3OnNeither = SSLv3OnNeither + 1

#Check for TLSv1.0 support
        if re.search("TLSv1\.0:", resultsString):
            TLSv10OnOther = TLSv10OnOther + 1
        if re.search("TLSv1\.0:", resultsString443):
            TLSv10On443 = TLSv10On443 + 1
        if re.search("TLSv1\.0:", resultsString443) and not re.search("TLSv1\.0:", resultsString):
            TLSv10On443Only = TLSv10On443Only + 1
        if re.search("TLSv1\.0:", resultsString) and not re.search("TLSv1\.0:", resultsString443):
            TLSv10OnOtherOnly = TLSv10OnOtherOnly + 1
        if re.search("TLSv1\.0:", resultsString443) and re.search("TLSv1\.0:", resultsString):
            TLSv10OnBoth = TLSv10OnBoth + 1
        if not re.search("TLSv1\.0:", resultsString443) and not re.search("TLSv1\.0:", resultsString):
            TLSv10OnNeither = TLSv10OnNeither + 1

#Check for TLSv1.1 support
        if re.search("TLSv1\.1:", resultsString):
            TLSv11OnOther = TLSv11OnOther + 1
        if re.search("TLSv1\.1:", resultsString443):
            TLSv11On443 = TLSv11On443 + 1
        if re.search("TLSv1\.1:", resultsString443) and not re.search("TLSv1\.1:", resultsString):
            TLSv11On443Only = TLSv11On443Only + 1
        if re.search("TLSv1\.1:", resultsString) and not re.search("TLSv1\.1:", resultsString443):
            TLSv11OnOtherOnly = TLSv11OnOtherOnly + 1
        if re.search("TLSv1\.1:", resultsString443) and re.search("TLSv1\.1:", resultsString):
            TLSv11OnBoth = TLSv11OnBoth + 1
        if not re.search("TLSv1\.1:", resultsString443) and not re.search("TLSv1\.1:", resultsString):
            TLSv11OnNeither = TLSv11OnNeither + 1

#Check for TLSv1.2 support
        if re.search("TLSv1\.2:", resultsString):
            TLSv12OnOther = TLSv12OnOther + 1
        if re.search("TLSv1\.2:", resultsString443):
            TLSv12On443 = TLSv12On443 + 1
        if re.search("TLSv1\.2:", resultsString443) and not re.search("TLSv1\.2:", resultsString):
            TLSv12On443Only = TLSv12On443Only + 1
        if re.search("TLSv1\.2:", resultsString) and not re.search("TLSv1\.2:", resultsString443):
            TLSv12OnOtherOnly = TLSv12OnOtherOnly + 1
        if re.search("TLSv1\.2:", resultsString443) and re.search("TLSv1\.2:", resultsString):
            TLSv12OnBoth = TLSv12OnBoth + 1
        if not re.search("TLSv1\.2:", resultsString443) and not re.search("TLSv1\.2:", resultsString):
            TLSv12OnNeither = TLSv12OnNeither + 1

#Check for TLSv1.3 support
        if re.search("TLSv1\.3:", resultsString):
            TLSv13OnOther = TLSv13OnOther + 1
        if re.search("TLSv1\.3:", resultsString443):
            TLSv13On443 = TLSv13On443 + 1
        if re.search("TLSv1\.3:", resultsString443) and not re.search("TLSv1\.3:", resultsString):
            TLSv13On443Only = TLSv13On443Only + 1
        if re.search("TLSv1\.3:", resultsString) and not re.search("TLSv1\.3:", resultsString443):
            TLSv13OnOtherOnly = TLSv13OnOtherOnly + 1
        if re.search("TLSv1\.3:", resultsString443) and re.search("TLSv1\.3:", resultsString):
            TLSv13OnBoth = TLSv13OnBoth + 1
        if not re.search("TLSv1\.3:", resultsString443) and not re.search("TLSv1\.3:", resultsString):
            TLSv13OnNeither = TLSv13OnNeither + 1

#Check for EXPORT cipher support
        if re.search("EXPORT", resultsString):
            EXPORTOnOther = EXPORTOnOther + 1
        if re.search("EXPORT", resultsString443):
            EXPORTOn443 = EXPORTOn443 + 1
        if re.search("EXPORT", resultsString443) and not re.search("EXPORT", resultsString):
            EXPORTOn443Only = EXPORTOn443Only + 1
        if re.search("EXPORT", resultsString) and not re.search("EXPORT", resultsString443):
            EXPORTOnOtherOnly = EXPORTOnOtherOnly + 1
        if re.search("EXPORT", resultsString443) and re.search("EXPORT", resultsString):
            EXPORTOnBoth = EXPORTOnBoth + 1
        if not re.search("EXPORT", resultsString443) and not re.search("EXPORT", resultsString):
            EXPORTOnNeither = EXPORTOnNeither + 1

#Check for DES cipher support
        if re.search("_WITH_DES", resultsString):
            DESOnOther = DESOnOther + 1
        if re.search("_WITH_DES", resultsString443):
            DESOn443 = DESOn443 + 1
        if re.search("_WITH_DES", resultsString443) and not re.search("_WITH_DES", resultsString):
            DESOn443Only = DESOn443Only + 1
        if re.search("_WITH_DES", resultsString) and not re.search("_WITH_DES", resultsString443):
            DESOnOtherOnly = DESOnOtherOnly + 1
        if re.search("_WITH_DES", resultsString443) and re.search("_WITH_DES", resultsString):
            DESOnBoth = DESOnBoth + 1
        if not re.search("_WITH_DES", resultsString443) and not re.search("_WITH_DES", resultsString):
            DESOnNeither = DESOnNeither + 1

#Check for 3DES cipher support
        if re.search("_WITH_3DES_", resultsString):
            TripleDESOnOther = TripleDESOnOther + 1
        if re.search("_WITH_3DES_", resultsString443):
            TripleDESOn443 = TripleDESOn443 + 1
        if re.search("_WITH_3DES_", resultsString443) and not re.search("_WITH_3DES_", resultsString):
            TripleDESOn443Only = TripleDESOn443Only + 1
        if re.search("_WITH_3DES_", resultsString) and not re.search("_WITH_3DES_", resultsString443):
            TripleDESOnOtherOnly = TripleDESOnOtherOnly + 1
        if re.search("_WITH_3DES_", resultsString443) and re.search("_WITH_3DES_", resultsString):
            TripleDESOnBoth = TripleDESOnBoth + 1
        if not re.search("_WITH_3DES_", resultsString443) and not re.search("_WITH_3DES_", resultsString):
            TripleDESOnNeither = TripleDESOnNeither + 1

#Check for MD5 MAC support
        if re.search("MD5", resultsString):
            MD5OnOther = MD5OnOther + 1
        if re.search("MD5", resultsString443):
            MD5On443 = MD5On443 + 1
        if re.search("MD5", resultsString443) and not re.search("MD5", resultsString):
            MD5On443Only = MD5On443Only + 1
        if re.search("MD5", resultsString) and not re.search("MD5", resultsString443):
            MD5OnOtherOnly = MD5OnOtherOnly + 1
        if re.search("MD5", resultsString443) and re.search("MD5", resultsString):
            MD5OnBoth = MD5OnBoth + 1
        if not re.search("MD5", resultsString443) and not re.search("MD5", resultsString):
            MD5OnNeither = MD5OnNeither + 1

#Check for Compression support
        if re.search("DEFLATE", resultsString):
            CompressionOnOther = CompressionOnOther + 1
        if re.search("DEFLATE", resultsString443):
            CompressionOn443 = CompressionOn443 + 1
        if re.search("DEFLATE", resultsString443) and not re.search("DEFLATE", resultsString):
            CompressionOn443Only = CompressionOn443Only + 1
        if re.search("DEFLATE", resultsString) and not re.search("DEFLATE", resultsString443):
            CompressionOnOtherOnly = CompressionOnOtherOnly + 1
        if re.search("DEFLATE", resultsString443) and re.search("DEFLATE", resultsString):
            CompressionOnBoth = CompressionOnBoth + 1
        if not re.search("DEFLATE", resultsString443) and not re.search("DEFLATE", resultsString):
            CompressionOnNeither = CompressionOnNeither + 1



# Check for HeartBleed vulnerability
        with open(hbFile) as f:
            hbString = f.read().replace('\n', ' ')
        with open(hbFile443) as g:
            hbString443 = g.read().replace('\n', ' ')
        if re.search("State: VULNERABLE", hbString):
            HbOnOther = HbOnOther + 1
        if re.search("State: VULNERABLE", hbString443):
            HbOn443 = HbOn443 + 1
        if re.search("State: VULNERABLE", hbString443) and not re.search("State: VULNERABLE", hbString):
            HbOn443Only = HbOn443Only + 1
        if re.search("State: VULNERABLE", hbString) and not re.search("State: VULNERABLE", hbString443):
            HbOnOtherOnly = HbOnOtherOnly + 1
        if re.search("State: VULNERABLE", hbString443) and re.search("State: VULNERABLE", hbString):
            HbOnBoth = HbOnBoth + 1
        if not re.search("State: VULNERABLE", hbString443) and not re.search("State: VULNERABLE", hbString):
            HbOnNeither = HbOnNeither + 1

# Check for weak DH key negotiation
#    with open(dhFile) as f:
#        dhString = f.read().replace('\n', ' ')
#        if re.search("State: VULNERABLE", dhString):
#            score = max (score, 3)
#            reasons = reasons + "Weak DH;"

##    with open(resultsFile) as f:
##        resultsString = f.read().replace('\n', ' ')
#        print(resultsString)
# Filtered - target didn't respond, score as 100
#        if re.search("filtered", resultsString):
#            score = max (score, 100)
#            reasons = reasons + "Filtered - host did not respond to probing attempt"
# Open - target didn't respond as expected, score as 100
#        if re.search("tcp open ", resultsString):
#            score = max (score, 100)
# ssl-enum-ciphers script didn't return results - not scanned?
##        if not re.search("ssl-enum-ciphers:", resultsString):
##            score = max (score, 100)
##            reasons = reasons + "No result from ssl-enum-ciphers script logged"
# Protocol Support
##        if re.search("SSLv3:", resultsString):
##            score = max (score, 6)
##            reasons = reasons + "SSLv3;"
##        if re.search("TLSv1.0:", resultsString):
##            score = max (score, 3)
##            reasons = reasons + "TLSv1.0;"
##        if re.search("TLSv1.1:", resultsString):
##            score = max (score, 3)
##            reasons = reasons + "TLSv1.1;"
# Compression Support
##        if re.search("DEFLATE", resultsString):
##            score = max (score, 3)
##            reasons = reasons + "Compression;"
# Key Exchange
##        if re.search("TLS_RSA_", resultsString):
##            score = max (score, 2)
##            reasons = reasons + "RSA doesn't offer PFS;"
##        if re.search("TLS_ECDH_RSA_", resultsString):
##            score = max (score, 2)
##            reasons = reasons + "ECDH_RSA doesn't offer PFS;"
##        if re.search("TLS_ECDH_ECDSA_", resultsString):
##            score = max (score, 2)
##            reasons = reasons + "ECDH_ECDSA doesn't offer PFS;"
##        if re.search("_PSK", resultsString):
##            score = max (score, 3)
##            reasons = reasons + "PSK doesn't offer PFS and susceptible to brute force;"
# Authentication
##        if re.search("DH_anon", resultsString):
##            score = max (score, 6)
##            reasons = reasons + "Anon authentication;"
##        if re.search("TLS_NULL_", resultsString):
##            score = max (score, 6)
##            reasons = reasons + "NULL authentication;"
# Ciphers

# If score < 10 (ie, there is data for that particular target and Nmap didn't return "filtered") then print the result for this record
#    if score < 10:
#        print(i[0] + "," + i[1] + "," + str(score) + "," + reasons)
##    print(i[0] + "," + i[1] + "," + str(score) + "," + reasons)

print("SSLv2On443: " + str(SSLv2On443))
print("SSLv2OnOther: " + str(SSLv2OnOther))
print("SSLv2On443Only: " + str(SSLv2On443Only))
print("SSLv2OnOtherOnly: " + str(SSLv2OnOtherOnly))
print("SSLv2OnBoth: " + str(SSLv2OnBoth))
print("SSLv2OnNeither: " + str(SSLv2OnNeither))
print()

print("SSLv3On443: " + str(SSLv3On443))
print("SSLv3OnOther: " + str(SSLv3OnOther))
print("SSLv3On443Only: " + str(SSLv3On443Only))
print("SSLv3OnOtherOnly: " + str(SSLv3OnOtherOnly))
print("SSLv3OnBoth: " + str(SSLv3OnBoth))
print("SSLv3OnNeither: " + str(SSLv3OnNeither))
print()

print("TLSv10On443: " + str(TLSv10On443))
print("TLSv10OnOther: " + str(TLSv10OnOther))
print("TLSv10On443Only: " + str(TLSv10On443Only))
print("TLSv10OnOtherOnly: " + str(TLSv10OnOtherOnly))
print("TLSv10OnBoth: " + str(TLSv10OnBoth))
print("TLSv10OnNeither: " + str(TLSv10OnNeither))
print()

print("TLSv11On443: " + str(TLSv11On443))
print("TLSv11OnOther: " + str(TLSv11OnOther))
print("TLSv11On443Only: " + str(TLSv11On443Only))
print("TLSv11OnOtherOnly: " + str(TLSv11OnOtherOnly))
print("TLSv11OnBoth: " + str(TLSv11OnBoth))
print("TLSv11OnNeither: " + str(TLSv11OnNeither))
print()

print("TLSv12On443: " + str(TLSv12On443))
print("TLSv12OnOther: " + str(TLSv12OnOther))
print("TLSv12On443Only: " + str(TLSv12On443Only))
print("TLSv12OnOtherOnly: " + str(TLSv12OnOtherOnly))
print("TLSv12OnBoth: " + str(TLSv12OnBoth))
print("TLSv12OnNeither: " + str(TLSv12OnNeither))
print()

print("TLSv13On443: " + str(TLSv13On443))
print("TLSv13OnOther: " + str(TLSv13OnOther))
print("TLSv13On443Only: " + str(TLSv13On443Only))
print("TLSv13OnOtherOnly: " + str(TLSv13OnOtherOnly))
print("TLSv13OnBoth: " + str(TLSv13OnBoth))
print("TLSv13OnNeither: " + str(TLSv13OnNeither))
print()

print("EXPORTOn443: " + str(EXPORTOn443))
print("EXPORTOnOther: " + str(EXPORTOnOther))
print("EXPORTOn443Only: " + str(EXPORTOn443Only))
print("EXPORTOnOtherOnly: " + str(EXPORTOnOtherOnly))
print("EXPORTOnBoth: " + str(EXPORTOnBoth))
print("EXPORTOnNeither: " + str(EXPORTOnNeither))
print()

print("DESOn443: " + str(DESOn443))
print("DESOnOther: " + str(DESOnOther))
print("DESOn443Only: " + str(DESOn443Only))
print("DESOnOtherOnly: " + str(DESOnOtherOnly))
print("DESOnBoth: " + str(DESOnBoth))
print("DESOnNeither: " + str(DESOnNeither))
print()

print("TripleDESOn443: " + str(TripleDESOn443))
print("TripleDESOnOther: " + str(TripleDESOnOther))
print("TripleDESOn443Only: " + str(TripleDESOn443Only))
print("TripleDESOnOtherOnly: " + str(TripleDESOnOtherOnly))
print("TripleDESOnBoth: " + str(TripleDESOnBoth))
print("TripleDESOnNeither: " + str(TripleDESOnNeither))
print()

print("MD5On443: " + str(MD5On443))
print("MD5OnOther: " + str(MD5OnOther))
print("MD5On443Only: " + str(MD5On443Only))
print("MD5OnOtherOnly: " + str(MD5OnOtherOnly))
print("MD5OnBoth: " + str(MD5OnBoth))
print("MD5OnNeither: " + str(MD5OnNeither))
print()

print("CompressionOn443: " + str(CompressionOn443))
print("CompressionOnOther: " + str(CompressionOnOther))
print("CompressionOn443Only: " + str(CompressionOn443Only))
print("CompressionOnOtherOnly: " + str(CompressionOnOtherOnly))
print("CompressionOnBoth: " + str(CompressionOnBoth))
print("CompressionOnNeither: " + str(CompressionOnNeither))
print()

print("HbOn443: " + str(HbOn443))
print("HbOnOther: " + str(HbOnOther))
print("HbOn443Only: " + str(HbOn443Only))
print("HbOnOtherOnly: " + str(HbOnOtherOnly))
print("HbOnBoth: " + str(HbOnBoth))
print("HbOnNeither: " + str(HbOnNeither))
print()

print("Filtered: " + str(filtered))
print("Total Count: " + str(TotalCount))
