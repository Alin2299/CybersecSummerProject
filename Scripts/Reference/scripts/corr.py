#!/usr/bin/python3

# Takes two result files (TCP/443 as argv[1], non-standard as argv[2]),
# Producs a Pandas dataframe of various aspects (SSL/TLS prevalence, for example),
# then performs a pairwise correlation between the columns.

import sys
import re
import os.path
import numpy as np
import pandas as pd
import csv
from scipy import stats

stdFile = sys.argv[1]
nonStdFile = sys.argv[2]

with open(stdFile) as f:
    r = csv.reader(f)
    stdData = list(r)
#    for data in r:
#        print(data)
#        sockets.append [data]
#print(type(stdData))
#print(stdData)

with open(nonStdFile) as g:
    s = csv.reader(g)
    nonStdData = list(s)

#print(type(nonStdData))
#print(nonStdData)

stdCorr = []

for i in stdData:
#    print(i)
#    print(type(i))
#    print(i[0])
#    print(type(i[0]))
    line = []
# #1: IP address
    line.append(i[0])
# #2: Port
    line.append(i[1])
# #3: SSLv2 support
    if re.search("SSLv2", i[3]):
        line.append(1)
    else:
        line.append(0)
# #4: SSLv3 support
    if re.search("SSLv3", i[3]):
        line.append(1)
    else:
        line.append(0)
# #5: TLSv1.0 support
    if re.search("TLSv1\.0", i[3]):
        line.append(1)
    else:
        line.append(0)
# #6: TLSv1.1 support
    if re.search("TLSv1\.1", i[3]):
        line.append(1)
    else:
        line.append(0)
# #7: TLSv1.2 support
    if re.search("\*\*TLSv1\.2\*\*", i[3]):
        line.append(1)
    else:
        line.append(0)
# #8: iTLSv1.3 support
    if re.search("\*\*TLSv1\.3\*\*", i[3]):
        line.append(1)
    else:
        line.append(0)
# #9: CBC mode support
    if re.search("CBC mode", i[3]):
        line.append(1)
    else:
        line.append(0)
# #10: ARIA cipher support
    if re.search("ARIA cipher", i[3]):
        line.append(1)
    else:
        line.append(0)
# #11: CAMELLIA cipher support
    if re.search("CAMELLIA cipher", i[3]):
        line.append(1)
    else:
        line.append(0)
# #12: Weak DH
    if re.search("Weak DH", i[3]):
        line.append(1)
    else:
        line.append(0)
# #13: Heartbleed
    if re.search("Heartbleed", i[3]):
        line.append(1)
    else:
        line.append(0)
# #14: EXPORT cipher
    if re.search("EXPORT cipher", i[3]):
        line.append(1)
    else:
        line.append(0)
# #15: DES cipher
    if re.search("[,;]DES cipher", i[3]):
        line.append(1)
    else:
        line.append(0)
# #16: 3DES cipher
    if re.search("3DES cipher", i[3]):
        line.append(1)
    else:
        line.append(0)
# #17: RC4 cipher
    if re.search("RC4 cipher", i[3]):
        line.append(1)
    else:
        line.append(0)
# #18: MD5 MAC
    if re.search("MD5 MAC", i[3]):
        line.append(1)
    else:
        line.append(0)
# #19: Compression support
    if re.search("Compression", i[3]):
        line.append(1)
#        line.append(22)
#        line.append(176)
    else:
        line.append(0)
#        line.append(74)
#        line.append(1032)
# #20: Test control line, 1
#    line.append(1)
# #21: Test control line, 1
#    line.append(0)


    stdCorr.append(line)

nonStdCorr = []

for i in nonStdData:
    line = []
# #1: IP address
    line.append(i[0])
# #2: Port
    line.append(i[1])
# #3: SSLv2 support
    if re.search("SSLv2", i[3]):
        line.append(1)
    else:
        line.append(0)
# #4: SSLv3 support
    if re.search("SSLv3", i[3]):
        line.append(1)
    else:
        line.append(0)
# #5: TLSv1.0 support
    if re.search("TLSv1\.0", i[3]):
        line.append(1)
    else:
        line.append(0)
# #6: TLSv1.1 support
    if re.search("TLSv1\.1", i[3]):
        line.append(1)
    else:
        line.append(0)
# #7: TLSv1.2 support
    if re.search("\*\*TLSv1\.2\*\*", i[3]):
        line.append(1)
    else:
        line.append(0)
# #8: iTLSv1.3 support
    if re.search("\*\*TLSv1\.3\*\*", i[3]):
        line.append(1)
    else:
        line.append(0)
# #9: CBC mode support
    if re.search("CBC mode", i[3]):
        line.append(1)
    else:
        line.append(0)
# #10: ARIA cipher support
    if re.search("ARIA cipher", i[3]):
        line.append(1)
    else:
        line.append(0)
# #11: CAMELLIA cipher support
    if re.search("CAMELLIA cipher", i[3]):
        line.append(1)
    else:
        line.append(0)
# #12: Weak DH
    if re.search("Weak DH", i[3]):
        line.append(1)
    else:
        line.append(0)
# #13: Heartbleed
    if re.search("Heartbleed", i[3]):
        line.append(1)
    else:
        line.append(0)
# #14: EXPORT cipher
    if re.search("EXPORT cipher", i[3]):
        line.append(1)
    else:
        line.append(0)
# #15: DES cipher
    if re.search("[,;]DES cipher", i[3]):
        line.append(1)
    else:
        line.append(0)
# #16: 3DES cipher
    if re.search("3DES cipher", i[3]):
        line.append(1)
    else:
        line.append(0)
# #17: RC4 cipher
    if re.search("RC4 cipher", i[3]):
        line.append(1)
    else:
        line.append(0)
# #18: MD5 MAC
    if re.search("MD5 MAC", i[3]):
        line.append(1)
    else:
        line.append(0)
# #19: Compression support
    if re.search("Compression", i[3]):
        line.append(1)
#        line.append(22)
#        line.append(176)
    else:
        line.append(0)
#        line.append(74)
#        line.append(1033)
# #20: Test control line, 1
#    line.append(1)
# #21: Test control line, 1
#    line.append(0)

    nonStdCorr.append(line)

#    print(type(line))
#    print(line)
#    print()
#print(stdCorr)
print(type(stdCorr))
print(len(stdCorr))
print()
#print(nonStdCorr)
print(type(nonStdCorr))
print(len(nonStdCorr))
print()

stdCorrFrame = pd.DataFrame(stdCorr, columns = ['IP address', 'Port', 'SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3', 'CBC', 'ARIA', 'CAMELLIA', 'Weak DH', 'Heartbleed', 'EXPORT', 'DES', '3DES', 'RC4', 'MD5', 'Compression'])
#with pd.option_context('display.max_rows', None):
#    print(stdCorrFrame)
print(stdCorrFrame)
print(type(stdCorrFrame))

nonStdCorrFrame = pd.DataFrame(nonStdCorr, columns = ['IP address', 'Port', 'SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3', 'CBC', 'ARIA', 'CAMELLIA', 'Weak DH', 'Heartbleed', 'EXPORT', 'DES', '3DES', 'RC4', 'MD5', 'Compression'])
#with pd.option_context('display.max_rows', None):
#    print(nonStdCorrFrame)
print(nonStdCorrFrame)
print(type(nonStdCorrFrame))

print(stdCorrFrame.corrwith(nonStdCorrFrame))
print()

print(stdCorrFrame['SSLv2'].corr(nonStdCorrFrame['SSLv2']))
print(stdCorrFrame['SSLv3'].corr(nonStdCorrFrame['SSLv3']))
#print(stdCorrFrame['Ctrl1'].corr(nonStdCorrFrame['Ctrl1']))
#print(stdCorrFrame['Ctrl0'].corr(nonStdCorrFrame['Ctrl0']))
print()

#print(stdCorrFrame.corr())
#print()

#print(nonStdCorrFrame.corr())
#print()

#print(stdCorrFrame.corrwith(nonStdCorrFrame["SSLv2"]))
#print(stdCorrFrame["SSLv2"])



##ct = pd.crosstab(stdCorrFrame['SSLv2'], nonStdCorrFrame['SSLv2'])
#ct = pd.crosstab(stdCorrFrame['SSLv2'], stdCorrFrame['SSLv3'])
#print(ct)
#print(stats.chi2_contingency(ct))


