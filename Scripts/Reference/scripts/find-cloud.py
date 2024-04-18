#!/usr/bin/python3

# Takes a results/score file (IP address, port, score, comments - comma separated)
# as argv[1] and a list of subnets in CIDR notation (one per line) as argv[2], and
# returns the lines where the IP address are included in the subnets file. Output
# to stdout.

import sys
import ipaddress
import itertools

scoresIn = sys.argv[1]
subnetsIn = sys.argv[2]

#print("scoresIn is", scoresIn)
#print("subnetsIn is", subnetsIn)

subnets = {}
with open(subnetsIn) as f:
    for line in f:
#        (key, val) = line.split()
#        print(key)
#        print(val)
#        print()
#        print(line.strip())
        subnets[line.strip()] = 1

#print(len(subnets))

#source = {}
source = []
long_list = []
short_list = []
#reject_count = 0

with open(scoresIn) as f:
    for line in f:
        present = False
        inner_list = line.split(',')
        source.append(inner_list)
        for i, (subnet, reason) in enumerate(subnets.items()):
            if ipaddress.ip_address(inner_list[0]) in ipaddress.ip_network(subnet):
#                print("# ", inner_list[0]," has been rejected as it's in ", subnet, " which is ", reason)
#                print(inner_list[0])
#                reject_count = reject_count + 1
                present = True
#                print("reject count is now ", reject_count)
#            else:
#                long_list.append(inner_list)
#                if not (inner_list in short_list):
#                    short_list.append(inner_list)
#                    print("short_list now has ", len(short_list), " items")
#                print(key, " ", val)
#                print(key)
#                print(subnet)
#                print(reason)
#                print()
#        if not(present):
        if present:
#            print(inner_list[0], " ", inner_list[1])
            print(line.strip())
