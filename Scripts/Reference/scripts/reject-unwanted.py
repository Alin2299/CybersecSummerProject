import sys
import ipaddress
#from itertools import groupby
import itertools

socketsIn = sys.argv[1]
rejectIn = sys.argv[2]
#socketsOut = sys.argv[3]

#print("socketsIn is", socketsIn)
#print("rejectIn is", rejectIn)
#print("socketsOut is", socketsOut)

rejects = {}
with open(rejectIn) as f:
    for line in f:
        (key, val) = line.split()
#        print(key)
#        print(val)
#        print()
        rejects[key] = val

#print(len(rejects))

#source = {}
source = []
long_list = []
short_list = []
reject_count = 0

with open(socketsIn) as f:
    for line in f:
        reject = False
#        (key, val) = line.split()
        inner_list = line.split()
#        print(key)
#        print(val)
#        print()
#        source[key] = val
        source.append(inner_list)
        for i, (subnet, reason) in enumerate(rejects.items()):
            if ipaddress.ip_address(inner_list[0]) in ipaddress.ip_network(subnet):
#                print("# ", inner_list[0]," has been rejected as it's in ", subnet, " which is ", reason)
#                print(inner_list[0])
                reject_count = reject_count + 1
                reject = True
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
        if not(reject):
            print(inner_list[0], " ", inner_list[1])

#print("long_list is a ", type(long_list), " with ", len(long_list), " items")
#[short_list.append(x) for x in long_list if x not in short_list]
#print("short_list is a ", type(short_list), " with ", len(short_list), " items")
#print("total reject count is ", reject_count)
#print("total source record count is ", len(source))
#short_list = [k for k, g in itertools.groupby(long_list)]
#print("short_list is a ", type(short_list), " with ", len(short_list), " items")
#print(long_list)
