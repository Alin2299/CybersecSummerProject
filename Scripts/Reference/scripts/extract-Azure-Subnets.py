#! /usr/bin/python3

#
# Not yet working
#

import json
import sys

file = sys.argv[1]

db = json.load(open(file))

#print(len(db))

for i, val in enumerate(db):
    print(type(i))
    print(i)
    print(type(val))
    print(val)
#    print(val.keys())
#    for key in val:
#        print(key, 'corresponds to', val[key])
#    print(val)
#    print(i)
#    print(type(db[i]['services']))
##    for serv, data in enumerate(db[i]['services']):
#        print(type(serv))
#        print(type(data))
#        print(data.keys())
##        if "certificate" in data:
##            if data['service_name'] == "HTTP":
#                print(db[i]['ip'], end=" ")
#                print(data['port'])
##                 print(db[i]['ip'], " ", data['port'])
#                print()
#print()
#print(type(db))
