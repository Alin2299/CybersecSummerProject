import json
import sys

file = sys.argv[1]

db = json.load(open(file))

#print(len(db))

for i, val in enumerate(db):
#    print(type(i))
#    print(i)
#    print(type(val))
#    print(val.keys())
    for key in val:
        if key == "autonomous_system":
#            print(val[key])
#            print(type(val[key]))
            j = val[key]
#            print(type(j))
#            print(j['asn'])
            asnumber = j['asn']
            prefix = j['bgp_prefix']
            print(db[i]['ip'], " ", asnumber, " ", prefix)
#            print(db[i]['ip'])
#            print(asnumber, " ", prefix)
#            for x in val[key]:
#                print(type(x))
#                print(x)
#            print(key, 'corresponds to', val[key])
#            print(type(val[key]))
#            print()
#    print(val)
#    print(i)
#    print(type(db[i]['services']))
#    for serv, data in enumerate(db[i]['services']):
#    for asn, data in enumerate(db[i]['autonomous_system']):
#        print(type(asn))
#        print(asn)
#        print(type(data))
#        if "bgp_prefix" in data:
#            print (data)
#        print()
#        if "certificate" in data:
#            if data['service_name'] == "HTTP":
#                print(db[i]['ip'], end=" ")
#                print(data['port'])
#                 print(db[i]['ip'], " ", data['port'])
#                print()
#print()
#print(type(db))
