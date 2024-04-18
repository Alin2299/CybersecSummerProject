import json
#import pandas as pd
#import os
import sys

#file_path = input("JSON file: ")
#with open(file_path, 'r') as file:
file = sys.argv[1]
data = json.load(open(file))


address_prefixes = []
for item in data['values']:
#    if item['properties']['regionId'] == 0 or 'australia' in item['properties']['region'].lower():
    if 'australia' in item['properties']['region'].lower():
        address_prefixes.extend(item['properties']['addressPrefixes'])

address_prefixes2 = set(address_prefixes)
#print(address_prefixes)
#print()
#print()
#print(address_prefixes2)

for i in address_prefixes2:
    print(i)

#address_prefixes = set(address_prefixes)

#df = pd.DataFrame({'Address Prefix': list(address_prefixes)})
#csv_file = os.path.abspath(os.path.join(os.path.dirname( __file__ ), '..', 'address_prefixes.csv'))
#df.to_csv(csv_file, index=False)
#print("Done")
