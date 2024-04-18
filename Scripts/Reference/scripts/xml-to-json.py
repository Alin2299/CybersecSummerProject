#!/usr/bin/python3

import json
import xmltodict
import sys

file = sys.argv[1]

f = open(file)
xml_content = f.read()
f.close()

print(json.dumps(xmltodict.parse(xml_content), indent=2, sort_keys=True))
