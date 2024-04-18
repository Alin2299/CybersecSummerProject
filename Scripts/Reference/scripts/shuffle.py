import sys
import random

file = sys.argv[1]
#d = {}
keys = []
with open(file) as f:
    for line in f:
#        key = line.split()
#        d[(line.strip())] = 0
        keys.append(line.split())
#keys =  list(d.keys())
random.shuffle(keys)
#print(keys)
#print(type(keys))

for i in keys:
    print(i[0], " ", i[1])
