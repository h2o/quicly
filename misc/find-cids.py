import sys
import json

if len(sys.argv) != 2:
    print "Usage: python find-cids.py inTrace"
    sys.exit(1)
    
cids = {}
f = open(sys.argv[1], 'r')
for line in f:
    event = json.loads(line)
    if event["type"] != "" and event["type"] == "accept":
        cids[event["conn"]] = None

print "Connection IDs:", cids.keys()
f.close()
