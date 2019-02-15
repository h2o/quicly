import sys
import json
from pprint import pprint

fields = {"streamId": "stream-id",
          "fin": "fin",
          "length": "len",
          }

def transform(inf, outf):
    start = -1
    qtr = {}
    qtr["protocolVersion"] = "AAAA"
    qtr["events"] = []
    frames = []
    for line in inf:
        trace = json.loads(line)
        if trace["type"][:9] != "quictrace": continue

        # Use first connection that is seen as the CID for the trace.
        # TODO: Make this a cmdline parameter if multiple CIDs in trace.
        if cid == -1: 
            cid = trace["conn"]
            qtr["destinationConnectionId"] = str(cid)

        # Packet sent
        if trace["type"] == "quictrace-sent":
            packet = {}
            packet["eventType"] = "PACKET_SENT"
            if start == -1: start = trace["time"]
            packet["timeUs"] = str((trace["time"] - start) * 1000)
            packet["packetNumber"] = str(trace["pn"])
            packet["packetSize"] = str(trace["len"])
            packet["encryptionLevel"] = "ENCRYPTION_1RTT"
            packet["frames"] = frames
            qtr["events"].append(packet)
            frames = []  # empty frames list

        # Stream frame sent
        if trace["type"] == "quictrace-send-stream":
            info = {}
            info["streamId"] = str(trace["stream-id"])
            if (trace["stream-id"] < 0):
                info["streamId"] = str(31337 + trace["stream-id"])
            if trace["fin"] == 0:
                info["fin"] = False
            else:
                info["fin"] = True
            info["length"] = str(trace["len"])
            info["offset"] = str(trace["off"])
            # Create and populate new frame
            frame = {}
            frame["frameType"] = "STREAM"
            frame["streamFrameInfo"] = info
            frames.append(frame)

    json.dump(qtr, outf)


def main():
    if len(sys.argv) != 3:
        print "Usage: python adapter.py inTrace outTrace"
        sys.exit(1)
        
    inf = open(sys.argv[1], 'r')
    outf = open(sys.argv[2], 'w')
    transform(inf, outf)
    inf.close()
    outf.close()


if __name__ == "__main__":
    main()

