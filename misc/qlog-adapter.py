#!/usr/bin/env python
#
# Copyright (c) 2020 Fastly, Toru Maesaka
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import sys
import json

PACKET_LABELS = ["initial", "0rtt", "handshake", "1rtt"]

def handle_packet_received(events, idx):
    frames = []
    for i in range(idx+1, len(events)):
        ev = events[i]
        if ev["type"] == "packet-prepare" or QLOG_EVENT_HANDLERS.has_key(ev["type"]):
            break
        handler = FRAME_EVENT_HANDLERS.get(ev["type"])
        if handler:
            frames.append(handler(ev))

    return [events[idx]["time"], "transport", "packet_received", {
        "packet_type": PACKET_LABELS[events[idx]["packet-type"]],
        "header": {
            "packet_number": events[idx]["pn"]
        },
        "frames": frames
    }]

def handle_packet_sent(events, idx):
    frames = []
    i = idx-1
    while i > 0 and events[i]["type"] != "packet-prepare":
        handler = FRAME_EVENT_HANDLERS.get(events[i]["type"])
        if handler:
            frames.append(handler(events[i]))
        i -= 1

    return [events[idx]["time"], "transport", "packet_sent", {
        "packet_type": PACKET_LABELS[events[idx]["packet-type"]],
        "header": {
            "packet_number": events[idx]["pn"]
        },
        "frames": frames
    }]

def handle_ack_send(event):
    return {
        "frame_type": "ack",
    }

def handle_quictrace_recv_ack(event):
    return {
        "frame_type": "ack",
    }

def handle_ping_receive(event):
    return {
        "frame_type": "ping",
    }


def handle_recv_crypto_frame(event):
    return {
        "frame_type": "crypto",
        "length": event["len"],
        "offset": event["off"]
    }

QLOG_EVENT_HANDLERS = {
    "packet-received": handle_packet_received,
    "packet-sent": handle_packet_sent
}

FRAME_EVENT_HANDLERS = {
    "ack-send": handle_ack_send,
    "ping-receive": handle_ping_receive,
    "quictrace-recv-ack": handle_quictrace_recv_ack,
    "recv-crypto-frame": handle_recv_crypto_frame,
}

def usage():
    print(r"""
Usage:
    python qlog-adapter.py inTrace.jsonl
""".strip())

def load_quicly_events(infile):
    events = []
    with open(infile, "r") as fh:
        for line in fh:
            events.append(json.loads(line))
    return events

def main():
    if len(sys.argv) != 2:
        usage()
        sys.exit(1)

    (_, infile) = sys.argv
    source_events = load_quicly_events(infile)
    trace = {
        "vantage_point": {
            "type": "server"
        },
        "event_fields": [
           "time",
           "category",
           "event",
           "data"
        ],
        "events": []
    }
    for i, event in enumerate(source_events):
        handler = QLOG_EVENT_HANDLERS.get(event["type"])
        if handler:
            trace["events"].append(handler(source_events, i))

    print(json.dumps({
        "qlog_version": "draft-02-wip",
        "title": "h2o/quicly qlog",
        "traces": [trace]
    }))

if __name__ == "__main__":
    main()
