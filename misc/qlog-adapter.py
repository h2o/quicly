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
    source_event = events[idx]
    qlog_event_data = {
        "packet_type": PACKET_LABELS[source_event["packet-type"]],
        "header": {
            "packet_number": source_event["pn"]
        },
        "frames": []
    }
    return [source_event["time"], "transport", "packet_received", qlog_event_data]

def handle_packet_sent(events, idx):
    source_event = events[idx]
    qlog_event_data = {
        "packet_type": PACKET_LABELS[source_event["packet-type"]],
        "header": {
            "packet_number": source_event["pn"]
        },
        "frames": []
    }
    return [source_event["time"], "transport", "packet_sent", qlog_event_data]

QLOG_EVENT_HANDLERS = {
    "packet-received": handle_packet_received,
    "packet-sent": handle_packet_sent
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
