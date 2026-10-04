"""Compute the latency of each sampled offset of one run-one.py --latency capture.

For each offset in the client's recv-offset events (multiples of 15000), latency is the time the client received the
byte at that offset minus the first time tunulator received a downstream packet covering that offset. Offsets are TCP stream
offsets (sequence number minus server ISN + 1) for TCP, and stream offsets of the response stream for QUIC. The run covers only
the measurement window, so all the samples are reported.

QUIC packets are decrypted from the 64-byte prefixes in tunulator.pktlog by `cli --decrypt-packet-batch`, using the server's
1-RTT secret from the key log; STREAM frames are then read from the decrypted bytes.
"""
import argparse
import json
from pathlib import Path
import struct
import subprocess

p = argparse.ArgumentParser()
p.add_argument("run", type=Path, help="Run directory captured with run-one.py --latency")
args = p.parse_args()
run = args.run
metadata = json.loads((run / "metadata.json").read_text())
assert metadata.get("latency"), "capture was not taken with --latency"
interval = 15000  # the interval of the clients' recv-offset events

# tunulator.pktlog: (receive time, segment length, first 64 bytes after the IP header) of each downstream packet
records = list(struct.iter_unpack("<QH64s", (run / "tunulator.pktlog").read_bytes()))

# for each sampled offset, the first time tunulator received it, and the number of times it was received
tunulator_received, tunulator_receives, stats = {}, {}, {}


def count(key):
    stats[key] = stats.get(key, 0) + 1


def received(off, length, at):
    """Record that tunulator received stream bytes [off, off + length) at `at`."""
    k = -(-off // interval) * interval
    while k < off + length:
        tunulator_received.setdefault(k, at)
        tunulator_receives[k] = tunulator_receives.get(k, 0) + 1
        k += interval


def decode_tcp():
    isn = None
    highest = 0
    for at, length, b in records:
        count("packets")
        seq, = struct.unpack_from(">I", b, 4)
        hdr = (b[12] >> 4) * 4
        if b[13] & 0x12 == 0x12:  # SYN-ACK
            isn = seq
            continue
        if isn is None or length <= hdr:
            continue
        # unwrap the 32-bit sequence number relative to the highest offset seen
        rel = (seq - isn - 1 - highest + (1 << 31)) % (1 << 32) - (1 << 31) + highest
        highest = max(highest, rel)
        count("data packets")
        received(rel, length - hdr, at)
    assert isn is not None, "no SYN-ACK in packet log"


def varint(b, i):
    if i >= len(b):
        raise IndexError
    n = 1 << (b[i] >> 6)
    if i + n > len(b):
        raise IndexError
    v = b[i] & 0x3f
    for j in range(1, n):
        v = v << 8 | b[i + j]
    return v, i + n


def parse_frames(b, payload_len):
    """Yield (stream_id, off, len) for STREAM frames; raises IndexError when the prefix ends, KeyError on unknown frames."""
    i = 0
    while i < len(b):
        t = b[i]
        if t in (0x00, 0x01, 0x1e, 0x1f):  # PADDING, PING, HANDSHAKE_DONE, IMMEDIATE_ACK
            i += 1
        elif t in (0x02, 0x03):  # ACK
            _, i = varint(b, i + 1)
            _, i = varint(b, i)
            ranges, i = varint(b, i)
            _, i = varint(b, i)
            for _ in range(ranges * 2 + (3 if t == 0x03 else 0)):
                _, i = varint(b, i)
        elif 0x08 <= t <= 0x0f:  # STREAM
            stream_id, i = varint(b, i + 1)
            off = 0
            if t & 0x04:
                off, i = varint(b, i)
            if t & 0x02:
                length, i = varint(b, i)
            else:
                length = payload_len - i
            yield stream_id, off, length
            i += length
        elif t in (0x10, 0x12, 0x13, 0x14, 0x16, 0x17, 0x19):  # MAX_DATA, MAX_STREAMS, *_BLOCKED, RETIRE_CONNECTION_ID
            _, i = varint(b, i + 1)
        elif t in (0x11, 0x15):  # MAX_STREAM_DATA, STREAM_DATA_BLOCKED
            _, i = varint(b, i + 1)
            _, i = varint(b, i)
        elif t == 0x06 or t == 0x07:  # CRYPTO, NEW_TOKEN
            i += 1
            if t == 0x06:
                _, i = varint(b, i)
            length, i = varint(b, i)
            i += length
        elif t == 0x18:  # NEW_CONNECTION_ID
            _, i = varint(b, i + 1)
            _, i = varint(b, i)
            i += 1 + b[i] + 16
        else:
            raise KeyError(t)


def decode_quic():
    secret = None
    for line in (run / "keylog").read_text().splitlines():
        fields = line.split()
        if fields and fields[0] == "SERVER_TRAFFIC_SECRET_0":
            secret = fields[2]
    assert secret is not None, "no SERVER_TRAFFIC_SECRET_0 in key log"
    # (receive time, packet length, input to cli) of short header packets, skipping the UDP header; a truncated packet is given
    # up to where its tag starts, followed by a dummy tag, so that all the captured payload is decrypted. The server's long header
    # packets carry the client's CID as DCID.
    dcid_len, packets = None, []
    for at, length, b in records:
        count("packets")
        q, qlen = bytes(b[8:min(len(b), length)]), length - 8
        if q[0] & 0x80:
            dcid_len = q[5]
        elif len(q) == qlen:
            packets.append((at, qlen, q))
        else:
            count("truncated")
            packets.append((at, qlen, q[:qlen - 16] + bytes(16)))
    assert dcid_len is not None, "no long header packet in packet log"
    batch = b"".join(struct.pack(">H", len(x)) + x for _, _, x in packets)
    cli = metadata["commands"]["client"][0]
    r = subprocess.run([cli, "--decrypt-packet-batch", f"{secret}:{dcid_len}"], input=batch, capture_output=True, check=True)
    (run / "decrypt.log").write_bytes(r.stderr)
    out, i = [], 0
    while i < len(r.stdout):
        n, = struct.unpack_from(">H", r.stdout, i)
        out.append(r.stdout[i + 2:i + 2 + n])
        i += 2 + n
    assert len(out) == len(packets), (len(out), len(packets))
    for (at, qlen, x), plain in zip(packets, out):
        if not plain:
            count("not decrypted")
            continue
        payload_len = len(plain) + qlen - len(x)  # what was decrypted, plus the payload not captured
        found = False
        try:
            for stream_id, off, n in parse_frames(plain, payload_len):
                found = True
                if stream_id == 0:
                    received(off, n, at)
            count("decoded")
        except IndexError:
            count("decoded" if found else "prefix ends before any STREAM frame")
        except KeyError as e:
            count(f"unknown frame 0x{e.args[0]:02x}")


(decode_tcp if metadata["protocol"] == "tcp" else decode_quic)()

client_received = {}  # in ns, as tunulator; the client reports microseconds
for e in map(json.loads, (run / "client.jsonl").read_text().split("\n")[:-1]):  # the last line might be incomplete
    if e["type"] == "recv-offset":
        client_received[e["offset"]] = e["at"] * 1000

rows = [(k, tunulator_received[k], client_received[k], (client_received[k] - tunulator_received[k]) / 1e6, tunulator_receives[k])
        for k in sorted(tunulator_received) if k in client_received]
not_received_by_client = sum(1 for k in tunulator_received if k not in client_received)
not_received_by_tunulator = sum(1 for k in client_received if k not in tunulator_received)

with (run / "latency.csv").open("w") as f:
    f.write("offset,tunulator_received_ns,client_received_ns,latency_ms,tunulator_receives\n")
    for r in rows:
        f.write("%d,%d,%d,%.3f,%d\n" % r)

lat = sorted(r[3] for r in rows)


def pct(q):
    return lat[min(len(lat) - 1, int(q / 100 * len(lat)))] if lat else None


summary = dict(samples=len(rows), retransmitted_samples=sum(1 for r in rows if r[4] > 1),
               not_received_by_client=not_received_by_client, not_received_by_tunulator=not_received_by_tunulator,
               latency_ms={"min": lat[0] if lat else None, "p50": pct(50), "p90": pct(90), "p99": pct(99),
                           "p99.9": pct(99.9), "max": lat[-1] if lat else None,
                           "mean": sum(lat) / len(lat) if lat else None},
               packet_log=stats)
(run / "latency.json").write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary, indent=2))
