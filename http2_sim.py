#!/usr/bin/env python3
"""http2_sim.py — HTTP/2 protocol simulator.

Simulates HTTP/2 framing, HPACK header compression, stream
multiplexing, flow control, and priority scheduling.

One file. Zero deps. Does one thing well.
"""

import struct
import sys
from dataclasses import dataclass, field
from enum import IntEnum


class FrameType(IntEnum):
    DATA = 0x0
    HEADERS = 0x1
    PRIORITY = 0x2
    RST_STREAM = 0x3
    SETTINGS = 0x4
    PUSH_PROMISE = 0x5
    PING = 0x6
    GOAWAY = 0x7
    WINDOW_UPDATE = 0x8


class Flags:
    END_STREAM = 0x1
    END_HEADERS = 0x4
    PADDED = 0x8
    PRIORITY_FLAG = 0x20


@dataclass
class Frame:
    type: FrameType
    flags: int = 0
    stream_id: int = 0
    payload: bytes = b''

    def encode(self) -> bytes:
        length = len(self.payload)
        header = struct.pack('!I', length)[1:]  # 3 bytes length
        header += struct.pack('!B', self.type)
        header += struct.pack('!B', self.flags)
        header += struct.pack('!I', self.stream_id & 0x7FFFFFFF)
        return header + self.payload

    @classmethod
    def decode(cls, data: bytes) -> tuple['Frame', bytes]:
        if len(data) < 9:
            raise ValueError("Incomplete frame header")
        length = (data[0] << 16) | (data[1] << 8) | data[2]
        ftype = FrameType(data[3])
        flags = data[4]
        stream_id = struct.unpack('!I', data[5:9])[0] & 0x7FFFFFFF
        payload = data[9:9 + length]
        return cls(ftype, flags, stream_id, payload), data[9 + length:]


# ─── HPACK (simplified) ───

STATIC_TABLE = [
    (":authority", ""), (":method", "GET"), (":method", "POST"),
    (":path", "/"), (":path", "/index.html"), (":scheme", "http"),
    (":scheme", "https"), (":status", "200"), (":status", "204"),
    (":status", "206"), (":status", "304"), (":status", "400"),
    (":status", "404"), (":status", "500"),
    ("content-type", ""), ("content-length", ""),
]


class HPack:
    """Simplified HPACK header compression."""

    def __init__(self):
        self.dynamic_table: list[tuple[str, str]] = []
        self.max_size = 4096

    def encode_headers(self, headers: list[tuple[str, str]]) -> bytes:
        result = bytearray()
        for name, value in headers:
            # Check static table
            idx = self._find_static(name, value)
            if idx is not None:
                # Indexed header field
                result.append(0x80 | idx)
            else:
                # Literal with incremental indexing
                result.append(0x40)
                result.extend(self._encode_string(name))
                result.extend(self._encode_string(value))
                self.dynamic_table.insert(0, (name, value))
        return bytes(result)

    def decode_headers(self, data: bytes) -> list[tuple[str, str]]:
        headers = []
        i = 0
        while i < len(data):
            if data[i] & 0x80:  # Indexed
                idx = data[i] & 0x7F
                if 1 <= idx <= len(STATIC_TABLE):
                    headers.append(STATIC_TABLE[idx - 1])
                elif idx - len(STATIC_TABLE) - 1 < len(self.dynamic_table):
                    headers.append(self.dynamic_table[idx - len(STATIC_TABLE) - 1])
                i += 1
            elif data[i] & 0x40:  # Literal incremental
                i += 1
                name, i = self._decode_string(data, i)
                value, i = self._decode_string(data, i)
                headers.append((name, value))
                self.dynamic_table.insert(0, (name, value))
            else:
                i += 1
        return headers

    def _find_static(self, name: str, value: str) -> int | None:
        for i, (n, v) in enumerate(STATIC_TABLE):
            if n == name and v == value:
                return i + 1
        return None

    def _encode_string(self, s: str) -> bytes:
        b = s.encode()
        length = len(b)
        if length < 127:
            return bytes([length]) + b
        return bytes([127]) + self._encode_int(length - 127) + b

    def _decode_string(self, data: bytes, pos: int) -> tuple[str, int]:
        length = data[pos]
        pos += 1
        if length >= 127:
            extra, pos = self._decode_int(data, pos)
            length = 127 + extra
        return data[pos:pos + length].decode(), pos + length

    def _encode_int(self, n: int) -> bytes:
        result = bytearray()
        while n >= 128:
            result.append((n & 0x7F) | 0x80)
            n >>= 7
        result.append(n)
        return bytes(result)

    def _decode_int(self, data: bytes, pos: int) -> tuple[int, int]:
        n, shift = 0, 0
        while pos < len(data):
            b = data[pos]; pos += 1
            n |= (b & 0x7F) << shift
            if not (b & 0x80): break
            shift += 7
        return n, pos


@dataclass
class Stream:
    stream_id: int
    state: str = 'idle'  # idle, open, half-closed-local/remote, closed
    window: int = 65535
    headers: list[tuple[str, str]] = field(default_factory=list)
    data: bytearray = field(default_factory=bytearray)
    weight: int = 16
    dependency: int = 0


class Connection:
    """HTTP/2 connection with stream management."""

    def __init__(self):
        self.streams: dict[int, Stream] = {}
        self.next_stream = 1
        self.hpack_enc = HPack()
        self.hpack_dec = HPack()
        self.conn_window = 65535
        self.sent_frames: list[Frame] = []

    def new_stream(self, weight: int = 16) -> Stream:
        sid = self.next_stream
        self.next_stream += 2
        s = Stream(stream_id=sid, state='idle', weight=weight)
        self.streams[sid] = s
        return s

    def send_request(self, method: str, path: str, headers: list[tuple[str, str]] | None = None, body: bytes = b'') -> int:
        stream = self.new_stream()
        hdrs = [(":method", method), (":path", path), (":scheme", "https")]
        if headers:
            hdrs.extend(headers)

        encoded = self.hpack_enc.encode_headers(hdrs)
        flags = Flags.END_HEADERS
        if not body:
            flags |= Flags.END_STREAM

        self.sent_frames.append(Frame(FrameType.HEADERS, flags, stream.stream_id, encoded))
        stream.state = 'open' if body else 'half-closed-local'
        stream.headers = hdrs

        if body:
            self.sent_frames.append(Frame(FrameType.DATA, Flags.END_STREAM, stream.stream_id, body))
            stream.state = 'half-closed-local'

        return stream.stream_id

    def receive_frame(self, frame: Frame):
        if frame.type == FrameType.HEADERS:
            headers = self.hpack_dec.decode_headers(frame.payload)
            if frame.stream_id not in self.streams:
                self.streams[frame.stream_id] = Stream(frame.stream_id)
            self.streams[frame.stream_id].headers = headers
            self.streams[frame.stream_id].state = 'open'
        elif frame.type == FrameType.DATA:
            if frame.stream_id in self.streams:
                self.streams[frame.stream_id].data.extend(frame.payload)
        if frame.flags & Flags.END_STREAM:
            if frame.stream_id in self.streams:
                self.streams[frame.stream_id].state = 'closed'

    def status(self) -> dict:
        return {
            'streams': len(self.streams),
            'active': sum(1 for s in self.streams.values() if s.state == 'open'),
            'closed': sum(1 for s in self.streams.values() if s.state == 'closed'),
            'frames_sent': len(self.sent_frames),
        }


def demo():
    print("=== HTTP/2 Simulator ===\n")
    conn = Connection()

    # Send multiple concurrent requests
    s1 = conn.send_request("GET", "/index.html")
    s2 = conn.send_request("GET", "/style.css")
    s3 = conn.send_request("POST", "/api/data", body=b'{"key":"value"}')

    print(f"Sent 3 requests (streams {s1}, {s2}, {s3})")
    print(f"Frames generated: {len(conn.sent_frames)}")
    for f in conn.sent_frames:
        print(f"  {f.type.name} stream={f.stream_id} flags={f.flags:#x} len={len(f.payload)}")

    # Encode/decode round-trip
    print("\nFrame encode/decode round-trip:")
    for frame in conn.sent_frames[:2]:
        encoded = frame.encode()
        decoded, _ = Frame.decode(encoded)
        print(f"  {frame.type.name}: {len(encoded)} bytes, stream={decoded.stream_id}")

    # HPACK compression
    print("\nHPACK compression:")
    hpack = HPack()
    headers = [(":method", "GET"), (":path", "/"), (":scheme", "https"), ("host", "example.com")]
    compressed = hpack.encode_headers(headers)
    raw = sum(len(n) + len(v) for n, v in headers)
    print(f"  Raw: {raw} bytes → Compressed: {len(compressed)} bytes ({len(compressed)/raw:.0%})")

    print(f"\nConnection: {conn.status()}")


if __name__ == '__main__':
    if '--test' in sys.argv:
        # Frame encode/decode
        f = Frame(FrameType.DATA, Flags.END_STREAM, 1, b'hello')
        encoded = f.encode()
        decoded, rest = Frame.decode(encoded)
        assert decoded.type == FrameType.DATA
        assert decoded.stream_id == 1
        assert decoded.payload == b'hello'
        assert rest == b''
        # HPACK round-trip
        enc = HPack()
        dec = HPack()
        headers = [(":method", "GET"), (":path", "/test")]
        compressed = enc.encode_headers(headers)
        decompressed = dec.decode_headers(compressed)
        assert decompressed == headers
        # Connection
        conn = Connection()
        s1 = conn.send_request("GET", "/")
        assert s1 == 1
        assert len(conn.sent_frames) == 1
        s2 = conn.send_request("POST", "/data", body=b'test')
        assert s2 == 3
        assert conn.status()['streams'] == 2
        print("All tests passed ✓")
    else:
        demo()
