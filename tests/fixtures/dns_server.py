"""Minimal UDP fixture for DNSx contract checks; no upstream DNS."""

from contextlib import contextmanager
import socket
import socketserver
import struct
import threading


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        packet, transport = self.request
        offset, labels = 12, []
        while offset < len(packet) and packet[offset]:
            size = packet[offset]
            if size > 63 or offset + size + 1 >= len(packet):
                return
            labels.append(packet[offset + 1:offset + size + 1])
            offset += size + 1
        offset += 1
        if offset + 4 > len(packet):
            return
        record_type, record_class = struct.unpack("!HH", packet[offset:offset + 4])
        question = packet[12:offset + 4]
        live = b".".join(labels).lower() == b"live.example.test"
        answer = b""
        if live and record_type in (1, 28) and record_class == 1:
            address = (socket.inet_pton(socket.AF_INET, "192.0.2.1") if record_type == 1
                       else socket.inet_pton(socket.AF_INET6, "2001:db8::1"))
            answer = b"\xc0\x0c" + struct.pack("!HHIH", record_type, 1, 60, len(address)) + address
        header = packet[:2] + struct.pack("!HHHHH", 0x8180 if live else 0x8183, 1, bool(answer), 0, 0)
        transport.sendto(header + question + answer, self.client_address)


@contextmanager
def local_dns():
    with socketserver.UDPServer(("127.0.0.1", 0), DNSHandler) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        try:
            yield f"127.0.0.1:{server.server_address[1]}"
        finally:
            server.shutdown()
            thread.join(1)
