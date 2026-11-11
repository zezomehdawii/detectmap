"""Bounded endpoint discovery from PCAP and PCAPNG link/network headers."""
from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address, ip_address
from struct import unpack, unpack_from
from typing import BinaryIO, Iterator

MAX_CAPTURE_BYTES = 128 * 1024 * 1024
MAX_PACKETS = 1_000_000
MAX_ENDPOINTS = 500
_MAX_BLOCKS = 1_200_000
_HEADER_BYTES = 256
_PCAP_ORDERS = {
    bytes.fromhex("d4 c3 b2 a1"): "<",
    bytes.fromhex("4d 3c b2 a1"): "<",
    bytes.fromhex("a1 b2 c3 d4"): ">",
    bytes.fromhex("a1 b2 3c 4d"): ">",
}
_SECTION = bytes.fromhex("0a 0d 0d 0a")
_SECTION_ORDERS = {bytes.fromhex("4d 3c 2b 1a"): "<", bytes.fromhex("1a 2b 3c 4d"): ">"}
_LINK_TYPES = {0, 1, 101, 108, 113, 228, 229, 276}
_VLAN_TYPES = {0x8100, 0x88A8, 0x9100}
_BROADCAST_MAC = b"\xff" * 6
_IP_PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}
_PORT_LABELS = {
    6: {
        22: "SSH", 53: "DNS", 80: "HTTP", 102: "ISO-on-TCP",
        443: "HTTPS", 445: "SMB", 502: "Modbus/TCP", 3389: "RDP",
        4840: "OPC UA", 20000: "DNP3", 44818: "EtherNet/IP",
    },
    17: {
        53: "DNS", 67: "DHCP", 68: "DHCP", 123: "NTP", 161: "SNMP",
        546: "DHCPv6", 547: "DHCPv6", 2222: "EtherNet/IP",
        20000: "DNP3", 44818: "EtherNet/IP", 47808: "BACnet/IP",
    },
}


class CaptureError(ValueError):
    """Invalid capture framing or unsupported capture format."""


class _ScanLimit(Exception):
    pass


@dataclass
class Endpoint:
    ip_address: str
    mac_addresses: set[str] = field(default_factory=set)
    protocols: set[str] = field(default_factory=set)
    packet_count: int = 0


@dataclass
class Discovery:
    endpoints: list[Endpoint]
    packet_count: int
    truncated: bool
    warnings: list[str]


def canonical_address(value: str | bytes) -> IPv4Address | IPv6Address:
    """Normalise equivalent IPv6 spellings and IPv4-mapped IPv6 addresses."""
    address = ip_address(value.strip() if isinstance(value, str) else value)
    if isinstance(address, IPv6Address):
        if address.scope_id is not None:
            raise ValueError("IP addresses must not include an interface zone")
        if address.ipv4_mapped is not None:
            return address.ipv4_mapped
    return address


def is_endpoint(address: IPv4Address | IPv6Address) -> bool:
    return not (
        address.is_multicast or address.is_unspecified or address.is_loopback
        or address == IPv4Address("255.255.255.255")
    )


def _pcap_frames(stream: BinaryIO, size: int, order: str) -> Iterator[tuple[int, bytes]]:
    header = stream.read(24)
    if len(header) != 24:
        raise CaptureError("PCAP file header is incomplete.")
    major, minor, _, _, snaplen, linktype = unpack_from(order + "HHIIII", header, 4)
    if (major, minor) != (2, 4) or not snaplen:
        raise CaptureError("Unsupported PCAP version or invalid snapshot length.")
    linktype &= 0xFFFF
    while stream.tell() < size:
        record = stream.read(16)
        if len(record) != 16:
            raise CaptureError("PCAP packet header is incomplete.")
        _, _, captured, original = unpack(order + "IIII", record)
        if captured > original or captured > size - stream.tell():
            raise CaptureError("PCAP packet length is invalid or truncated.")
        header = stream.read(min(captured, _HEADER_BYTES))
        if captured > len(header):
            stream.seek(captured - len(header), 1)
        yield linktype, header


def _pcapng_frames(stream: BinaryIO, size: int) -> Iterator[tuple[int, bytes]]:
    order = None
    interfaces: list[tuple[int, int]] = []
    blocks = 0
    while stream.tell() < size:
        offset = stream.tell()
        blocks += 1
        if blocks > _MAX_BLOCKS:
            raise _ScanLimit
        prefix = stream.read(12)
        if len(prefix) < 12:
            raise CaptureError("PCAPNG block header is incomplete.")
        new_section = prefix[:4] == _SECTION
        if new_section:
            order = _SECTION_ORDERS.get(prefix[8:12])
            interfaces.clear()
        if order is None:
            raise CaptureError("PCAPNG byte order or section header is invalid.")
        block_type, length = unpack_from(order + "II", prefix)
        minimum = 28 if new_section else 12
        if length < minimum or length % 4 or length > size - offset:
            raise CaptureError("PCAPNG block length is invalid or truncated.")
        end = offset + length
        stream.seek(end - 4)
        if unpack(order + "I", stream.read(4))[0] != length:
            raise CaptureError("PCAPNG block length does not match its trailer.")
        stream.seek(offset + 8)
        if new_section:
            section = stream.read(8)
            if unpack_from(order + "H", section, 4)[0] != 1:
                raise CaptureError("Unsupported PCAPNG section version.")
        elif block_type == 1:
            if length < 20 or len(interfaces) >= 1024:
                raise CaptureError("PCAPNG interface definition is invalid or exceeds the limit.")
            linktype, _, snaplen = unpack(order + "HHI", stream.read(8))
            interfaces.append((linktype, snaplen))
        elif block_type in {2, 3, 6}:
            if block_type == 3:
                if length < 16 or not interfaces:
                    raise CaptureError("PCAPNG simple packet has no valid interface.")
                original, = unpack(order + "I", stream.read(4))
                linktype, snaplen = interfaces[0]
                captured = min(original, snaplen) if snaplen else original
            else:
                if length < 32:
                    raise CaptureError("PCAPNG packet header is incomplete.")
                packet = stream.read(20)
                interface = unpack_from(order + ("H" if block_type == 2 else "I"), packet)[0]
                if interface >= len(interfaces):
                    raise CaptureError("PCAPNG packet refers to an unknown interface.")
                linktype, _ = interfaces[interface]
                captured, original = unpack_from(order + "II", packet, 12)
            padded = (captured + 3) & ~3
            available = end - 4 - stream.tell()
            if captured > original or padded > available or (block_type == 3 and padded != available):
                raise CaptureError("PCAPNG captured packet length is invalid or truncated.")
            yield linktype, stream.read(min(captured, _HEADER_BYTES))
        stream.seek(end)


def _mac(data: bytes | None) -> str | None:
    if not data or data == b"\0" * 6 or data[0] & 1:
        return None
    return data.hex(":")


def _link_header(linktype: int, frame: bytes) -> tuple[int, bytes, bytes | None, bytes | None]:
    source = destination = None
    if linktype == 1 and len(frame) >= 14:
        source, destination = frame[6:12], frame[:6]
        protocol, offset = int.from_bytes(frame[12:14], "big"), 14
    elif linktype == 113 and len(frame) >= 16:
        protocol, offset = int.from_bytes(frame[14:16], "big"), 16
        if frame[:2] == b"\0\1":
            destination = _BROADCAST_MAC
    elif linktype == 276 and len(frame) >= 20:
        protocol, offset = int.from_bytes(frame[:2], "big"), 20
        if frame[10] == 1:
            destination = _BROADCAST_MAC
    elif linktype in {0, 108, 101, 228, 229}:
        offset = 4 if linktype in {0, 108} else 0
        if len(frame) <= offset:
            return 0, b"", None, None
        protocol = {4: 0x0800, 6: 0x86DD}.get(frame[offset] >> 4, 0)
    else:
        return 0, b"", None, None

    for _ in range(4):
        if protocol not in _VLAN_TYPES or len(frame) < offset + 4:
            break
        protocol = int.from_bytes(frame[offset + 2:offset + 4], "big")
        offset += 4
    return protocol, frame[offset:], source, destination


def _transport(protocol: int, packet: bytes, offset: int | None) -> set[str]:
    label = _IP_PROTOCOLS.get(protocol)
    labels = {label} if label else set()
    if protocol in _PORT_LABELS and offset is not None and len(packet) >= offset + 4:
        for port in unpack_from("!HH", packet, offset):
            service = _PORT_LABELS[protocol].get(port)
            if service:
                labels.add(f"{service} (port {port})")
    return labels


def _ipv6_transport(packet: bytes) -> tuple[int, int | None]:
    protocol, offset = packet[6], 40
    for _ in range(8):
        if protocol not in {0, 43, 44, 51, 60}:
            return protocol, offset
        if len(packet) < offset + 2:
            break
        next_protocol = packet[offset]
        if protocol == 44:
            if len(packet) < offset + 8:
                break
            if unpack_from("!H", packet, offset + 2)[0] & 0xFFF8:
                return next_protocol, None
            size = 8
        elif protocol == 51:
            size = (packet[offset + 1] + 2) * 4
        else:
            size = (packet[offset + 1] + 1) * 8
        offset += size
        protocol = next_protocol
    return protocol, None


def _endpoints(linktype: int, frame: bytes) -> tuple[list[tuple[bytes, bytes | None]], set[str]]:
    protocol, packet, source_mac, destination_mac = _link_header(linktype, frame)
    if protocol == 0x0800 and len(packet) >= 20 and packet[0] >> 4 == 4:
        header_len = (packet[0] & 0x0F) * 4
        total_len = unpack_from("!H", packet, 2)[0]
        if header_len < 20 or total_len < header_len:
            return [], set()
        fragment = unpack_from("!H", packet, 6)[0] & 0x1FFF
        labels = {"IPv4"} | _transport(packet[9], packet[:total_len], None if fragment else header_len)
        peers = [(packet[12:16], source_mac)]
        if destination_mac != _BROADCAST_MAC:
            peers.append((packet[16:20], destination_mac))
        return peers, labels
    if protocol == 0x86DD and len(packet) >= 40 and packet[0] >> 4 == 6:
        payload_len = unpack_from("!H", packet, 4)[0]
        packet = packet[:40 + payload_len]
        transport, offset = _ipv6_transport(packet)
        labels = {"IPv6"} | _transport(transport, packet, offset)
        return [(packet[8:24], source_mac), (packet[24:40], destination_mac)], labels
    if protocol == 0x0806 and len(packet) >= 28 and packet[:6] == b"\x00\x01\x08\x00\x06\x04":
        opcode = unpack_from("!H", packet, 6)[0]
        peers = [(packet[14:18], packet[8:14])] if opcode in {1, 2} else []
        if opcode == 2:
            peers.append((packet[24:28], packet[18:24]))
        return peers, {"ARP"}
    return [], set()


def discover(stream: BinaryIO) -> Discovery:
    """Scan capture headers without retaining payloads or connection metadata."""
    stream.seek(0, 2)
    size = stream.tell()
    if size > MAX_CAPTURE_BYTES:
        raise CaptureError("Capture exceeds the 128 MiB limit.")
    stream.seek(0)
    magic = stream.read(4)
    stream.seek(0)
    if magic in _PCAP_ORDERS:
        frames = _pcap_frames(stream, size, _PCAP_ORDERS[magic])
    elif magic == _SECTION:
        frames = _pcapng_frames(stream, size)
    else:
        raise CaptureError("Upload an uncompressed PCAP or PCAPNG file.")

    endpoints: dict[IPv4Address | IPv6Address, Endpoint] = {}
    known_addresses: dict[bytes, IPv4Address | IPv6Address] = {}
    unsupported: set[int] = set()
    supported_frames = False
    endpoint_limit = packet_limit = False
    packet_count = 0
    try:
        for linktype, frame in frames:
            if packet_count == MAX_PACKETS:
                raise _ScanLimit
            packet_count += 1
            if linktype not in _LINK_TYPES:
                unsupported.add(linktype)
                continue
            supported_frames = True
            observations, protocols = _endpoints(linktype, frame)
            seen: set[IPv4Address | IPv6Address] = set()
            for raw, mac_bytes in observations:
                address = known_addresses.get(raw)
                if address is None:
                    address = canonical_address(raw)
                    if not is_endpoint(address):
                        continue
                endpoint = endpoints.get(address)
                if endpoint is None:
                    if len(endpoints) >= MAX_ENDPOINTS:
                        endpoint_limit = True
                        continue
                    endpoint = endpoints[address] = Endpoint(str(address))
                known_addresses[raw] = address
                if address not in seen:
                    endpoint.packet_count += 1
                    endpoint.protocols.update(protocols)
                    seen.add(address)
                if len(endpoint.mac_addresses) < 8 and (mac := _mac(mac_bytes)):
                    endpoint.mac_addresses.add(mac)
    except _ScanLimit:
        packet_limit = True

    if unsupported and not supported_frames:
        raise CaptureError("No packets use a supported capture link type.")
    warnings = []
    if unsupported:
        shown = ", ".join(map(str, sorted(unsupported)[:8]))
        suffix = f" and {len(unsupported) - 8} more" if len(unsupported) > 8 else ""
        warnings.append(f"Skipped unsupported link types: {shown}{suffix}.")
    if packet_limit:
        warnings.append("The scan limit was reached; some packets were not inspected.")
    if endpoint_limit:
        warnings.append(f"Only the first {MAX_ENDPOINTS} distinct endpoint addresses are shown.")
    if not endpoints:
        warnings.append("No unicast IP endpoints were found in the inspected packets.")
    ordered = sorted(endpoints, key=lambda address: (address.version, int(address)))
    return Discovery([endpoints[address] for address in ordered], packet_count, endpoint_limit or packet_limit, warnings)
