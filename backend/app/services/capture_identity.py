"""Passively extract bounded, address-linked identity evidence from packet payloads."""
from __future__ import annotations

import re
from collections import OrderedDict
from ipaddress import IPv4Address, IPv6Address
from struct import unpack_from

_NAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)
_MAX_ADDRESSES = 2000
_MAX_VALUES = 8
_MAX_DHCP_REQUESTS = 1024


def _hostname(value: str) -> str | None:
    name = value.lower().removesuffix(".")
    if 0 < len(name) <= 253 and all(_NAME.fullmatch(label) for label in name.split(".")):
        if not all(label.isdigit() for label in name.split(".")):
            return name
    return None


def _dns_name(message: bytes, start: int, *, compressed: bool = True) -> tuple[str, int]:
    labels = []
    cursor = start
    end = None
    wire_length = 1
    pointers = 0
    while cursor < len(message):
        length = message[cursor]
        if length == 0:
            return ".".join(labels), end if end is not None else cursor + 1
        if compressed and length & 0xC0 == 0xC0 and cursor + 1 < len(message):
            target = ((length & 0x3F) << 8) | message[cursor + 1]
            pointers += 1
            if target >= cursor or pointers > 16:
                break
            if end is None:
                end = cursor + 2
            cursor = target
            continue
        if length > 63 or cursor + 1 + length > len(message):
            break
        wire_length += length + 1
        if wire_length > 255:
            break
        label = message[cursor + 1:cursor + 1 + length].decode("ascii")
        # A dot inside a wire label is not a DNS label separator.
        if "." in label:
            break
        labels.append(label)
        cursor += length + 1
    raise ValueError("Invalid DNS name")


def _reverse_address(name: str) -> bytes | None:
    labels = name.lower().split(".")
    try:
        if len(labels) == 6 and labels[-2:] == ["in-addr", "arpa"]:
            return IPv4Address(".".join(reversed(labels[:-2]))).packed
        if len(labels) == 34 and labels[-2:] == ["ip6", "arpa"] and all(
            len(label) == 1 and label in "0123456789abcdef" for label in labels[:-2]
        ):
            return IPv6Address(int("".join(reversed(labels[:-2])), 16)).packed
    except ValueError:
        pass
    return None


def _dns_answers(message: bytes, label: str) -> list[tuple[bytes, str, str]]:
    if len(message) < 12:
        return []
    flags, questions, answers, _, _ = unpack_from("!5H", message, 2)
    if flags & 0xFA0F != 0x8000 or questions > 32 or answers > 128:
        return []
    cursor = 12
    results = []
    try:
        for _ in range(questions):
            _, cursor = _dns_name(message, cursor)
            cursor += 4
        for _ in range(answers):
            owner, cursor = _dns_name(message, cursor)
            if len(message) < cursor + 10:
                return []
            kind, rr_class, ttl, length = unpack_from("!HHIH", message, cursor)
            cursor += 10
            end = cursor + length
            if end > len(message):
                return []
            internet_class = rr_class & 0x7FFF if label == "mDNS" else rr_class
            if internet_class == 1 and (ttl or label != "mDNS"):
                if (kind, length) in {(1, 4), (28, 16)} and (name := _hostname(owner)):
                    results.append((message[cursor:end], name, f"{label} {'A' if kind == 1 else 'AAAA'}"))
                elif kind == 12 and (address := _reverse_address(owner)):
                    target, name_end = _dns_name(message, cursor)
                    if name_end == end and (name := _hostname(target)):
                        results.append((address, name, f"{label} PTR"))
            cursor = end
    except ValueError:
        return []
    return results


def _dhcp_options(message: bytes) -> dict[int, bytes]:
    if len(message) < 241 or message[236:240] != b"\x63\x82\x53\x63":
        return {}
    options: dict[int, bytes] = {}
    cursor = 240
    while cursor < len(message):
        code = message[cursor]
        cursor += 1
        if code == 0:
            continue
        if code == 255:
            return options
        if cursor >= len(message):
            break
        end = cursor + 1 + message[cursor]
        if end > len(message):
            break
        if code in {12, 53, 81}:
            options.setdefault(code, message[cursor + 1:end])
        cursor = end
    return {}


def _dhcp_name(options: dict[int, bytes]) -> str | None:
    fqdn = options.get(81, b"")
    try:
        if len(fqdn) > 3:
            if fqdn[0] & 4:
                # RFC 4702 uses DNS label encoding without compression.
                name, end = _dns_name(fqdn[3:], 0, compressed=False)
                if end == len(fqdn) - 3 and (valid := _hostname(name)):
                    return valid
            elif valid := _hostname(fqdn[3:].decode("ascii")):
                return valid
    except ValueError:
        pass
    try:
        return _hostname(options.get(12, b"").decode("ascii"))
    except UnicodeError:
        return None


def _ntlm_text(data: bytes, is_unicode: bool = True) -> str | None:
    try:
        return _hostname(data.decode("utf-16-le" if is_unicode else "ascii"))
    except UnicodeError:
        return None


def _ntlm_buffer(message: bytes, offset: int, minimum: int) -> bytes:
    size, _, start = unpack_from("<HHI", message, offset)
    if size and minimum <= start <= len(message) - size:
        return message[start:start + size]
    return b""


def _smb2_identity(data: bytes, *, from_server: bool) -> tuple[list[tuple[str, str]], str | None]:
    # Direct-hosted SMB2 on TCP 445. Inspect complete Session Setup frames.
    if len(data) < 76 or data[0] or data[4:8] != b"\xfeSMB":
        return [], None
    end = 4 + int.from_bytes(data[1:4], "big")
    if not 76 <= end <= len(data) or data[8:10] != b"\x40\0" or data[16:18] != b"\x01\0":
        return [], None
    response = bool(data[20] & 1)
    if response != from_server:
        return [], None
    # A compound message bounds this command's security buffer.
    next_command, = unpack_from("<I", data, 24)
    if next_command:
        end = min(end, 4 + next_command)
    structure, = unpack_from("<H", data, 68)
    if response and structure == 9:
        start, length = unpack_from("<HH", data, 72)
        minimum = 72
    elif not response and structure == 25 and end >= 92:
        start, length = unpack_from("<HH", data, 80)
        minimum = 88
    else:
        return [], None
    if start < minimum or 4 + start + length > end:
        return [], None
    token = data[4 + start:4 + start + length]
    signature = token.find(b"NTLMSSP\0")
    if signature < 0:
        return [], None
    message = token[signature:]
    if len(message) >= 64 and not response and message[8:12] == b"\x03\0\0\0":
        flags, = unpack_from("<I", message, 60)
        workstation = _ntlm_buffer(message, 44, 72 if flags & 0x02000000 else 64)
        hostname = _ntlm_text(workstation, bool(flags & 1))
        names = [(hostname, "SMB2 NTLM workstation")] if hostname else []
        version_offset = 64
    elif len(message) >= 48 and response and message[8:12] == b"\x02\0\0\0":
        flags, = unpack_from("<I", message, 20)
        pairs = _ntlm_buffer(message, 40, 56 if flags & 0x02000000 else 48) if flags & 0x00800000 else b""
        names = []
        cursor = 0
        while cursor + 4 <= len(pairs):
            kind, size = unpack_from("<HH", pairs, cursor)
            cursor += 4
            if kind == 0 or cursor + size > len(pairs):
                break
            if kind in {1, 3} and (name := _ntlm_text(pairs[cursor:cursor + size])):
                names.append((name, "SMB2 NTLM server DNS name" if kind == 3 else "SMB2 NTLM server NetBIOS name"))
            cursor += size
        version_offset = 48
    else:
        return [], None

    version = None
    if flags & 0x02000000 and len(message) >= version_offset + 8:
        major, minor, build, reserved, revision = unpack_from("<BBH3sB", message, version_offset)
        if major and build and reserved == b"\0" * 3 and revision == 15:
            version = f"{major}.{minor}.{build} (NTLM-reported OS version)"
    return names, version


class CaptureIdentity:
    def __init__(self) -> None:
        self.hostnames: dict[bytes, dict[str, set[str]]] = {}
        self.os_versions: dict[bytes, set[str]] = {}
        self._dhcp_requests: OrderedDict[tuple[bytes, bytes], str] = OrderedDict()

    def add_hostname(self, address: bytes, name: str, source: str) -> None:
        if address not in self.hostnames and len(self.hostnames) >= _MAX_ADDRESSES:
            return
        names = self.hostnames.setdefault(address, {})
        if name in names or len(names) < _MAX_VALUES:
            names.setdefault(name, set()).add(source)

    def _dhcp(self, payload: bytes, ports: tuple[int, int]) -> tuple[bytes, bytes] | None:
        options = _dhcp_options(payload)
        if not options or payload[1:3] != b"\x01\x06":
            return None
        mac = payload[28:34]
        if not any(mac) or mac[0] & 1:
            return None
        key = (payload[4:8], mac)
        name = _dhcp_name(options)
        kind = options.get(53)
        if ports == (68, 67) and payload[0] == 1 and kind in {b"\x01", b"\x03"}:
            if name:
                self._dhcp_requests[key] = name
                self._dhcp_requests.move_to_end(key)
                if len(self._dhcp_requests) > _MAX_DHCP_REQUESTS:
                    self._dhcp_requests.popitem(last=False)
        elif ports == (67, 68) and payload[0] == 2:
            if kind == b"\x06":
                self._dhcp_requests.pop(key, None)
            if kind == b"\x05":
                address = payload[16:20]
                requested = self._dhcp_requests.pop(key, None)
                if address != b"\0" * 4:
                    if name:
                        self.add_hostname(address, name, "DHCP ACK")
                    elif requested:
                        self.add_hostname(address, requested, "DHCP request and ACK")
                    return address, mac
        return None

    def observe(
        self, protocol: int, packet: bytes, offset: int | None, source: bytes,
    ) -> tuple[bytes, bytes] | None:
        if offset is None or protocol not in {6, 17} or len(packet) < offset + 8:
            return None
        ports = unpack_from("!HH", packet, offset)
        if protocol == 17:
            length, = unpack_from("!H", packet, offset + 4)
            if length < 8 or offset + length > len(packet):
                return None
            if ports in {(68, 67), (67, 68)} and len(source) == 4:
                return self._dhcp(packet[offset + 8:offset + length], ports)
            if ports[0] not in {53, 5353, 5355}:
                return None
            payload = packet[offset + 8:offset + length]
        else:
            if (445 not in ports and ports[0] != 53) or len(packet) < offset + 20:
                return None
            header_length = (packet[offset + 12] >> 4) * 4
            if header_length < 20 or len(packet) < offset + header_length:
                return None
            payload = packet[offset + header_length:]
            if 445 in ports:
                names, version = _smb2_identity(payload, from_server=ports[0] == 445)
                for name, origin in names:
                    self.add_hostname(source, name, origin)
                if version and (source in self.os_versions or len(self.os_versions) < _MAX_ADDRESSES):
                    versions = self.os_versions.setdefault(source, set())
                    if len(versions) < _MAX_VALUES:
                        versions.add(version)
                return None
            if len(payload) < 2 or int.from_bytes(payload[:2], "big") != len(payload) - 2:
                return None
            payload = payload[2:]
        label = {53: "DNS", 5353: "mDNS", 5355: "LLMNR"}[ports[0]]
        for address, name, origin in _dns_answers(payload, label):
            self.add_hostname(address, name, origin)
        return None
