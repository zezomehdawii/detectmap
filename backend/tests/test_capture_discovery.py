"""Capture-format and endpoint discovery regressions."""
from contextlib import asynccontextmanager
from io import BytesIO
from ipaddress import ip_address
from struct import pack

import pytest
from httpx import ASGITransport, AsyncClient

from app.api import assets
from app.api.deps import TenantPrincipal, current_tenant_user
from app.main import app
from app.models.public import Customer, CustomerStatus, Role, User
from app.services import capture_discovery as capture


def ethernet(payload, ethertype=0x0800, *, broadcast=False, vlan=False):
    destination = b"\xff" * 6 if broadcast else bytes.fromhex("02 00 00 00 00 02")
    source = bytes.fromhex("02 00 00 00 00 01")
    protocol = pack("!HHH", 0x8100, 10, ethertype) if vlan else pack("!H", ethertype)
    return destination + source + protocol + payload


def ipv4(source="10.0.0.1", destination="10.0.0.2", *, fragment=0):
    return pack(
        "!BBHHHBBH4s4sHH", 0x45, 0, 40, 1, fragment, 64, 6, 0,
        ip_address(source).packed, ip_address(destination).packed, 39001, 502,
    ) + b"\0" * 16


def ipv6(source, destination):
    return pack(
        "!IHBB16s16sHHHH", 6 << 28, 8, 17, 64, ip_address(source).packed,
        ip_address(destination).packed, 39001, 53, 8, 0,
    )


def pcap(frames, *, order="<", linktype=1, nanos=False):
    magic = 0xA1B23C4D if nanos else 0xA1B2C3D4
    header = pack(order + "IHHIIII", magic, 2, 4, 0, 0, 65535, linktype)
    return header + b"".join(pack(order + "IIII", 0, 0, len(frame), len(frame)) + frame for frame in frames)


def block(order, blocktype, body):
    padding = bytes((-len(body)) % 4)
    length = 12 + len(body) + len(padding)
    return pack(order + "II", blocktype, length) + body + padding + pack(order + "I", length)


def section(order, links):
    return block(order, 0x0A0D0D0A, pack(order + "IHHq", 0x1A2B3C4D, 1, 0, -1)) + b"".join(
        block(order, 1, pack(order + "HHI", link, 0, 65535)) for link in links
    )


def epb(order, interface, frame):
    return block(order, 6, pack(order + "IIIII", interface, 0, 0, len(frame), len(frame)) + frame)


@pytest.mark.parametrize("order,nanos", [("<", False), (">", False), ("<", True), (">", True)])
def test_pcap_discovers_vlan_endpoints_and_excludes_broadcast(order, nanos):
    result = capture.discover(BytesIO(pcap([
        ethernet(ipv4(), vlan=True),
        ethernet(ipv4(destination="10.0.0.255"), broadcast=True),
    ], order=order, nanos=nanos)))
    assert result.packet_count == 2 and not result.truncated
    first, second = result.endpoints
    assert (first.ip_address, first.packet_count) == ("10.0.0.1", 2)
    assert (second.ip_address, second.packet_count) == ("10.0.0.2", 1)
    assert first.mac_addresses == {"02:00:00:00:00:01"}
    assert first.protocols == {"IPv4", "TCP", "Modbus/TCP (port 502)"}


def test_pcapng_multiple_interfaces_and_sections_normalize_mapped_addresses():
    tcp = ethernet(ipv4())
    udp = ipv6("::ffff:10.0.0.1", "2001:db8::1")
    payload = (
        section("<", [1, 101, 127])
        + epb("<", 0, tcp)
        + epb("<", 1, udp)
        + epb("<", 2, b"unsupported link")
        + section(">", [1])
        + block(">", 3, pack(">I", len(tcp)) + tcp)
    )
    result = capture.discover(BytesIO(payload))
    assert result.packet_count == 4 and not result.truncated
    assert result.warnings == ["Skipped unsupported link types: 127."]
    assert [row.ip_address for row in result.endpoints] == ["10.0.0.1", "10.0.0.2", "2001:db8::1"]
    assert result.endpoints[0].packet_count == 3
    assert result.endpoints[0].protocols.issuperset({"TCP", "UDP", "IPv4", "IPv6", "DNS (port 53)"})


def test_arp_queries_and_later_ip_fragments_do_not_imply_extra_endpoints_or_ports():
    arp_request = pack(
        "!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, bytes.fromhex("02 00 00 00 00 01"),
        ip_address("10.0.0.1").packed, b"\0" * 6, ip_address("10.0.0.9").packed,
    )
    result = capture.discover(BytesIO(pcap([
        ethernet(arp_request, ethertype=0x0806, broadcast=True),
        ethernet(ipv4(destination="224.0.0.1", fragment=1)),
    ])))
    assert len(result.endpoints) == 1
    assert result.endpoints[0].ip_address == "10.0.0.1"
    assert result.endpoints[0].protocols == {"ARP", "IPv4", "TCP"}


@pytest.mark.parametrize("data,message", [
    (b"not capture", "uncompressed PCAP or PCAPNG"),
    (pcap([ethernet(ipv4())])[:-1], "invalid or truncated"),
    (section("<", [1])[:-1] + b"\xff", "does not match"),
    (section("<", [1]) + epb("<", 2, ethernet(ipv4())), "unknown interface"),
    (pcap([b"unsupported"], linktype=127), "supported capture link type"),
])
def test_rejects_malformed_and_unsupported_captures(data, message):
    with pytest.raises(capture.CaptureError, match=message):
        capture.discover(BytesIO(data))


def test_bounds_packets_and_endpoint_candidates(monkeypatch):
    monkeypatch.setattr(capture, "MAX_PACKETS", 2)
    monkeypatch.setattr(capture, "MAX_ENDPOINTS", 1)
    packet = ethernet(ipv4())
    result = capture.discover(BytesIO(pcap([packet, packet, packet])))
    assert result.packet_count == 2 and result.truncated
    assert len(result.warnings) == 2
    assert len(result.endpoints) == 1 and result.endpoints[0].packet_count == 2


def override_principal(monkeypatch, role, status=CustomerStatus.ACTIVE):
    principal = TenantPrincipal(
        user=User(role=role),
        customer=Customer(codename="test_capture", status=status),
    )
    monkeypatch.setitem(app.dependency_overrides, current_tenant_user, lambda: principal)


async def test_preview_returns_review_candidates_without_writing(monkeypatch):
    override_principal(monkeypatch, Role.MSSP_ADMIN)

    @asynccontextmanager
    async def session():
        yield object()

    async def existing(_, addresses):
        assert addresses == {"10.0.0.1", "10.0.0.2"}
        return {"10.0.0.2": ("asset-2", "Existing controller")}

    monkeypatch.setattr(assets, "tenant_session", session)
    monkeypatch.setattr(assets, "_existing_capture_assets", existing)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/assets/pcap/preview", files={"file": ("sample.pcap", pcap([ethernet(ipv4())]))},
        )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["packet_count"] == 1
    first, second = data["endpoints"]
    assert first["suggested_name"] == "10.0.0.1" and first["suggested_kind"] == "other"
    assert first["existing_asset_id"] is None
    assert second["existing_asset_id"] == "asset-2"


async def test_preview_checks_permission_before_reading_upload(monkeypatch):
    override_principal(monkeypatch, Role.MSSP_READONLY)

    async def unreadable():
        raise AssertionError("Upload must not be read for a read-only caller.")
        yield

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/assets/pcap/preview", headers={"Content-Type": "multipart/form-data; boundary=demo"},
            content=unreadable(),
        )
    assert response.status_code == 403


@pytest.mark.parametrize("status", [CustomerStatus.ARCHIVED, CustomerStatus.SUSPENDED, CustomerStatus.PROVISIONING])
async def test_discovery_requires_active_environment(monkeypatch, status):
    override_principal(monkeypatch, Role.MSSP_ADMIN, status)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        preview = await client.post("/assets/pcap/preview")
        imported = await client.post(
            "/assets/pcap/import", json={"rows": [{"ip_address": "10.0.0.1", "name": "Controller"}]},
        )
    assert preview.status_code == imported.status_code == 409


async def test_preview_rejects_malformed_capture_and_limits_chunked_upload(monkeypatch):
    override_principal(monkeypatch, Role.MSSP_ADMIN)
    monkeypatch.setattr(capture, "MAX_CAPTURE_BYTES", 64)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        invalid = await client.post("/assets/pcap/preview", files={"file": ("fake.pcap", b"wrong magic")})
        assert invalid.status_code == 422

        async def oversize():
            yield b'--demo\r\nContent-Disposition: form-data; name="file"; filename="oversized.pcap"\r\n\r\n'
            yield b"x" * (65536 + 64)
            yield b"\r\n--demo--\r\n"

        bounded = await client.post(
            "/assets/pcap/preview", headers={"Content-Type": "multipart/form-data; boundary=demo"},
            content=oversize(),
        )
    assert bounded.status_code == 413
