from __future__ import annotations

import pyshark

from otparse.analyzers.devices import inventory_from_bacnet
from otparse.models import BacnetPacket, BacnetParseResult, ToolMetadata
from otparse.parsers.common import ensure_tshark, safe_int, safe_str, validate_pcap_path


def _get_attr(layer: object, *names: str) -> object | None:
    for name in names:
        if hasattr(layer, name):
            return getattr(layer, name)
    return None


def parse_bacnet_pcap(pcap_path: str, packet_limit: int = 500) -> BacnetParseResult:
    """Parse BACnet/IP traffic from a PCAP file."""
    ensure_tshark()
    path = validate_pcap_path(pcap_path)

    capture = pyshark.FileCapture(
        str(path),
        display_filter="bacnet or bvlc",
        keep_packets=False,
        use_json=True,
        include_raw=False,
        tshark_path="tshark",
    )

    packets: list[BacnetPacket] = []
    notes: list[str] = []
    packet_count = 0

    try:
        for packet in capture:
            packet_count += 1
            if packet_count > packet_limit:
                notes.append(f"Stopped after packet_limit={packet_limit} matching packets.")
                break

            bacnet = getattr(packet, "bacnet", None)
            bvlc = getattr(packet, "bvlc", None)
            bacapp = getattr(packet, "bacapp", None)
            ip = getattr(packet, "ip", None)
            udp = getattr(packet, "udp", None)
            if bacnet is None and bvlc is None and bacapp is None:
                continue

# Added from here
            apdu_type = safe_str(_get_attr(bacapp, "type"))
            service = safe_str(_get_attr(bacapp, "confirmed_service", "unconfirmed_service"))
            invoke_id = safe_int(_get_attr(bacapp, "invoke_id"))
# to here

            object_type = None
            object_instance = None
            oid = _get_attr(bacapp, "objectidentifier")
            if oid is not None:
                object_type = safe_int(getattr(oid, "objectType", None))
                object_instance = safe_int(getattr(oid, "instance_number", None))

            property_identifier = None
            pid = _get_attr(bacapp, "property_identifier")
            if pid is not None:
                property_identifier = safe_int(pid.get("property_identifier"))

# and added this block
            if apdu_type == "5" and (invoke_id is None or service is None):
                notes.append(
                    f"Frame {packet.number}: Error PDU is missing invoke_id/service due to a "
                    "known pyshark JSON-dissection limitation (raw tshark field export still "
                    "has these values; pyshark's field_names omits them for apdu_type=5)."
                )

            packets.append(
                BacnetPacket(
                    frame_number=int(packet.number),
                    timestamp=str(packet.sniff_time.isoformat()),
                    src_ip=safe_str(getattr(ip, "src", None)),
                    dst_ip=safe_str(getattr(ip, "dst", None)),
                    src_port=safe_int(getattr(udp, "srcport", None)),
                    dst_port=safe_int(getattr(udp, "dstport", None)),
                    bvlc_function=safe_str(_get_attr(bvlc, "function", "func")),
                    npdu_control=safe_str(_get_attr(bacnet, "control", "npdu_control")),
                    apdu_type=apdu_type,
                    service=service,
                    invoke_id=invoke_id,
                    object_type=object_type,
                    object_instance=object_instance,
                    property_identifier=property_identifier,
                    error_class=safe_int(_get_attr(bacapp, "error_class")),
                    error_code=safe_int(_get_attr(bacapp, "error_code")),
                    raw_summary=safe_str(getattr(packet, "highest_layer", None)),
                )
            )
    finally:
        capture.close()

    if not packets:
        notes.append("No BACnet packets were decoded by tshark. The capture may not contain BACnet/IP or tshark may lack the needed dissector.")

    return BacnetParseResult(
        metadata=ToolMetadata(pcap_path=str(path), packet_count=packet_count, notes=notes),
        packets=packets,
    )


def parse_bacnet_with_inventory(pcap_path: str, packet_limit: int = 500) -> dict:
    result = parse_bacnet_pcap(pcap_path=pcap_path, packet_limit=packet_limit)
    inventory = inventory_from_bacnet(result.packets)
    return {
        "result": result.model_dump(),
        "device_inventory": inventory.model_dump(),
    }
