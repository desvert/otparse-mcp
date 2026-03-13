from __future__ import annotations

from collections.abc import Iterable

import pyshark

from otparse.analyzers.devices import inventory_from_modbus
from otparse.models import ModbusParseResult, ModbusTransaction, ToolMetadata
from otparse.parsers.common import ensure_tshark, safe_int, safe_str, validate_pcap_path

FUNCTION_NAMES = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    22: "Mask Write Register",
    23: "Read/Write Multiple Registers",
    24: "Read FIFO Queue",
    43: "Encapsulated Interface Transport",
}


def _get_attr(layer: object, *names: str) -> object | None:
    for name in names:
        if hasattr(layer, name):
            return getattr(layer, name)
    return None


def parse_modbus_pcap(pcap_path: str, packet_limit: int = 500) -> ModbusParseResult:
    """Parse Modbus/TCP traffic from a PCAP file."""
    ensure_tshark()
    path = validate_pcap_path(pcap_path)

    capture = pyshark.FileCapture(
        str(path),
        display_filter="modbus",
        keep_packets=False,
        use_json=True,
        include_raw=False,
        tshark_path="tshark",
    )

    transactions: list[ModbusTransaction] = []
    notes: list[str] = []
    packet_count = 0

    try:
        for packet in capture:
            packet_count += 1
            if packet_count > packet_limit:
                notes.append(f"Stopped after packet_limit={packet_limit} matching packets.")
                break

            modbus = getattr(packet, "modbus", None)
            ip = getattr(packet, "ip", None)
            tcp = getattr(packet, "tcp", None)
            if modbus is None:
                continue

            function_code = safe_int(_get_attr(modbus, "func_code", "function_code"))
            function_name = FUNCTION_NAMES.get(function_code or -1) or safe_str(
                _get_attr(modbus, "func_code", "function_code")
            )
            if function_name and function_name.isdigit() and function_code in FUNCTION_NAMES:
                function_name = FUNCTION_NAMES[function_code]

            raw_data = _get_attr(modbus, "data", "regval_uint16", "regnum16")
            data_values: list[int] = []
            if raw_data is not None:
                if isinstance(raw_data, Iterable) and not isinstance(raw_data, (str, bytes)):
                    for item in raw_data:
                        parsed = safe_int(item)
                        if parsed is not None:
                            data_values.append(parsed)
                else:
                    parsed = safe_int(raw_data)
                    if parsed is not None:
                        data_values.append(parsed)

            direction = "unknown"
            request_flag = safe_str(_get_attr(modbus, "request"))
            response_flag = safe_str(_get_attr(modbus, "response"))
            if request_flag is not None:
                direction = "request"
            elif response_flag is not None:
                direction = "response"

            transactions.append(
                ModbusTransaction(
                    frame_number=int(packet.number),
                    timestamp=str(packet.sniff_time.isoformat()),
                    src_ip=safe_str(getattr(ip, "src", None)),
                    dst_ip=safe_str(getattr(ip, "dst", None)),
                    src_port=safe_int(getattr(tcp, "srcport", None)),
                    dst_port=safe_int(getattr(tcp, "dstport", None)),
                    transaction_id=safe_int(_get_attr(modbus, "trans_id", "transaction_id")),
                    unit_id=safe_int(_get_attr(modbus, "unit_id")),
                    function_code=function_code,
                    function_name=function_name,
                    reference_number=safe_int(_get_attr(modbus, "reference_num", "reference_number")),
                    word_count=safe_int(_get_attr(modbus, "word_cnt", "word_count")),
                    bit_count=safe_int(_get_attr(modbus, "bit_cnt", "bit_count")),
                    data=data_values,
                    raw_summary=safe_str(getattr(packet, "highest_layer", None)),
                    direction=direction,
                )
            )
    finally:
        capture.close()

    if not transactions:
        notes.append("No Modbus packets were decoded by tshark. The capture may not contain Modbus/TCP or tshark may lack the needed dissector.")

    return ModbusParseResult(
        metadata=ToolMetadata(pcap_path=str(path), packet_count=packet_count, notes=notes),
        transactions=transactions,
    )


def parse_modbus_with_inventory(pcap_path: str, packet_limit: int = 500) -> dict:
    result = parse_modbus_pcap(pcap_path=pcap_path, packet_limit=packet_limit)
    inventory = inventory_from_modbus(result.transactions)
    return {
        "result": result.model_dump(),
        "device_inventory": inventory.model_dump(),
    }
