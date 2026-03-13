from __future__ import annotations

from collections import defaultdict

from otparse.models import BacnetPacket, DeviceInventory, DeviceRecord, ModbusTransaction


def inventory_from_modbus(transactions: list[ModbusTransaction]) -> DeviceInventory:
    table: dict[str, dict[str, set]] = defaultdict(lambda: {"protocols": set(), "ports": set(), "hints": set()})
    for tx in transactions:
        for ip, port, role in ((tx.src_ip, tx.src_port, "modbus_client"), (tx.dst_ip, tx.dst_port, "modbus_server")):
            if not ip:
                continue
            row = table[ip]
            row["protocols"].add("modbus")
            if port:
                row["ports"].add(int(port))
            row["hints"].add(role)
    return DeviceInventory(
        devices=[
            DeviceRecord(
                ip=ip,
                protocols=sorted(info["protocols"]),
                ports=sorted(info["ports"]),
                hints=sorted(info["hints"]),
            )
            for ip, info in sorted(table.items())
        ]
    )


def inventory_from_bacnet(packets: list[BacnetPacket]) -> DeviceInventory:
    table: dict[str, dict[str, set]] = defaultdict(lambda: {"protocols": set(), "ports": set(), "hints": set()})
    for pkt in packets:
        for ip, port, role in ((pkt.src_ip, pkt.src_port, "bacnet_sender"), (pkt.dst_ip, pkt.dst_port, "bacnet_listener")):
            if not ip:
                continue
            row = table[ip]
            row["protocols"].add("bacnet")
            if port:
                row["ports"].add(int(port))
            row["hints"].add(role)
            if pkt.service:
                row["hints"].add(pkt.service)
    return DeviceInventory(
        devices=[
            DeviceRecord(
                ip=ip,
                protocols=sorted(info["protocols"]),
                ports=sorted(info["ports"]),
                hints=sorted(info["hints"]),
            )
            for ip, info in sorted(table.items())
        ]
    )
