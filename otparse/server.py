from __future__ import annotations

import asyncio

from mcp.server.fastmcp import FastMCP

from otparse.parsers.bacnet import parse_bacnet_with_inventory
from otparse.parsers.modbus import parse_modbus_with_inventory

mcp = FastMCP("otparse")


@mcp.tool()
async def parse_modbus_pcap(pcap_path: str, packet_limit: int = 500) -> dict:
    """Parse Modbus/TCP traffic from a PCAP and return transactions plus a basic device inventory."""
    return await asyncio.to_thread(parse_modbus_with_inventory, pcap_path=pcap_path, packet_limit=packet_limit)


@mcp.tool()
async def parse_bacnet_pcap(pcap_path: str, packet_limit: int = 500) -> dict:
    """Parse BACnet/IP traffic from a PCAP and return decoded packets plus a basic device inventory."""
    return await asyncio.to_thread(parse_bacnet_with_inventory, pcap_path=pcap_path, packet_limit=packet_limit)


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
