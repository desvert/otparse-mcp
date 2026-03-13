# Changelog

## [0.1.0]] — 2026-03-12

### Added
- `parse_modbus_pcap` MCP tool: parses Modbus/TCP transactions from saved PCAPs using tshark/pyshark, returns decoded frames and device inventory
- `parse_bacnet_pcap` MCP tool: parses BACnet/IP packets from saved PCAPs using tshark/pyshark, returns decoded frames and device inventory
- `DeviceInventory` builder for both protocols: derives IP, port, protocol, and role data from observed traffic
- Pydantic models for all inputs and outputs (`ModbusTransaction`, `BacnetPacket`, `DeviceRecord`, `DeviceInventory`, `ToolMetadata`, `ErrorResult`)
- Shared parser utilities in `common.py`: path validation, tshark availability check, safe type coercion helpers
- Dockerfile: Python 3.12 slim base, tshark install, non-root `mcpuser`
- `docker-compose.yml`: container config with `network_mode: none` and read-only evidence mount
- `pyproject.toml` with explicit package discovery and `otparse` entry point
- Initial README and tool reference docs