# Changelog

## [0.1.1] — 2026-07-11

### Added

- `tests/fixtures/modbus/` and `tests/fixtures/bacnet/` — small, hand-verified PCAP fixtures with matching expected-output JSON, used as regression baselines
- `tests/test_modbus_parser.py` and `tests/test_bacnet_parser.py`
- `diagnostic_subfunction`, `diagnostic_subfunction_name`, `exception_code`, `exception_name` fields on `ModbusTransaction`
- `error_class`, `error_code` fields on `BacnetPacket`
- `CLAUDE.md`: documents venv usage, testing conventions, and known limitations for future development sessions

### Fixed

- `parse_modbus_pcap`: `unit_id` and `transaction_id` were read from the wrong tshark layer (`modbus` instead of `mbtcp`) and always returned `null`
- `parse_modbus_pcap`: function code 8 (Diagnostics) was missing from `FUNCTION_NAMES`, so `function_name` returned the raw numeric code instead of a label
- `parse_modbus_pcap`: `direction` was always `"unknown"` (checked nonexistent attributes) and, after an initial fix, still misreported exception responses as `"request"`
- `parse_bacnet_pcap`: the `bacapp` (APDU) layer was never fetched, so `apdu_type`, `service`, `invoke_id`, `object_type`, `object_instance`, and `property_identifier` were all `null` regardless of actual packet content
- `parse_bacnet_pcap`: `object_type`/`object_instance` are nested under a `bacapp.objectidentifier` sub-layer in pyshark, not top-level `bacapp` attributes
- `parse_bacnet_pcap`: `property_identifier` returned a garbled nested-object string dump instead of the scalar value; now correctly extracted via the layer's `.get()` accessor

### Known limitations

- `parse_bacnet_pcap`: pyshark's JSON-based dissection omits `invoke_id`/`confirmed_service` for BACnet Error PDUs (`apdu_type=5`), even though raw tshark field export has both values. Documented via a runtime `notes` entry rather than fixed, pending a possible future switch to raw XML/PDML-based extraction.

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
