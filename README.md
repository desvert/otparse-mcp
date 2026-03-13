# otparse

A containerized MCP server that parses OT/ICS packet captures and returns structured JSON. Designed to plug into a Claude Code workflow for analyzing saved PCAP files from Modbus/TCP and BACnet/IP networks.

**Status:** [EXPERIMENTAL]

---

## What It Does

`otparse` exposes two MCP tools:

- **`parse_modbus_pcap`** -- reads a saved PCAP file, extracts Modbus/TCP transactions using tshark, and returns decoded frames plus a basic device inventory derived from observed IPs.
- **`parse_bacnet_pcap`** -- reads a saved PCAP file, extracts BACnet/IP packets using tshark, and returns decoded frames plus a basic device inventory derived from observed IPs.

Both tools accept a path to a PCAP inside the container and an optional packet limit. Output is structured JSON that an LLM can reason over directly.

## Background

This grew out of interest in OT/ICS security and the gap between "I have a PCAP from an industrial network" and "I can actually understand what devices were talking to each other and whether anything looks off." Wrapping tshark in an MCP server means Claude can do the first layer of that analysis without a separate toolchain.

The container design follows the same pattern as `netparse`: read-only evidence mount, no outbound network access, non-root user.

## Requirements

- Docker (for the containerized path)
- Or: Python 3.11+, tshark installed on the host (for local dev)

## Setup

### Container (recommended)

```bash
docker build -t otparse-mcp .
```

### Local dev

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

tshark must be available in your PATH for local development.

## Usage

### Run as a containerized MCP server

```bash
docker run --rm -i \
  --network none \
  -v /srv/evidence:/evidence:ro \
  otparse-mcp:latest
```

### Claude Desktop / Claude Code config

```json
{
  "mcpServers": {
    "otparse": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "--network", "none",
        "-v", "/srv/evidence:/evidence:ro",
        "otparse-mcp:latest"
      ]
    }
  }
}
```

### Example tool call

Once connected, ask Claude something like:

> "Parse the Modbus capture at `/evidence/modbus/example.pcap` and summarize what devices were communicating."

Claude will call `parse_modbus_pcap` and work from the returned JSON.

### Run locally (dev only)

```bash
python -m otparse.server
```

## Project Structure

```
otparse/
├── otparse/
│   ├── __init__.py
│   ├── server.py               # FastMCP server, tool definitions
│   ├── models.py               # Pydantic models for all inputs/outputs
│   ├── parsers/
│   │   ├── common.py           # Shared helpers (path validation, tshark check, type coercion)
│   │   ├── modbus.py           # Modbus/TCP parser using pyshark + tshark
│   │   └── bacnet.py           # BACnet/IP parser using pyshark + tshark
│   └── analyzers/
│       └── devices.py          # Builds device inventory from parsed transactions
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
├── requirements.txt
└── README.md
```

## Tool Reference

See [docs/tool-reference.md](./docs/tool-reference.md) for full parameter and output documentation.

## Notes / Limitations

- This tool only analyzes **saved PCAP files**. It does not do live capture.
- tshark does the actual protocol dissection. If a PCAP uses a non-standard port or an unusual encapsulation, tshark may not identify the traffic and the tool will return an empty result with a note.
- Modbus `direction` (request vs. response) detection depends on pyshark exposing the right attributes. Some captures may produce `"unknown"` for most frames.
- The device inventory is derived purely from observed source/destination IPs. It does not correlate with vendor OUIs, DHCP records, or any external data source.
- BACnet device instance numbers and object names are extracted when present, but tshark attribute names vary by version. Some fields may be `null` on older tshark builds.
- `docker-compose.yml` is included for convenience but assumes the repo root layout matches the build context. Adjust `build:` paths if your layout differs.
- Both tools accept an optional `packet_limit` parameter (default: 500) that caps the number of matching packets decoded per run. This limit is in place during early testing and will be removed in a future version. For large captures, increase the limit explicitly when calling the tool.

## Test PCAPs

Sample ICS PCAPs suitable for testing can be found in the [ITI ICS-Security-Tools repository](https://github.com/ITI/ICS-Security-Tools), which maintains a collection of ICS protocol captures for security research.

## Planned

- `extract_ics_devices` tool combining Modbus and BACnet inventory into a single view
- Anomaly heuristics (unusual function codes, broadcast storms, write-heavy sessions)
- Timeline/session summarizer tool
- Fixture PCAPs and parser unit tests

## Changelog

See [CHANGELOG.md](./CHANGELOG.md)