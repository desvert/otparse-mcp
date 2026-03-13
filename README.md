# otparse

`otparse` is a containerized MCP server for parsing OT/ICS packet captures. This first cut exposes two tools:

- `parse_modbus_pcap`
- `parse_bacnet_pcap`

The design follows the same container-first pattern you used for `netparse`, so the server can run with a read-only evidence mount and no network access.

## Why this shape

This is the practical MVP:

- Use `tshark` for protocol dissection instead of reinventing BACnet and Modbus parsing from raw bytes
- Wrap that parsing in a small MCP server
- Return structured JSON that an LLM can reason over
- Keep the container locked down with `network_mode: none`

## Tools

### `parse_modbus_pcap`

Inputs:
- `pcap_path`: path to a capture file inside the container, such as `/evidence/modbus/example.pcap`
- `packet_limit`: optional ceiling for decoded packets

Returns:
- decoded Modbus/TCP transactions
- basic device inventory derived from source and destination IPs

### `parse_bacnet_pcap`

Inputs:
- `pcap_path`: path to a capture file inside the container, such as `/evidence/bacnet/example.pcap`
- `packet_limit`: optional ceiling for decoded packets

Returns:
- decoded BACnet/IP packets
- basic device inventory derived from source and destination IPs

## Build

```bash
docker build -t otparse-mcp .
```

## Run as a containerized MCP server

```bash
docker run --rm -i \
  --network none \
  -v /srv/evidence:/evidence:ro \
  otparse-mcp:latest
```

## Claude Desktop style MCP config example

```json
{
  "mcpServers": {
    "otparse": {
      "command": "docker",
      "args": [
        "run",
        "--rm",
        "-i",
        "--network",
        "none",
        "-v",
        "/srv/evidence:/evidence:ro",
        "otparse-mcp:latest"
      ]
    }
  }
}
```

## Local dev

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m otparse.server
```

You still need `tshark` installed on the host for local development.

## Notes about the sample PCAP source

You mentioned using PCAPs from the ITI `ICS-Security-Tools` repository. That repo includes a `pcaps/` area intended for ICS security exploration, which makes it a reasonable source for test captures. The repository describes itself as a community asset for ICS security tools, guides, protocols, and PCAP files. citeturn0view0turn1view2

## Next good additions

- add a combined `extract_ics_devices` tool
- add anomaly heuristics for writes, scans, and unusual BACnet services
- add a timeline/summarizer tool
- add small fixture PCAPs and parser tests
