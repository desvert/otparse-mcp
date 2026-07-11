# otparse-mcp

## Python environment

This project's virtual environment lives at `venv/`. Do not run `source venv/bin/activate`
— it does not persist between tool calls. Instead, invoke the venv's binaries directly:

- Run a script: `venv/bin/python script.py`
- Run tests: `venv/bin/pytest`
- Install a package: `venv/bin/pip install <package>`
- REPL: `venv/bin/python`

## Project setup

Install the package in editable mode before running tests or scripts — `import otparse`
will fail otherwise, even though direct `python script.py` invocation works without it:

    venv/bin/pip install -e .

## Testing conventions

- Fixtures live under `tests/fixtures/<protocol>/` as small, hand-verified PCAP slices
  paired with a `*_expected.json` file (the parser's own verified-correct output, used
  as a regression baseline — not independently hand-typed).
- Before trusting any new PCAP fixture, derive ground truth independently via raw tshark
  field extraction (`tshark -T fields -e ...`), not by reading the parser's own output.
  Always confirm exact field names first with `tshark -G fields | grep -i <protocol>` —
  field names are dissector-version-specific and split across layers (e.g. Modbus:
  `mbtcp.*` vs `modbus.*`; BACnet: `bvlc.*` vs `bacnet.*` (NPDU) vs `bacapp.*` (APDU)).
- Keep fixtures small and hand-verifiable. Large/messy source PCAPs (full multi-thousand
  packet captures) are reserved for a separate stress-test tier, not committed as
  standard regression fixtures. Use `editcap -r <in> <out> <frame-list>` to carve small
  slices out of larger public captures.
- Run the full suite with `venv/bin/pytest tests/ -v`.

## Known limitations

- pyshark's JSON-based dissection omits `invoke_id`/`confirmed_service` fields for
  BACnet Error PDUs (apdu_type=5), even though raw tshark field export has them.
  Documented via a runtime `notes` entry in `parse_bacnet_pcap`, not fixed.

## Code conventions

- Models are pydantic (`otparse/models.py`); prefer adding typed fields there over
  returning loosely-typed dicts.
- Parsers use `_get_attr(layer, *names)` to try multiple possible pyshark attribute
  names — but don't guess new attribute names; introspect first with `dir()` or
  `field_names` on the actual pyshark layer object when uncertain.
