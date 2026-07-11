import json
from otparse.parsers.modbus import parse_modbus_pcap

result = parse_modbus_pcap("tests/fixtures/modbus/modbus_diag_session.pcap")
with open("tests/fixtures/modbus/modbus_diag_session_expected.json", "w") as f:
    json.dump(result.model_dump(), f, indent=2)
print("Wrote expected fixture.")
