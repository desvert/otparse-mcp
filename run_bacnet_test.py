import json
from otparse.parsers.bacnet import parse_bacnet_pcap

result = parse_bacnet_pcap("tests/fixtures/bacnet/bacnet_discovery_session.pcap")
with open("tests/fixtures/bacnet/bacnet_discovery_session_expected.json", "w") as f:
    json.dump(result.model_dump(), f, indent=2)
print("Wrote expected fixture.")
