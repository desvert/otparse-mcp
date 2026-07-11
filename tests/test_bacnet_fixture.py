import json
from pathlib import Path

from otparse.parsers.bacnet import parse_bacnet_pcap

FIXTURES = Path(__file__).parent / "fixtures" / "bacnet"


def test_discovery_session_matches_expected():
    result = parse_bacnet_pcap(str(FIXTURES / "bacnet_discovery_session.pcap"))

    with open(FIXTURES / "bacnet_discovery_session_expected.json") as f:
        expected = json.load(f)

    assert result.model_dump() == expected
