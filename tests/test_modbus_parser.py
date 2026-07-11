import json
from pathlib import Path

from otparse.parsers.modbus import parse_modbus_pcap

FIXTURES = Path(__file__).parent / "fixtures" / "modbus"


def test_diag_session_matches_expected():
    result = parse_modbus_pcap(str(FIXTURES / "modbus_diag_session.pcap"))

    with open(FIXTURES / "modbus_diag_session_expected.json") as f:
        expected = json.load(f)

    assert result.model_dump() == expected
