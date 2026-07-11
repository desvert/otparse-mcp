import pyshark

capture = pyshark.FileCapture(
    "tests/fixtures/bacnet/bacnet_discovery_session.pcap",
    display_filter="bacapp",
    use_json=True,
)

for packet in capture:
    if hasattr(packet, "bacapp"):
        bacapp = packet.bacapp
        print(f"--- Frame {packet.number} ---")
        print("field_names:", bacapp.field_names)
        print()
capture.close()
