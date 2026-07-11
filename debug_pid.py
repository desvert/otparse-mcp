import pyshark

capture = pyshark.FileCapture(
    "tests/fixtures/bacnet/bacnet_discovery_session.pcap",
    display_filter="bacapp",
    use_json=True,
)

for packet in capture:
    if hasattr(packet, "bacapp"):
        bacapp = packet.bacapp
        if hasattr(bacapp, "property_identifier"):
            pid = bacapp.property_identifier
            print(f"--- Frame {packet.number} ---")
            print("value attr:", repr(getattr(pid, "value", "NO VALUE ATTR")))
            print("get('property_identifier'):", pid.get("property_identifier"))
            print("main_field:", pid.main_field.show if hasattr(pid, "main_field") else "n/a")
            print()
capture.close()
