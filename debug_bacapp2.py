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
        if hasattr(bacapp, "objectidentifier"):
            oid = bacapp.objectidentifier
            print("objectidentifier repr:", repr(oid))
            print("objectidentifier str:", str(oid))
        if hasattr(bacapp, "property_identifier"):
            pid = bacapp.property_identifier
            print("property_identifier type:", type(pid))
            print("property_identifier dir:", [a for a in dir(pid) if not a.startswith("_")])
        if hasattr(bacapp, "confirmed_service"):
            print("confirmed_service:", bacapp.confirmed_service)
        print()
capture.close()
