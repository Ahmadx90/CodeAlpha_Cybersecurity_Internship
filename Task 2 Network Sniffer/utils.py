from scapy.all import Raw
from scapy.all import TCP, UDP, ICMP

def protocol_name(proto_num: int) -> str:
    # basic mapping
    return {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto_num, f"OTHER({proto_num})")

def pretty_payload(pkt) -> str:
    """
    Return a full printable representation of payload if present.
    - For text: Decoded as UTF-8 with replacements.
    - For binary: Formatted hex dump with spaces.
    - No truncation for complete display.
    """
    # Try Raw payload first
    raw = None
    if Raw in pkt:
        raw = bytes(pkt[Raw].load)
    else:
        # For some layers, payload is in layer.payload
        try:
            pl = pkt.payload
            if hasattr(pl, "original"):
                raw = bytes(pl.original)
        except Exception:
            raw = None

    if not raw:
        return "<no-payload>"

    # Try to decode as utf-8
    try:
        text = raw.decode("utf-8", errors="replace")
        # Preserve newlines for readability
        return text
    except Exception:
        # Formatted hex: 'xx xx xx ...'
        hex_formatted = ' '.join(f"{b:02x}" for b in raw)
        return hex_formatted