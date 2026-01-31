INVALID_MACS = {
    "00:00:00:00:00:00",
    "ff:ff:ff:ff:ff:ff",
}

def is_valid_mac(mac: str | None) -> bool:
    if not mac:
        return False
    mac = mac.lower()
    return mac not in INVALID_MACS
