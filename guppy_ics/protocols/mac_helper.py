# Centralized MAC address validation helper
# A valid MAC here means: a unicast host identifier
# (not broadcast, not all-zero, not multicast)

INVALID_MACS = {
    "00:00:00:00:00:00",
    "ff:ff:ff:ff:ff:ff",
}


def is_valid_mac(mac: str | None) -> bool:
    """
    Return True only for unicast, non-placeholder MAC addresses.

    This intentionally rejects:
    - all-zero MACs
    - broadcast MACs
    - multicast MACs (IPv4, IPv6, STP, LLDP, etc.)

    Multicast MAC detection is done by checking the
    least-significant bit of the first octet.
    """
    if not mac:
        return False

    mac = mac.lower()

    # Reject known invalid placeholders
    if mac in INVALID_MACS:
        return False

    try:
        first_octet = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return False

    # Multicast MACs have LSB of first octet set
    # e.g. 01:00:5e:*, 33:33:*, 01:80:c2:*
    if first_octet & 1:
        return False

    return True
