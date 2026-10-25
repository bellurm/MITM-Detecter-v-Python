"""ARP table duplicate-MAC heuristic; this cannot confirm or exclude a MITM attack."""
import ipaddress
import re
import subprocess
from collections import defaultdict

def duplicate_macs(arp_text):
    entries = defaultdict(set)
    for line in arp_text.splitlines():
        ip_match = re.search(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", line)
        mac_match = re.search(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])", line)
        if not ip_match or not mac_match:
            continue
        try:
            address = ipaddress.IPv4Address(ip_match.group())
        except ValueError:
            continue
        mac = mac_match.group().lower().replace("-", ":")
        # Multicast/broadcast entries are normal and do not identify a host.
        if int(mac[:2], 16) & 1 or mac == "00:00:00:00:00:00":
            continue
        entries[mac].add(str(address))
    return {mac: sorted(addresses) for mac, addresses in entries.items() if len(addresses) > 1}

def main():
    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True, check=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"Cannot read ARP table: {exc}")
        return 1
    duplicates = duplicate_macs(result.stdout)
    if not duplicates:
        print("No duplicate unicast MAC entries observed. This is not proof of network safety.")
    for mac, addresses in duplicates.items():
        print(f"Review {mac}: {', '.join(addresses)}. Proxy ARP, routing or other normal behavior may explain this; MITM is not confirmed.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
