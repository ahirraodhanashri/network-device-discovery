"""MAC address -> manufacturer lookup using the OUI (first 3 bytes of the MAC).

Lookup order:
  1. Locally-administered bit set  -> "Randomized / private MAC" (phones do this for privacy)
  2. backend/data/oui.csv          -> optional full list ("AA:BB:CC,Vendor Name"), see README
  3. Scapy's bundled manufacturer database (large, ships with Scapy)
  4. A tiny built-in fallback table (only a handful of well-known prefixes)
"""
import csv
import re
from functools import lru_cache
from pathlib import Path

OUI_FILE = Path(__file__).resolve().parent / "data" / "oui.csv"

FALLBACK = {
    "00:0c:29": "VMware, Inc.",
    "00:50:56": "VMware, Inc.",
    "00:15:5d": "Microsoft (Hyper-V)",
    "08:00:27": "Oracle VirtualBox",
    "b8:27:eb": "Raspberry Pi Foundation",
    "dc:a6:32": "Raspberry Pi Trading",
    "e4:5f:01": "Raspberry Pi Trading",
}


def is_locally_administered(mac):
    """Bit 1 of the first octet: set => address was assigned by software, not the manufacturer."""
    return bool(int(mac.split(":")[0], 16) & 0b10)


@lru_cache(maxsize=1)
def _load_file_table():
    table = {}
    if OUI_FILE.exists():
        with OUI_FILE.open(newline="", encoding="utf-8") as fh:
            for row in csv.reader(fh):
                if len(row) >= 2 and re.match(r"^[0-9a-fA-F:.-]{6,8}$", row[0].strip()):
                    prefix = re.sub(r"[^0-9a-f]", "", row[0].lower())[:6]
                    table[prefix] = row[1].strip()
    return table


def _scapy_lookup(mac):
    try:
        from scapy.all import conf  # type: ignore
        db = conf.manufdb
        if hasattr(db, "lookup"):
            short, long_name = db.lookup(mac)
            name = long_name or short
        else:
            name = db._get_manuf(mac)
        if name and name.lower() != mac.lower():
            return name
    except Exception:
        pass
    return None


def lookup_vendor(mac):
    """Return a manufacturer string for a MAC, or None when unknown."""
    if not mac:
        return None
    mac = mac.lower().replace("-", ":")
    if not re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", mac):
        return None
    if is_locally_administered(mac):
        return "Randomized / private MAC"
    prefix = mac.replace(":", "")[:6]
    return _load_file_table().get(prefix) or _scapy_lookup(mac) or FALLBACK.get(mac[:8])
