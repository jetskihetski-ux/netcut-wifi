import json
import os

_FILE = os.path.join(os.path.dirname(__file__), "favorites.json")
_data: dict[str, dict] = {}   # mac -> {ip, mac, hostname}


def _load() -> None:
    global _data
    try:
        with open(_FILE) as f:
            _data = json.load(f)
    except Exception:
        _data = {}


def _save() -> None:
    with open(_FILE, "w") as f:
        json.dump(_data, f, indent=2)


_load()


def is_favorite(mac: str) -> bool:
    return mac.lower() in _data


def add(dev: dict) -> None:
    _data[dev["mac"].lower()] = {
        "ip":       dev["ip"],
        "mac":      dev["mac"].lower(),
        "hostname": dev.get("hostname", ""),
    }
    _save()


def remove(mac: str) -> None:
    _data.pop(mac.lower(), None)
    _save()


def all_favorites() -> list[dict]:
    return list(_data.values())
