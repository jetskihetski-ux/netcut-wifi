import json
import os

_FILE = os.path.join(os.path.dirname(__file__), "custom_names.json")
_data: dict[str, str] = {}


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


def get(mac: str) -> str:
    return _data.get(mac.lower(), "")


def set_name(mac: str, name: str) -> None:
    _data[mac.lower()] = name.strip()
    _save()


def clear(mac: str) -> None:
    _data.pop(mac.lower(), None)
    _save()
