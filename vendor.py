import subprocess
import re

# OUI (first 8 chars of MAC: xx:xx:xx) -> (emoji, friendly label)
OUI_MAP = {
    # Sony / PlayStation
    "a8:8f:d9": ("🎮", "PlayStation"),
    "00:04:1f": ("🎮", "PlayStation"),
    "00:13:a9": ("🎮", "PlayStation"),
    "00:15:c1": ("🎮", "PlayStation"),
    "00:1d:0d": ("🎮", "PlayStation"),
    "00:1f:a7": ("🎮", "PlayStation"),
    "00:24:8d": ("🎮", "PlayStation"),
    "28:37:37": ("🎮", "PlayStation"),
    "70:66:55": ("🎮", "PlayStation"),
    "ac:9b:0a": ("🎮", "PlayStation"),
    "bc:60:a7": ("🎮", "PlayStation"),
    # Microsoft / Xbox
    "28:18:78": ("🎮", "Xbox"),
    "7c:1e:52": ("🎮", "Xbox"),
    "98:5f:d3": ("🎮", "Xbox"),
    "00:17:fa": ("🎮", "Xbox"),
    # Nintendo
    "00:1a:e9": ("🎮", "Nintendo Switch"),
    "98:b6:e9": ("🎮", "Nintendo Switch"),
    "00:17:ab": ("🎮", "Nintendo"),
    "00:19:fd": ("🎮", "Nintendo"),
    "00:22:d7": ("🎮", "Nintendo"),
    "00:24:44": ("🎮", "Nintendo"),
    # Apple iPhone / iPad
    "00:1b:63": ("📱", "iPhone"),
    "00:1c:b3": ("📱", "iPhone"),
    "00:23:12": ("📱", "iPhone"),
    "00:26:b9": ("📱", "iPhone"),
    "3c:07:54": ("📱", "iPhone"),
    "78:7b:8a": ("📱", "iPhone"),
    "a4:5e:60": ("📱", "iPhone"),
    "f0:d1:a9": ("📱", "iPhone"),
    "8c:85:90": ("📱", "iPhone"),
    "dc:2b:2a": ("📱", "iPhone"),
    "f4:f1:5a": ("📱", "iPhone"),
    # Apple MacBook / Mac
    "00:17:f2": ("💻", "MacBook"),
    "00:1f:5b": ("💻", "MacBook"),
    "00:21:e9": ("💻", "MacBook"),
    "60:fb:42": ("💻", "MacBook"),
    "88:66:5a": ("💻", "MacBook"),
    # Samsung Phone
    "00:15:99": ("📱", "Samsung Phone"),
    "2c:54:cf": ("📱", "Samsung Phone"),
    "78:52:1a": ("📱", "Samsung Phone"),
    "bc:20:a4": ("📱", "Samsung Phone"),
    "e4:7c:f9": ("📱", "Samsung Phone"),
    "8c:71:f8": ("📱", "Samsung Phone"),
    "cc:f9:e8": ("📱", "Samsung Phone"),
    # Samsung TV
    "00:16:32": ("📺", "Samsung TV"),
    "8c:77:12": ("📺", "Samsung TV"),
    "f4:7b:5e": ("📺", "Samsung TV"),
    # LG TV
    "00:1e:75": ("📺", "LG TV"),
    "a8:23:fe": ("📺", "LG TV"),
    "cc:2d:8c": ("📺", "LG TV"),
    "78:5d:c8": ("📺", "LG TV"),
    # Amazon
    "40:b4:cd": ("📦", "Amazon Device"),
    "68:37:e9": ("📺", "Fire TV"),
    "74:c2:46": ("🔊", "Echo"),
    "fc:a6:67": ("🔊", "Echo"),
    "50:f5:da": ("📺", "Fire TV"),
    # Google / Chromecast
    "54:60:09": ("🔊", "Google Home"),
    "f4:f5:d8": ("📱", "Google Pixel"),
    "48:d6:d5": ("📺", "Chromecast"),
    "6c:ad:f8": ("📺", "Chromecast"),
    # Raspberry Pi
    "b8:27:eb": ("🖥️", "Raspberry Pi"),
    "dc:a6:32": ("🖥️", "Raspberry Pi"),
    "e4:5f:01": ("🖥️", "Raspberry Pi"),
    # TP-Link
    "14:cc:20": ("📡", "TP-Link Router"),
    "50:c7:bf": ("📡", "TP-Link Router"),
    "ec:08:6b": ("📡", "TP-Link Router"),
    "c4:e9:84": ("📡", "TP-Link Router"),
    # Netgear
    "a0:04:60": ("📡", "Netgear Router"),
    "20:e5:2a": ("📡", "Netgear Router"),
    # ASUS Router
    "00:1a:92": ("📡", "ASUS Router"),
    "04:d9:f5": ("📡", "ASUS Router"),
    "2c:fd:a1": ("📡", "ASUS Router"),
    # Huawei Phone
    "00:e0:fc": ("📱", "Huawei Phone"),
    "04:f9:38": ("📱", "Huawei Phone"),
    "28:6e:d4": ("📱", "Huawei Phone"),
    # Xiaomi Phone
    "00:9e:c8": ("📱", "Xiaomi Phone"),
    "64:09:80": ("📱", "Xiaomi Phone"),
    "d4:97:0b": ("📱", "Xiaomi Phone"),
    "f8:a4:5f": ("📱", "Xiaomi Phone"),
    # OnePlus
    "ac:37:43": ("📱", "OnePlus Phone"),
}

# When API returns a company name, map keywords -> (emoji, label)
_COMPANY_MAP = [
    (["sony", "playstation"],                  "🎮", "PlayStation"),
    (["apple"],                                 "📱", "Apple Device"),
    (["samsung electronics"],                   "📱", "Samsung Phone"),
    (["samsung"],                               "📱", "Samsung Device"),
    (["microsoft"],                             "💻", "Windows PC"),
    (["xbox"],                                  "🎮", "Xbox"),
    (["nintendo"],                              "🎮", "Nintendo"),
    (["amazon"],                                "📦", "Amazon Device"),
    (["google"],                                "📱", "Google Device"),
    (["huawei"],                                "📱", "Huawei Phone"),
    (["xiaomi"],                                "📱", "Xiaomi Phone"),
    (["oppo"],                                  "📱", "OPPO Phone"),
    (["oneplus"],                               "📱", "OnePlus Phone"),
    (["lg electronics"],                        "📺", "LG TV"),
    (["tp-link", "tp link"],                    "📡", "TP-Link Router"),
    (["netgear"],                               "📡", "Netgear Router"),
    (["asus"],                                  "💻", "ASUS Device"),
    (["raspberry pi"],                          "🖥️", "Raspberry Pi"),
    (["intel"],                                 "💻", "Laptop / PC"),
    (["qualcomm"],                              "📱", "Android Phone"),
    (["realtek"],                               "💻", "Windows PC"),
    (["broadcom"],                              "💻", "Laptop / PC"),
    (["mediatek"],                              "📱", "Android Phone"),
    (["espressif"],                             "🔌", "Smart Device"),
    (["tuya"],                                  "🔌", "Smart Device"),
]

_cache: dict[str, tuple] = {}


def _api_lookup(mac: str) -> str:
    try:
        import requests
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
        return r.text.strip() if r.status_code == 200 else ""
    except Exception:
        return ""


def _company_to_info(company: str) -> tuple:
    c = company.lower()
    for keywords, emoji, label in _COMPANY_MAP:
        if any(k in c for k in keywords):
            return emoji, label
    return "🖥️", company[:28]   # show company name if no match, trimmed


def get_device_info(mac: str, hostname: str = "") -> tuple:
    """Return (emoji, display_name) for a device."""

    # 1. Local OUI table — fastest and most accurate
    oui = mac[:8].lower()
    if oui in OUI_MAP:
        return OUI_MAP[oui]

    # 2. Hostname hints — often most descriptive
    if hostname and hostname not in ("", mac):
        h = hostname.lower()
        if any(x in h for x in ("iphone", "ipad")):         return "📱", "iPhone"
        if "macbook" in h:                                   return "💻", "MacBook"
        if any(x in h for x in ("android", "pixel")):       return "📱", "Android Phone"
        if any(x in h for x in ("ps4", "ps5", "playstation")): return "🎮", "PlayStation"
        if "xbox" in h:                                      return "🎮", "Xbox"
        if any(x in h for x in ("switch", "nintendo")):     return "🎮", "Nintendo Switch"
        if any(x in h for x in ("tv", "roku", "firetv", "appletv")): return "📺", "Smart TV"
        if any(x in h for x in ("laptop", "notebook")):     return "💻", "Laptop"
        if any(x in h for x in ("desktop", "pc", "imac")):  return "🖥️", "Desktop PC"
        if any(x in h for x in ("echo", "alexa")):          return "🔊", "Echo"
        if any(x in h for x in ("printer", "hp", "canon", "epson")): return "🖨️", "Printer"
        return "🖥️", hostname

    # 3. API lookup (cached)
    if mac not in _cache:
        company = _api_lookup(mac)
        _cache[mac] = _company_to_info(company) if company else ("🖥️", "Unknown Device")
    return _cache[mac]
