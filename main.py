import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading
import customtkinter as ctk

from network import get_subnet, get_gateway_ip, get_mac, scan_network, get_local_ip, get_interfaces
from spoofer import ARPSpoofer
from vendor import get_device_info
import names as namestore

ctk.set_appearance_mode("dark")

BG     = "#0d0d1a"
BAR    = "#16213e"
ACCENT = "#6C63FF"
RED    = "#FF5252"
GREEN  = "#4CAF50"


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("dz_solutions")
        self.geometry("780x520")
        self.configure(fg_color=BG)
        self.resizable(True, True)

        self._devices       = []
        self._gateway_ip    = None
        self._gateway_mac   = None
        self._timers:  dict[str, str] = {}
        self._delay_timers: dict[str, str] = {}
        self._iface         = None

        self._build()   # sets self._iface from interface picker

        # init spoofer AFTER build so it picks up the selected interface
        self._spoofer = ARPSpoofer(iface=self._iface)
        self._init_network()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build(self):
        # ── top bar ──
        top = ctk.CTkFrame(self, fg_color=BAR, corner_radius=0, height=54)
        top.pack(fill="x")
        top.pack_propagate(False)

        ctk.CTkLabel(top, text="dz_solutions",
                     font=ctk.CTkFont("Segoe UI", 20, "bold"),
                     text_color="white").pack(side="left", padx=20)

        self._scan_btn = ctk.CTkButton(
            top, text="⟳  Scan Network",
            fg_color=ACCENT, hover_color="#5550CC",
            font=ctk.CTkFont("Segoe UI", 12, "bold"),
            width=140, height=34,
            command=self._scan,
        )
        self._scan_btn.pack(side="right", padx=16, pady=10)

        # ── Interface picker ──
        ifaces = get_interfaces()
        self._iface_map = {f"{i['kind']} — {i['ip']}": i["name"] for i in ifaces} if ifaces else {}
        iface_labels    = list(self._iface_map.keys()) or ["No interfaces found"]

        self._iface_var = tk.StringVar(value=iface_labels[0])
        self._iface_menu = ctk.CTkOptionMenu(
            top,
            variable   = self._iface_var,
            values     = iface_labels,
            fg_color   = "#1e1e3a",
            button_color = ACCENT,
            button_hover_color = "#5550CC",
            font       = ctk.CTkFont("Segoe UI", 11),
            width      = 220,
            height     = 34,
            command    = self._on_iface_change,
        )
        self._iface_menu.pack(side="right", padx=(0, 6), pady=10)

        ctk.CTkLabel(top, text="Interface:",
                     font=ctk.CTkFont("Segoe UI", 11),
                     text_color="#888").pack(side="right", padx=(8, 2))

        # set initial interface
        if ifaces:
            self._iface = ifaces[0]["name"]

        self._gw_label = ctk.CTkLabel(
            top, text="Gateway: detecting...",
            font=ctk.CTkFont("Segoe UI", 11),
            text_color="#666",
        )
        self._gw_label.pack(side="left", padx=12)

        # ── search bar ──
        search_bar = ctk.CTkFrame(self, fg_color=BAR, corner_radius=6, height=40)
        search_bar.pack(fill="x", padx=10, pady=(6, 0))
        search_bar.pack_propagate(False)

        ctk.CTkLabel(search_bar, text="🔍",
                     font=ctk.CTkFont("Segoe UI", 14)).pack(side="left", padx=(10, 4))

        self._search_var = tk.StringVar()
        ctk.CTkEntry(
            search_bar,
            textvariable=self._search_var,
            placeholder_text="Filter by name, IP, or MAC…",
            font=ctk.CTkFont("Segoe UI", 12),
            fg_color="#0d0d1a",
            border_width=0,
            height=30,
        ).pack(side="left", fill="x", expand=True, padx=(0, 4), pady=5)

        ctk.CTkButton(
            search_bar, text="✕", width=28, height=28,
            fg_color="transparent", hover_color="#2d2d3f",
            text_color="#888",
            command=lambda: self._search_var.set(""),
        ).pack(side="right", padx=(0, 6))

        self._search_var.trace_add("write", lambda *_: self._refresh_table())

        # ── device table ──
        tbl = tk.Frame(self, bg=BG)
        tbl.pack(fill="both", expand=True, padx=10, pady=(4, 0))

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("N.Treeview",
                         background="#16213e",
                         foreground="white",
                         fieldbackground="#16213e",
                         rowheight=38,
                         font=("Segoe UI", 11))
        style.configure("N.Treeview.Heading",
                         background="#0d0d1a",
                         foreground="#888888",
                         font=("Segoe UI", 10, "bold"),
                         relief="flat")
        style.map("N.Treeview",
                   background=[("selected", ACCENT)],
                   foreground=[("selected", "white")])

        self.tree = ttk.Treeview(
            tbl,
            columns=("device", "ip", "mac", "status"),
            show="headings",
            style="N.Treeview",
            selectmode="browse",
        )
        self.tree.heading("device", text="Device")
        self.tree.heading("ip",     text="IP Address")
        self.tree.heading("mac",    text="MAC Address")
        self.tree.heading("status", text="Status")
        self.tree.column("device", width=240, anchor="w")
        self.tree.column("ip",     width=140, anchor="w")
        self.tree.column("mac",    width=180, anchor="w")
        self.tree.column("status", width=110, anchor="center")

        self.tree.tag_configure("online", foreground="#4CAF50")
        self.tree.tag_configure("cut",    foreground="#FF5252",
                                           background="#1e0a0a")

        sb = ttk.Scrollbar(tbl, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        self.tree.bind("<Double-1>", lambda _: self._toggle())
        self.tree.bind("<Button-3>", self._right_click)

        # ── bottom bar ──
        bot = ctk.CTkFrame(self, fg_color=BAR, corner_radius=0, height=54)
        bot.pack(fill="x", side="bottom")
        bot.pack_propagate(False)

        ctk.CTkButton(bot, text="✂  CUT",
                       fg_color=RED, hover_color="#c0392b",
                       font=ctk.CTkFont("Segoe UI", 13, "bold"),
                       width=120, height=36,
                       command=self._cut).pack(side="left", padx=(14, 6), pady=9)

        ctk.CTkButton(bot, text="▶  Resume",
                       fg_color=GREEN, hover_color="#27ae60",
                       font=ctk.CTkFont("Segoe UI", 13, "bold"),
                       text_color="white",
                       width=120, height=36,
                       command=self._resume).pack(side="left", padx=6, pady=9)

        ctk.CTkButton(bot, text="Resume All",
                       fg_color="transparent", hover_color="#2d2d3f",
                       text_color="#666",
                       width=100, height=36,
                       command=self._resume_all).pack(side="left", padx=6, pady=9)

        # ── Lag mode + intensity slider ──
        sep0 = ctk.CTkFrame(bot, fg_color="#333355", width=1, height=34)
        sep0.pack(side="left", padx=10, pady=10)

        ctk.CTkLabel(bot, text="⚡ Lag:",
                     font=ctk.CTkFont("Segoe UI", 11, "bold"),
                     text_color="#f0a030").pack(side="left", padx=(0, 4))

        self._intensity_var = tk.IntVar(value=50)
        self._intensity_label = ctk.CTkLabel(
            bot, text="50%",
            font=ctk.CTkFont("Segoe UI", 11),
            text_color="#f0a030", width=36,
        )
        self._intensity_label.pack(side="left", padx=(0, 4))

        ctk.CTkSlider(
            bot,
            from_=1, to=100,
            variable=self._intensity_var,
            width=120, height=18,
            button_color="#f0a030",
            button_hover_color="#c07010",
            progress_color="#f0a030",
            command=lambda v: self._intensity_label.configure(text=f"{int(v)}%"),
        ).pack(side="left", padx=(0, 6), pady=12)

        ctk.CTkButton(bot, text="⚡  LAG",
                       fg_color="#7a5200", hover_color="#5a3c00",
                       font=ctk.CTkFont("Segoe UI", 13, "bold"),
                       text_color="white",
                       width=100, height=36,
                       command=self._lag).pack(side="left", padx=(0, 6), pady=9)

        # ── timed cut ──
        sep = ctk.CTkFrame(bot, fg_color="#333355", width=1, height=34)
        sep.pack(side="left", padx=10, pady=10)

        self._timer_var = tk.StringVar(value="5")
        timer_entry = ctk.CTkEntry(
            bot, textvariable=self._timer_var,
            width=46, height=34,
            font=ctk.CTkFont("Segoe UI", 12),
            justify="center",
        )
        timer_entry.pack(side="left", padx=(0, 4), pady=9)

        ctk.CTkLabel(bot, text="sec",
                     font=ctk.CTkFont("Segoe UI", 11),
                     text_color="#666").pack(side="left", padx=(0, 6))

        ctk.CTkButton(bot, text="⏱  Timed Cut",
                       fg_color="#8B4513", hover_color="#6B3410",
                       font=ctk.CTkFont("Segoe UI", 13, "bold"),
                       text_color="white",
                       width=130, height=36,
                       command=self._timed_cut).pack(side="left", padx=(0, 6), pady=9)

        # ── Delayed cut ──
        sep2 = ctk.CTkFrame(bot, fg_color="#333355", width=1, height=34)
        sep2.pack(side="left", padx=10, pady=10)

        self._delay_var = tk.StringVar(value="3")
        ctk.CTkEntry(
            bot, textvariable=self._delay_var,
            width=46, height=34,
            font=ctk.CTkFont("Segoe UI", 12),
            justify="center",
        ).pack(side="left", padx=(0, 4), pady=9)

        ctk.CTkLabel(bot, text="sec delay",
                     font=ctk.CTkFont("Segoe UI", 11),
                     text_color="#666").pack(side="left", padx=(0, 6))

        ctk.CTkButton(bot, text="⏳  Delayed Cut",
                       fg_color="#1a4a6a", hover_color="#163d58",
                       font=ctk.CTkFont("Segoe UI", 13, "bold"),
                       text_color="white",
                       width=140, height=36,
                       command=self._delayed_cut).pack(side="left", padx=(0, 6), pady=9)

        self._status = ctk.CTkLabel(bot, text="Ready — select interface then Scan",
                                     font=ctk.CTkFont("Segoe UI", 11),
                                     text_color="#666")
        self._status.pack(side="right", padx=16)

    # ── interface change ──────────────────────────────────────────────────────

    def _on_iface_change(self, label: str):
        self._iface       = self._iface_map.get(label)
        self._gateway_ip  = None
        self._gateway_mac = None
        # update spoofer to use the new interface
        self._spoofer._iface = self._iface
        self._gw_label.configure(text="Gateway: detecting...")
        self._init_network()
        self._set_status(f"Interface changed — click Scan to refresh")

    # ── network init ──────────────────────────────────────────────────────────

    def _init_network(self):
        def _w():
            ip  = get_gateway_ip()
            self.after(0, lambda: self._set_gw(ip, None))
            mac = get_mac(ip) if ip else None
            self.after(0, lambda: self._set_gw(ip, mac))
        threading.Thread(target=_w, daemon=True).start()

    def _set_gw(self, ip, mac):
        self._gateway_ip  = ip
        self._gateway_mac = mac
        if ip and mac:
            self._gw_label.configure(text=f"Gateway: {ip}  ({mac})")
        elif ip:
            self._gw_label.configure(text=f"Gateway: {ip}  (resolving…)")
        else:
            self._gw_label.configure(text="Gateway: not found")

    # ── scan ──────────────────────────────────────────────────────────────────

    def _scan(self):
        if not self._gateway_ip:
            messagebox.showwarning("dz_solutions", "Gateway not detected.\nMake sure you are connected to WiFi.")
            return
        self._scan_btn.configure(state="disabled", text="Scanning…")
        self._set_status("Scanning…")
        threading.Thread(target=self._do_scan, daemon=True).start()

    def _do_scan(self):
        own  = get_local_ip(self._iface)
        devs = scan_network(
            get_subnet(self._iface),
            on_progress=lambda m: self.after(0, lambda msg=m: self._set_status(msg)),
            iface=self._iface,
        )

        # Grab gateway MAC from scan if still missing
        if not self._gateway_mac and self._gateway_ip:
            for d in devs:
                if d["ip"] == self._gateway_ip:
                    self._gateway_mac = d["mac"]
                    break
            if not self._gateway_mac:
                self._gateway_mac = get_mac(self._gateway_ip)
            if self._gateway_mac:
                self.after(0, lambda: self._set_gw(self._gateway_ip, self._gateway_mac))

        visible = [d for d in devs
                   if d["ip"] != own and d["ip"] != self._gateway_ip]
        self.after(0, lambda: self._on_scan_done(visible))

    def _on_scan_done(self, devices):
        self._devices = devices
        self._scan_btn.configure(state="normal", text="⟳  Scan Network")
        self._refresh_table()
        self._set_status(f"{len(devices)} device(s) found  —  double-click or select + CUT")

    # ── table ─────────────────────────────────────────────────────────────────

    def _refresh_table(self):
        # remember current selection before wiping rows
        selected = self.tree.selection()
        sel_ip   = selected[0] if selected else None

        query = self._search_var.get().lower().strip()

        for row in self.tree.get_children():
            self.tree.delete(row)

        for dev in self._devices:
            emoji, vendor = get_device_info(dev["mac"], dev["hostname"])
            custom   = namestore.get(dev["mac"])
            hostname = dev.get("hostname", "")
            name     = custom or hostname or vendor
            display  = f"{emoji}  {name}"

            # filter: match against name, IP, MAC, vendor (all lowercase)
            if query and not any(query in field for field in (
                name.lower(), dev["ip"], dev["mac"].lower(), vendor.lower(),
            )):
                continue

            cut  = self._spoofer.is_active(dev["ip"])
            tag  = "cut" if cut else "online"
            stat = "✂  CUT" if cut else "● Online"

            self.tree.insert("", "end", iid=dev["ip"],
                             values=(display, dev["ip"], dev["mac"], stat),
                             tags=(tag,))

        # restore selection
        if sel_ip and self.tree.exists(sel_ip):
            self.tree.selection_set(sel_ip)
            self.tree.focus(sel_ip)

    def _selected_dev(self):
        sel = self.tree.selection()
        if not sel:
            return None
        ip = sel[0]
        return next((d for d in self._devices if d["ip"] == ip), None)

    # ── cut / resume ──────────────────────────────────────────────────────────

    def _cut(self):
        dev = self._selected_dev()
        if not dev:
            messagebox.showinfo("dz_solutions", "Select a device first.")
            return
        if not self._gateway_ip or not self._gateway_mac:
            messagebox.showerror("dz_solutions",
                "Gateway MAC not resolved.\n\n"
                "Run as Administrator, then scan again.")
            return
        self._spoofer.apply(dev["ip"], dev["mac"],
                             self._gateway_ip, self._gateway_mac,
                             mode="block")
        self._refresh_table()
        self._set_status(f"Cutting {dev['ip']}…")

    def _lag(self):
        dev = self._selected_dev()
        if not dev:
            messagebox.showinfo("dz_solutions", "Select a device first.")
            return
        if not self._gateway_ip or not self._gateway_mac:
            messagebox.showerror("dz_solutions",
                "Gateway MAC not resolved.\n\nRun as Administrator, then scan again.")
            return
        intensity = self._intensity_var.get()
        self._spoofer.apply(dev["ip"], dev["mac"],
                             self._gateway_ip, self._gateway_mac,
                             mode="lag", intensity=intensity)
        self._refresh_table()
        self._set_status(f"⚡ Lagging {dev['ip']} at {intensity}% intensity")

    def _timed_cut(self):
        dev = self._selected_dev()
        if not dev:
            messagebox.showinfo("dz_solutions", "Select a device first.")
            return
        if not self._gateway_ip or not self._gateway_mac:
            messagebox.showerror("dz_solutions",
                "Gateway MAC not resolved.\n\nRun as Administrator, then scan again.")
            return
        try:
            secs = int(self._timer_var.get())
            if secs < 1:
                raise ValueError
        except ValueError:
            messagebox.showwarning("dz_solutions", "Enter a valid number of seconds (≥ 1).")
            return
        self._cancel_timer(dev["ip"])
        gw_ip  = self._gateway_ip
        gw_mac = self._gateway_mac
        self._spoofer.apply(dev["ip"], dev["mac"], gw_ip, gw_mac, mode="block")
        self._refresh_table()
        self._countdown(dev, secs, gw_ip, gw_mac)

    def _countdown(self, dev: dict, remaining: int, gw_ip: str, gw_mac: str):
        self._set_status(f"Cutting {dev['ip']} — resuming in {remaining}s")
        if remaining <= 0:
            self._timers.pop(dev["ip"], None)
            self._spoofer.remove(dev["ip"], dev["mac"], gw_ip, gw_mac)
            self._refresh_table()
            self._set_status(f"Timer done — {dev['ip']} resumed")
            return
        after_id = self.after(1000, lambda: self._countdown(dev, remaining - 1, gw_ip, gw_mac))
        self._timers[dev["ip"]] = after_id

    def _cancel_timer(self, ip: str):
        after_id = self._timers.pop(ip, None)
        if after_id:
            self.after_cancel(after_id)

    def _delayed_cut(self):
        dev = self._selected_dev()
        if not dev:
            messagebox.showinfo("dz_solutions", "Select a device first.")
            return
        if not self._gateway_ip or not self._gateway_mac:
            messagebox.showerror("dz_solutions",
                "Gateway MAC not resolved.\n\nRun as Administrator, then scan again.")
            return
        try:
            secs = int(self._delay_var.get())
            if secs < 1:
                raise ValueError
        except ValueError:
            messagebox.showwarning("dz_solutions", "Enter a valid delay in seconds (≥ 1).")
            return
        existing = self._delay_timers.pop(dev["ip"], None)
        if existing:
            self.after_cancel(existing)
        self._pre_cut_countdown(dev, secs)

    def _pre_cut_countdown(self, dev: dict, remaining: int):
        if remaining <= 0:
            self._delay_timers.pop(dev["ip"], None)
            self._spoofer.apply(dev["ip"], dev["mac"],
                                 self._gateway_ip, self._gateway_mac,
                                 mode="block")
            self._refresh_table()
            self._set_status(f"✂ Now cutting {dev['ip']}")
            return
        self._set_status(f"⏳ Cutting {dev['ip']} in {remaining}s… (select + Resume to cancel)")
        after_id = self.after(1000, lambda: self._pre_cut_countdown(dev, remaining - 1))
        self._delay_timers[dev["ip"]] = after_id

    def _resume(self):
        dev = self._selected_dev()
        if not dev:
            messagebox.showinfo("dz_solutions", "Select a device first.")
            return
        self._cancel_timer(dev["ip"])
        # also cancel any pending delayed cut
        delay_id = self._delay_timers.pop(dev["ip"], None)
        if delay_id:
            self.after_cancel(delay_id)
        self._spoofer.remove(dev["ip"], dev["mac"],
                              self._gateway_ip or "",
                              self._gateway_mac or "")
        self._refresh_table()
        self._set_status(f"Resumed {dev['ip']}")

    def _toggle(self):
        dev = self._selected_dev()
        if not dev:
            return
        if self._spoofer.is_active(dev["ip"]):
            self._resume()
        else:
            self._cut()

    def _resume_all(self):
        for ip in list(self._timers):
            self._cancel_timer(ip)
        self._spoofer.remove_all(self._devices,
                                  self._gateway_ip or "",
                                  self._gateway_mac or "")
        self._refresh_table()
        self._set_status("All devices resumed")

    # ── right-click rename ────────────────────────────────────────────────────

    def _right_click(self, event):
        row = self.tree.identify_row(event.y)
        if not row:
            return
        self.tree.selection_set(row)
        dev = self._selected_dev()
        if not dev:
            return

        menu = tk.Menu(self, tearoff=0, bg="#16213e", fg="white",
                       activebackground=ACCENT, activeforeground="white")
        menu.add_command(label="✏  Rename device",
                         command=lambda: self._rename(dev))
        menu.add_separator()
        menu.add_command(label="✂  Cut",    command=self._cut)
        menu.add_command(label="▶  Resume", command=self._resume)
        menu.tk_popup(event.x_root, event.y_root)

    def _rename(self, dev):
        current = namestore.get(dev["mac"]) or dev.get("hostname", "")
        name = simpledialog.askstring(
            "Rename Device",
            f"Name for {dev['ip']}:",
            initialvalue=current,
            parent=self,
        )
        if name is not None:
            if name.strip():
                namestore.set_name(dev["mac"], name.strip())
            else:
                namestore.clear(dev["mac"])
            self._refresh_table()

    # ── helpers ───────────────────────────────────────────────────────────────

    def _set_status(self, msg: str):
        self._status.configure(text=msg)

    def on_close(self):
        self._resume_all()
        self.destroy()


if __name__ == "__main__":
    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()
