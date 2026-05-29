import customtkinter as ctk
import tkinter as tk
import threading
import asyncio
import json
import os
import sys
import winreg
import ctypes
import webbrowser
import socket
import time
from proxy_server import ProxyServer
from cert_installer import install_ca, is_ca_trusted
from mitm import CA_CERT_FILE, MITMCertManager
from vless_config import build_vless_uri, config_to_vless_defaults

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")
CONFIG_FILE = "config.json"

def set_system_proxy(enable: bool, server: str = ""):
    try:
        internet_settings = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            0,
            winreg.KEY_ALL_ACCESS
        )
        if enable:
            winreg.SetValueEx(internet_settings, "ProxyEnable", 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(internet_settings, "ProxyServer", 0, winreg.REG_SZ, server)
        else:
            winreg.SetValueEx(internet_settings, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(internet_settings)

        INTERNET_OPTION_REFRESH = 37
        INTERNET_OPTION_SETTINGS_CHANGED = 39
        internet_set_option = ctypes.windll.wininet.InternetSetOptionW
        internet_set_option(0, INTERNET_OPTION_REFRESH, 0, 0)
        internet_set_option(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
    except Exception:
        pass

class VPNApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("MasterVPN")
        self.geometry("450x710")
        self.resizable(False, False)
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.proxy_loop = None
        self.proxy_task = None
        self.is_running = False
        self.load_config()
        self.setup_ui()
        self.after(100, self.generate_main_vless_link)

    def load_config(self):
        self.config = {
            "mode": "apps_script",
            "google_ip": "216.239.38.120",
            "front_domain": "www.google.com",
            "script_id": "",
            "auth_key": "",
            "listen_host": "127.0.0.1",
            "listen_port": 8085,
            "log_level": "INFO",
            "verify_ssl": True
        }
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r") as f:
                    self.config.update(json.load(f))
            except:
                pass

    def save_config(self):
        self.config["script_id"] = self.script_id_entry.get().strip()
        self.config["auth_key"] = self.auth_key_entry.get().strip()
        if "script_ids" in self.config:
            self.config["script_ids"] = [self.config["script_id"]]
        with open(CONFIG_FILE, "w") as f:
            json.dump(self.config, f, indent=4)

    def _copy_text(self, widget, event=None):
        try:
            text = widget.selection_get()
        except tk.TclError:
            text = widget.get()
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            self.update_idletasks()
        return "break"

    def _paste_text(self, widget, event=None):
        widget.focus_set()
        try:
            text = self.clipboard_get()
        except tk.TclError:
            return "break"
        
        try:
            if widget.selection_present():
                widget.delete("sel.first", "sel.last")
        except tk.TclError:
            pass
            
        widget.insert(tk.INSERT, text)
        return "break"

    def _cut_text(self, widget, event=None):
        try:
            text = widget.selection_get()
        except tk.TclError:
            text = widget.get()
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            try:
                widget.delete("sel.first", "sel.last")
            except tk.TclError:
                widget.delete(0, tk.END)
            self.update_idletasks()
        return "break"

    def apply_context_menu(self, entry_widget):
        menu = tk.Menu(self, tearoff=0, bg="#2b2b2b", fg="white", activebackground="#1f538d")
        menu.add_command(label="Copy", command=lambda w=entry_widget: self._copy_text(w))
        menu.add_command(label="Paste", command=lambda w=entry_widget: self._paste_text(w))
        menu.add_command(label="Cut", command=lambda w=entry_widget: self._cut_text(w))

        def show_menu(event):
            entry_widget.focus_set()
            menu.tk_popup(event.x_root, event.y_root)
            menu.grab_release()
            return "break"

        entry_widget.bind("<Button-3>", show_menu)
        entry_widget.bind("<Control-c>", lambda e, w=entry_widget: self._copy_text(w))
        entry_widget.bind("<Control-v>", lambda e, w=entry_widget: self._paste_text(w))
        entry_widget.bind("<Control-x>", lambda e, w=entry_widget: self._cut_text(w))

    def setup_ui(self):
        self.logo_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.logo_frame.pack(fill="x", pady=(30, 10))

        self.logo_label = ctk.CTkLabel(
            self.logo_frame,
            text="🛡️",
            font=("Segoe UI Emoji", 72),
            anchor="center",
            justify="center"
        )
        self.logo_label.pack(anchor="center")

        self.title_label = ctk.CTkLabel(self, text="Master VPN", font=("Segoe UI", 28, "bold"))
        self.title_label.pack(pady=(0, 25))

        self.script_id_entry = ctk.CTkEntry(self, placeholder_text="Google Script ID", width=360, height=45)
        self.script_id_entry.pack(pady=10)
        self.script_id_entry.insert(0, self.config.get("script_id", ""))
        self.apply_context_menu(self.script_id_entry)

        self.auth_key_entry = ctk.CTkEntry(self, placeholder_text="Auth Key (Secret)", show="*", width=360, height=45)
        self.auth_key_entry.pack(pady=10)
        self.auth_key_entry.insert(0, self.config.get("auth_key", ""))
        self.apply_context_menu(self.auth_key_entry)

        self.connect_btn = ctk.CTkButton(
            self,
            text="CONNECT",
            font=("Segoe UI", 18, "bold"),
            width=220,
            height=55,
            corner_radius=27,
            fg_color="#28a745",
            hover_color="#218838",
            command=self.toggle_connection
        )
        self.connect_btn.pack(pady=20)

        self.vless_btn = ctk.CTkButton(
            self,
            text="V2BOX VLESS CONFIG",
            font=("Segoe UI", 14, "bold"),
            width=220,
            height=42,
            corner_radius=21,
            fg_color="#1f6aa5",
            hover_color="#144870",
            command=self.open_vless_converter
        )
        self.vless_btn.pack(pady=(0, 12))

        self.links_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.links_frame.pack(pady=5)

        self.github_link = ctk.CTkLabel(
            self.links_frame,
            text="GitHub",
            font=("Segoe UI", 14, "bold"),
            text_color="#00a8ff",
            cursor="hand2"
        )
        self.github_link.pack(side="left", padx=8)
        self.github_link.bind("<Button-1>", lambda e: webbrowser.open("https://github.com/AriPath/MasterVPN"))

        self.separator = ctk.CTkLabel(
            self.links_frame,
            text="|",
            font=("Segoe UI", 14, "bold"),
            text_color="white"
        )
        self.separator.pack(side="left")

        self.telegram_link = ctk.CTkLabel(
            self.links_frame,
            text="Telegram",
            font=("Segoe UI", 14, "bold"),
            text_color="#00a8ff",
            cursor="hand2"
        )
        self.telegram_link.pack(side="left", padx=8)
        self.telegram_link.bind("<Button-1>", lambda e: webbrowser.open("https://t.me/AriPath"))

        self.proxy_label = ctk.CTkLabel(self, text="Status: Disconnected", font=("Segoe UI", 14))
        self.proxy_label.pack(pady=(15, 6))

        self.main_vless_label = ctk.CTkLabel(
            self,
            text="VLESS Import Link: Not generated",
            font=("Segoe UI", 12),
            text_color="#c8c8c8",
            wraplength=400,
        )
        self.main_vless_label.pack(pady=(0, 4))

        self.main_vless_text = ctk.CTkTextbox(self, width=400, height=58, wrap="word")
        self.main_vless_text.pack(pady=(0, 6))
        self.main_vless_text.insert("1.0", "Generating VLESS import link...")
        self.main_vless_text.configure(state="disabled")

        self.main_vless_actions = ctk.CTkFrame(self, fg_color="transparent")
        self.main_vless_actions.pack(pady=(0, 8))
        self.copy_vless_btn = ctk.CTkButton(
            self.main_vless_actions,
            text="Copy VLESS",
            width=115,
            height=30,
            command=self.copy_main_vless_link,
            state="disabled",
        )
        self.copy_vless_btn.pack(side="left", padx=(0, 8))
        self.ping_vless_btn = ctk.CTkButton(
            self.main_vless_actions,
            text="Test Ping",
            width=115,
            height=30,
            command=self.refresh_main_vless_ping,
            state="disabled",
        )
        self.ping_vless_btn.pack(side="left")

    def open_vless_converter(self):
        self.save_config()
        VlessConverterWindow(self, self.config)

    def _set_main_vless_text(self, text):
        self.main_vless_text.configure(state="normal")
        self.main_vless_text.delete("1.0", tk.END)
        self.main_vless_text.insert("1.0", text)
        self.main_vless_text.configure(state="disabled")

    def _build_main_vless_link(self):
        defaults = config_to_vless_defaults(self.config)
        return build_vless_uri(**defaults), defaults

    def generate_main_vless_link(self):
        try:
            uri, defaults = self._build_main_vless_link()
        except Exception as exc:
            self.main_vless_label.configure(text=f"VLESS Import Link: Error - {exc}", text_color="red")
            self._set_main_vless_text("Unable to generate VLESS import link.")
            self.copy_vless_btn.configure(state="disabled")
            self.ping_vless_btn.configure(state="disabled")
            return
        self.main_vless_label.configure(text="VLESS Import Link: Generated for V2BOX", text_color="#28a745")
        self._set_main_vless_text(uri)
        self.copy_vless_btn.configure(state="normal")
        self.ping_vless_btn.configure(state="normal")
        self._start_vless_ping(defaults)

    def copy_main_vless_link(self):
        uri = self.main_vless_text.get("1.0", tk.END).strip()
        if uri and uri.startswith("vless://"):
            self.clipboard_clear()
            self.clipboard_append(uri)
            self.main_vless_label.configure(text="VLESS Import Link: Copied to clipboard", text_color="#28a745")

    def refresh_main_vless_ping(self):
        try:
            _, defaults = self._build_main_vless_link()
        except Exception as exc:
            self.main_vless_label.configure(text=f"VLESS Ping: Error - {exc}", text_color="red")
            return
        self._start_vless_ping(defaults)

    def _start_vless_ping(self, defaults):
        self.main_vless_label.configure(text="VLESS Ping: Testing...", text_color="yellow")
        threading.Thread(target=self._ping_vless_target, args=(defaults,), daemon=True).start()

    def _ping_vless_target(self, defaults):
        address = defaults.get("address", "")
        port = int(defaults.get("port", 443))
        started = time.perf_counter()
        try:
            with socket.create_connection((address, port), timeout=5):
                latency_ms = round((time.perf_counter() - started) * 1000)
            self.after(0, lambda: self.main_vless_label.configure(
                text=f"VLESS Ping: {latency_ms} ms ({address}:{port})",
                text_color="#28a745",
            ))
        except Exception as exc:
            error = str(exc)
            self.after(0, lambda: self.main_vless_label.configure(
                text=f"VLESS Ping: Failed for {address}:{port} ({error})",
                text_color="red",
            ))

    def toggle_connection(self):
        if not self.is_running:
            self.start_vpn()
        else:
            self.stop_vpn()

    def start_vpn(self):
        if not self.script_id_entry.get() or not self.auth_key_entry.get():
            self.proxy_label.configure(text="Error: Missing Inputs!", text_color="red")
            return
        self.save_config()
        self.connect_btn.configure(text="CONNECTING...", state="disabled", fg_color="#ffc107")
        self.proxy_label.configure(text="Setting up system proxy...", text_color="yellow")
        self.update()
        threading.Thread(target=self._init_and_run).start()

    def _init_and_run(self):
        try:
            if not os.path.exists(CA_CERT_FILE):
                MITMCertManager()
            if not is_ca_trusted(CA_CERT_FILE):
                install_ca(CA_CERT_FILE)

            proxy_addr = f"{self.config.get('listen_host', '127.0.0.1')}:{self.config.get('listen_port', 8085)}"
            set_system_proxy(True, proxy_addr)

            self.proxy_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.proxy_loop)
            proxy = ProxyServer(self.config)

            self.is_running = True
            self.update_ui_state(True)

            self.proxy_task = self.proxy_loop.create_task(proxy.start())
            self.proxy_loop.run_until_complete(self.proxy_task)
        except asyncio.CancelledError:
            pass
        except Exception:
            self.is_running = False
            self.update_ui_state(False)

    def stop_vpn(self):
        self.is_running = False
        self.connect_btn.configure(text="DISCONNECTING...", state="disabled")
        set_system_proxy(False)
        if self.proxy_loop and self.proxy_task:
            self.proxy_loop.call_soon_threadsafe(self.proxy_task.cancel)
        self.update_ui_state(False)

    def update_ui_state(self, running):
        if running:
            self.connect_btn.configure(text="DISCONNECT", fg_color="#dc3545", hover_color="#c82333", state="normal")
            self.proxy_label.configure(text="Status: Connected (Auto Proxy Set)", text_color="#28a745")
            self.after(0, self.generate_main_vless_link)
        else:
            self.connect_btn.configure(text="CONNECT", fg_color="#28a745", hover_color="#218838", state="normal")
            self.proxy_label.configure(text="Status: Disconnected", text_color="white")
            self.generate_main_vless_link()

    def on_closing(self):
        if self.is_running:
            self.stop_vpn()
        set_system_proxy(False)
        self.destroy()
        os._exit(0)


class VlessConverterWindow(ctk.CTkToplevel):
    def __init__(self, master, config):
        super().__init__(master)
        self.title("VLESS Config for V2BOX")
        self.geometry("620x720")
        self.resizable(False, False)
        self.transient(master)
        self.grab_set()
        self.defaults = config_to_vless_defaults(config)
        self._entries = {}
        self._setup_ui()
        self.generate()

    def _setup_ui(self):
        title = ctk.CTkLabel(self, text="VLESS Config for iPhone V2BOX", font=("Segoe UI", 22, "bold"))
        title.pack(pady=(20, 4))
        note = ctk.CTkLabel(
            self,
            text="Edit these values to match your VLESS-capable server, then copy/import the link in V2BOX.",
            font=("Segoe UI", 12),
            text_color="#c8c8c8",
            wraplength=560,
        )
        note.pack(pady=(0, 12))

        form = ctk.CTkFrame(self)
        form.pack(fill="x", padx=22, pady=8)

        rows = [
            ("name", "Profile Name"),
            ("user_id", "UUID / Auth ID"),
            ("address", "Server Address"),
            ("port", "Port"),
            ("sni", "TLS SNI"),
            ("host", "WebSocket Host"),
            ("path", "WebSocket Path"),
            ("fingerprint", "Fingerprint"),
            ("alpn", "ALPN"),
            ("flow", "Flow (optional)"),
        ]
        for row, (key, label) in enumerate(rows):
            ctk.CTkLabel(form, text=label, anchor="w", width=140).grid(row=row, column=0, padx=(14, 8), pady=6, sticky="w")
            entry = ctk.CTkEntry(form, width=390)
            entry.grid(row=row, column=1, padx=(0, 14), pady=6, sticky="ew")
            entry.insert(0, str(self.defaults.get(key, "")))
            self._entries[key] = entry
        form.grid_columnconfigure(1, weight=1)

        options = ctk.CTkFrame(self, fg_color="transparent")
        options.pack(fill="x", padx=22, pady=(4, 8))
        self.security_var = tk.StringVar(value=self.defaults.get("security", "tls"))
        self.transport_var = tk.StringVar(value=self.defaults.get("transport", "ws"))
        self.allow_insecure_var = tk.BooleanVar(value=bool(self.defaults.get("allow_insecure", False)))
        ctk.CTkLabel(options, text="Security").grid(row=0, column=0, padx=(0, 8), sticky="w")
        ctk.CTkOptionMenu(options, values=["tls", "reality", "none"], variable=self.security_var, width=130).grid(row=0, column=1, padx=(0, 18))
        ctk.CTkLabel(options, text="Transport").grid(row=0, column=2, padx=(0, 8), sticky="w")
        ctk.CTkOptionMenu(options, values=["ws", "tcp", "grpc"], variable=self.transport_var, width=130).grid(row=0, column=3, padx=(0, 18))
        ctk.CTkCheckBox(options, text="Allow insecure TLS", variable=self.allow_insecure_var).grid(row=0, column=4, sticky="w")

        buttons = ctk.CTkFrame(self, fg_color="transparent")
        buttons.pack(fill="x", padx=22, pady=8)
        ctk.CTkButton(buttons, text="Generate", command=self.generate, width=120).pack(side="left", padx=(0, 10))
        ctk.CTkButton(buttons, text="Copy Link", command=self.copy_link, width=120).pack(side="left", padx=(0, 10))
        ctk.CTkButton(buttons, text="Open V2BOX Import", command=self.open_import_link, width=160).pack(side="left")

        self.status_label = ctk.CTkLabel(self, text="", anchor="w")
        self.status_label.pack(fill="x", padx=24, pady=(4, 0))

        self.output = ctk.CTkTextbox(self, width=570, height=170, wrap="word")
        self.output.pack(padx=22, pady=(8, 12), fill="both")

        help_text = (
            "Important: VLESS is a different protocol from the built-in MasterVPN/App Script relay. "
            "This tool creates a VLESS share link for clients such as V2BOX; the remote server must also run "
            "a compatible VLESS inbound with matching UUID, transport, TLS/SNI, host, and path."
        )
        ctk.CTkLabel(self, text=help_text, wraplength=560, justify="left", text_color="#ffcc66").pack(padx=24, pady=(0, 14))

    def _values(self):
        values = {key: entry.get().strip() for key, entry in self._entries.items()}
        values["security"] = self.security_var.get()
        values["transport"] = self.transport_var.get()
        values["allow_insecure"] = self.allow_insecure_var.get()
        return values

    def generate(self):
        try:
            values = self._values()
            uri = build_vless_uri(**values)
        except Exception as exc:
            self.status_label.configure(text=f"Error: {exc}", text_color="red")
            return
        self.output.configure(state="normal")
        self.output.delete("1.0", tk.END)
        self.output.insert("1.0", uri)
        self.output.configure(state="disabled")
        self.status_label.configure(text="VLESS link generated.", text_color="#28a745")

    def copy_link(self):
        self.generate()
        uri = self.output.get("1.0", tk.END).strip()
        if uri:
            self.clipboard_clear()
            self.clipboard_append(uri)
            self.status_label.configure(text="Copied VLESS link to clipboard.", text_color="#28a745")

    def open_import_link(self):
        self.generate()
        uri = self.output.get("1.0", tk.END).strip()
        if uri:
            webbrowser.open(uri)


if __name__ == "__main__":
    app = VPNApp()
    app.mainloop()
