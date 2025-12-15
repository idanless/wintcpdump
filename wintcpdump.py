import sys
import os
import ctypes
import logging
import socket
import threading
import datetime
import struct
import time

# ==============================================================================
# FIX ENCODING
# ==============================================================================
os.environ["PYTHONIOENCODING"] = "utf-8"
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except:
        pass

# ==============================================================================
# 2. PATH SETUP & DLL HOOK
# ==============================================================================
if getattr(sys, 'frozen', False):
    EXE_DIR = os.path.dirname(sys.executable)
else:
    EXE_DIR = os.path.abspath(".")

os.chdir(EXE_DIR)

logging.basicConfig(filename=os.path.join(EXE_DIR, "debug_log.txt"),
                    level=logging.ERROR,
                    format='%(asctime)s %(message)s')

_Original_WinDLL = ctypes.WinDLL
_Original_CDLL = ctypes.CDLL
_Original_LoadLibrary = ctypes.windll.LoadLibrary


def _resolve_path(name):
    if name and "WinDivert" in str(name):
        sub_dir = os.path.join(EXE_DIR, "pydivert")
        if os.path.exists(os.path.join(sub_dir, "WinDivert64.dll")):
            return os.path.join(sub_dir, "WinDivert64.dll")
        if os.path.exists(os.path.join(sub_dir, "WinDivert.dll")):
            return os.path.join(sub_dir, "WinDivert.dll")
        if os.path.exists(os.path.join(EXE_DIR, "WinDivert64.dll")):
            return os.path.join(EXE_DIR, "WinDivert64.dll")
        if os.path.exists(os.path.join(EXE_DIR, "WinDivert.dll")):
            return os.path.join(EXE_DIR, "WinDivert.dll")
    return name


def _Hooked_WinDLL(name, *args, **kwargs):
    return _Original_WinDLL(_resolve_path(name), *args, **kwargs)


def _Hooked_CDLL(name, *args, **kwargs):
    return _Original_CDLL(_resolve_path(name), *args, **kwargs)


def _Hooked_LoadLibrary(name):
    return _Original_LoadLibrary(_resolve_path(name))


ctypes.WinDLL = _Hooked_WinDLL
ctypes.CDLL = _Hooked_CDLL
ctypes.windll.LoadLibrary = _Hooked_LoadLibrary
ctypes.cdll.LoadLibrary = _Hooked_LoadLibrary


import pydivert
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import DataTable, Button, Input, Label, Switch, Select, Static, Log
from textual import work


#
def get_local_ips():
    try:
        hostname = socket.gethostname()
        _, _, ip_list = socket.gethostbyname_ex(hostname)
        return ip_list
    except:
        return ["127.0.0.1"]


def get_smart_filename(user_input):
    if not user_input or user_input.strip() == "":
        return f"LOG_{int(time.time())}.pcap"
    base_name = user_input.strip()
    if not base_name.endswith(".pcap"):
        base_name += ".pcap"
    full_path = os.path.join(EXE_DIR, base_name)
    if not os.path.exists(full_path):
        return full_path
    name, ext = os.path.splitext(full_path)
    counter = 1
    while True:
        new_name = f"{name}_{counter}{ext}"
        if not os.path.exists(new_name):
            return new_name
        counter += 1


def write_pcap_header(f):
    f.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101))


def write_pcap_packet(f, raw_bytes):
    t = time.time()
    sec = int(t)
    usec = int((t - sec) * 1_000_000)
    length = len(raw_bytes)
    f.write(struct.pack('<IIII', sec, usec, length, length))
    f.write(raw_bytes)


def get_clean_payload(payload_bytes):
    if not payload_bytes: return ""
    chunk = payload_bytes[:30]
    return "".join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)



class CyberSniffer(App):
    CSS = """
    Screen { background: #000000; color: #00ff00; }

    /* INPUTS */
    Input { background: #000; border: solid #004400; color: #ffffff; height: 3; }
    Input:focus { border: solid #00ff00; }

    /* --- SELECT MENU STYLING --- */
    Select { 
        height: 3; 
        border: solid #004400; 
        background: #000000; 
    }
    Select:focus { border: solid #00ff00; }

    SelectCurrent { 
        color: #00ff00; 
        background: #000000; 
        border: none; 
        text-style: bold; 
    }

    SelectOverlay { 
        background: #222222;
        border: solid #00ff00; 
        color: #ffffff; 
    }

    Option { 
        padding: 1; 
        background: #222222; 
        color: #ffffff;
        text-style: bold;
    }

    Option:hover, Option.-highlight { 
        background: #00ff00; 
        color: #000000;
        text-style: bold; 
    }

    /* LAYOUT */
    #top-bar { height: 1; background: #002200; color: #00ff00; content-align: center middle; text-style: bold; border-bottom: solid #005500; }
    #controls-container { height: auto; background: #0a0a0a; border-bottom: solid #00ff00; padding: 0 1; }
    .input-group { width: 1fr; height: auto; margin-right: 1; margin-top: 1; }
    .input-label { color: #008800; text-style: bold; padding-left: 1; height: 1; }
    #group-port { width: 15%; }
    .row { layout: horizontal; height: auto; margin-bottom: 1; }

    #in-src-custom {
        display: none; 
        margin-top: 1;
        border: solid #00ff00;
        background: #001100;
    }
    .show-custom {
        display: block !important;
    }

    #save-container { 
        width: 30%; 
        background: #111111; 
        border: solid #333333; 
        layout: horizontal; 
        height: 5; 
        margin-right: 1; 
        margin-top: 1; 
        align: center middle;
    }
    #lbl-save-status { 
        width: 1fr;
        height: 100%;
        color: #ffffff; 
        text-style: bold; 
        content-align: center middle;
        margin-right: 1;
    }
    Switch { width: auto; }
    #save-container.active { background: #002200; border: solid #00ff00; }
    .active #lbl-save-status { color: #00ff00; }

    Button { width: 1fr; border: none; height: 3; text-style: bold; margin-top: 1; }
    #btn-start { background: #004400; color: #00ff00; border: solid #00ff00; }
    #btn-start:hover { background: #00ff00; color: #000; }
    #btn-stop { display: none; background: #660000; color: #ffcccc; border: solid #ff0000; }
    #btn-stop:hover { background: #ff0000; color: #000; }

    #idan-label {
        height: 2;
        background: #001100;
        color: #00ff00;
        text-style: bold;
        content-align: center middle;
        border-bottom: solid #004400;
        text-opacity: 100%;
    }

    DataTable { height: 1fr; background: #000; border: none; scrollbar-gutter: stable; }
    DataTable > .datatable--header { background: #002200; color: #00ff00; text-style: bold; }
    Log { height: 2; background: #000; border-top: solid #003300; color: #008800; }
    """

    def __init__(self):
        super().__init__()
        self.stop_event = threading.Event()
        self.packet_count = 0
        self.local_ips = get_local_ips()
        self.windivert_handle = None

    def compose(self) -> ComposeResult:
        yield Static(f"[ NETSEC INTERCEPTOR V20 // FAST STOP FIX ]", id="top-bar")

        with Container(id="controls-container"):
            with Horizontal(classes="row"):
                with Vertical(classes="input-group"):
                    yield Label("IP SRC", classes="input-label")
                    ip_opts = [("ANY IP", ""), ("CUSTOM IP", "custom")] + [(ip, ip) for ip in self.local_ips]
                    yield Select(ip_opts, prompt="SELECT IP", id="sel-src")
                    yield Input(placeholder="Type IP Here...", id="in-src-custom")

                with Vertical(classes="input-group"):
                    yield Label("PROTO", classes="input-label")
                    proto_opts = [("ANY PROTO", ""), ("TCP", "tcp"), ("UDP", "udp"), ("ICMP", "icmp")]
                    yield Select(proto_opts, prompt="SELECT PROTO", id="sel-proto")

                with Vertical(classes="input-group"):
                    yield Label("IP DST", classes="input-label")
                    yield Input(placeholder="e.g. 1.1.1.1", id="in-target")

                with Vertical(classes="input-group", id="group-port"):
                    yield Label("PORT", classes="input-label")
                    yield Input(placeholder="80", id="in-port")

            with Horizontal(classes="row"):
                with Container(id="save-container"):
                    yield Label("ENABLE SAVE PCAP", id="lbl-save-status")
                    yield Switch(id="sw-save")

                with Vertical(classes="input-group"):
                    yield Input(placeholder="FILENAME (AUTO)", id="in-filename", disabled=True)

                yield Button("START SNIFFER", id="btn-start")
                yield Button("STOP SNIFFER", id="btn-stop")

        yield Static("created by idan less vr2", id="idan-label")
        yield DataTable(zebra_stripes=False)
        yield Log(id="sys-log")

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.cursor_type = "row"
        table.add_columns("TIME", "PROTO", "SRC", "DST", "FLAGS", "TTL", "LEN", "PAYLOAD")

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "sel-src":
            custom_box = self.query_one("#in-src-custom")
            if event.value == "custom":
                custom_box.add_class("show-custom")
                custom_box.focus()
            else:
                custom_box.remove_class("show-custom")

    def on_switch_changed(self, event: Switch.Changed) -> None:
        if event.switch.id == "sw-save":
            container = self.query_one("#save-container")
            label = self.query_one("#lbl-save-status")
            file_in = self.query_one("#in-filename")

            if event.value:
                container.add_class("active")
                label.update("SAVE PCAP: ON")
                file_in.disabled = False
            else:
                container.remove_class("active")
                label.update("ENABLE SAVE PCAP")
                file_in.disabled = True

    def log_sys(self, msg):
        log = self.query_one(Log)
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        log.write_line(f"[{ts}] {msg}")

    def build_filter(self):
        src_selection = self.query_one("#sel-src", Select).value
        src = ""
        if src_selection == "custom":
            src = self.query_one("#in-src-custom", Input).value.strip()
        elif src_selection != Select.BLANK:
            src = src_selection

        proto = self.query_one("#sel-proto", Select).value
        dst = self.query_one("#in-target", Input).value.strip()
        port = self.query_one("#in-port", Input).value.strip()

        f = []
        if src: f.append(f"(ip.SrcAddr == {src} or ip.DstAddr == {src})")
        if dst: f.append(f"(ip.SrcAddr == {dst} or ip.DstAddr == {dst})")
        if proto and proto != Select.BLANK: f.append(proto)
        if port and port.isdigit():
            if proto == "tcp":
                f.append(f"(tcp.SrcPort == {port} or tcp.DstPort == {port})")
            elif proto == "udp":
                f.append(f"(udp.SrcPort == {port} or udp.DstPort == {port})")
            else:
                f.append(
                    f"(tcp.SrcPort == {port} or tcp.DstPort == {port} or udp.SrcPort == {port} or udp.DstPort == {port})")
        return " and ".join(f) if f else "true"

    # =========================================================================
    #  handle for fast close
    # =========================================================================
    @work(thread=True)
    def capture_thread(self, filter_str, save_on, filename):
        f = None
        if save_on:
            try:
                f = open(filename, 'wb')
                write_pcap_header(f)
                self.call_from_thread(self.log_sys, f"WRITING: {filename}")
            except Exception as e:
                self.call_from_thread(self.log_sys, f"DISK ERROR: {e}")
                logging.error(f"File Error: {e}")

        try:
            self.windivert_handle = pydivert.WinDivert(filter_str, flags=pydivert.Flag.SNIFF)
            self.windivert_handle.open()

            self.call_from_thread(self.log_sys, "STREAM ACTIVE.")

            while not self.stop_event.is_set():
                try:
                    packet = self.windivert_handle.recv()

                    if self.stop_event.is_set():
                        break

                    self.packet_count += 1
                    if f:
                        write_pcap_packet(f, packet.raw)
                        f.flush()

                    ts = datetime.datetime.now().strftime("%H:%M:%S")
                    proto, src, dst, flags, ttl, load = "IP", packet.src_addr, packet.dst_addr, "", "?", ""
                    if packet.ipv4: ttl = str(packet.ipv4.ttl)
                    if packet.tcp:
                        proto = "TCP"
                        src = f"{packet.src_addr}:{packet.tcp.src_port}"
                        dst = f"{packet.dst_addr}:{packet.tcp.dst_port}"
                        fl = []
                        if packet.tcp.syn: fl.append("SYN ")
                        if packet.tcp.ack: fl.append("ACK ")
                        if packet.tcp.fin: fl.append("FIN ")
                        if packet.tcp.rst: fl.append("RST ")
                        flags = "".join(fl)
                        load = get_clean_payload(packet.tcp.payload)
                    elif packet.udp:
                        proto = "UDP"
                        src = f"{packet.src_addr}:{packet.udp.src_port}"
                        dst = f"{packet.dst_addr}:{packet.udp.dst_port}"
                        load = get_clean_payload(packet.udp.payload)
                    elif packet.icmp:
                        proto = "ICMP"
                        flags = f"T:{packet.icmp.type}"
                    row = [ts, proto, src, dst, flags, ttl, str(len(packet.raw)), load]
                    self.call_from_thread(self.add_row, row)

                except OSError:
                    break
                except Exception:
                    if self.stop_event.is_set():
                        break

        except Exception as e:
            self.call_from_thread(self.log_sys, f"DRIVER ERROR: {e}")
            logging.error(f"WinDivert Init Error: {e}")
        finally:
            try:
                if self.windivert_handle:
                    self.windivert_handle.close()
                    self.windivert_handle = None
            except:
                pass
            if f:
                f.close()
            self.call_from_thread(self.reset_ui)

    def add_row(self, row):
        t = self.query_one(DataTable)
        t.add_row(*row)
        t.scroll_end(animate=False)

    def reset_ui(self):
        self.query_one("#btn-start").display = True
        self.query_one("#btn-stop").display = False
        self.query_one("#sel-src").disabled = False
        self.query_one("#in-src-custom").disabled = False
        self.query_one("#sel-proto").disabled = False
        self.query_one("#in-target").disabled = False
        self.query_one("#in-port").disabled = False
        self.query_one("#sw-save").disabled = False
        if self.query_one("#sw-save", Switch).value:
            self.query_one("#in-filename").disabled = False
        self.log_sys("STOPPED.")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-start":
            self.stop_event.clear()
            self.packet_count = 0
            self.query_one(DataTable).clear()
            self.query_one("#btn-start").display = False
            self.query_one("#btn-stop").display = True
            self.query_one("#sel-src").disabled = True
            self.query_one("#in-src-custom").disabled = True
            self.query_one("#sel-proto").disabled = True
            self.query_one("#in-target").disabled = True
            self.query_one("#in-port").disabled = True
            self.query_one("#sw-save").disabled = True
            self.query_one("#in-filename").disabled = True
            filter_str = self.build_filter()
            save_on = self.query_one("#sw-save", Switch).value
            final_name = "dummy"
            if save_on:
                raw_input = self.query_one("#in-filename", Input).value
                final_name = get_smart_filename(raw_input)
            self.capture_thread(filter_str, save_on, final_name)

        elif event.button.id == "btn-stop":
            self.stop_event.set()
            self.log_sys("ABORTING...")

            if self.windivert_handle:
                try:
                    self.windivert_handle.close()
                except:
                    pass


if __name__ == "__main__":
    app = CyberSniffer()
    app.run()
