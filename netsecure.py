import configparser
import ctypes
import os
import smtplib
import sqlite3
import subprocess
import sys
import time
import tkinter as tk
from collections import defaultdict, deque
from email.mime.text import MIMEText
from threading import Thread, Lock, Event
from tkinter import ttk, Toplevel, Text, messagebox

import matplotlib.pyplot as plt
import requests
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from scapy.all import sniff, IP, TCP, UDP, ARP

# --- Default Configuration ---
DEFAULT_CONFIG = """
[General]
# Set the network interface to sniff on. Leave blank to sniff on all.
# Examples: eth0, en0, Wi-Fi
network_interface = 

# --- Performance ---
# Write to the database in batches every X seconds.
batch_write_interval = 5

[Thresholds]
# Number of packets/ports within the window to trigger an alert
flood_threshold = 150
port_scan_threshold = 20

# Time window in seconds for detection
flood_window = 10
port_scan_window = 60

# --- Alert Throttling ---
[Alert Throttling]
# Don't send the same alert for the same IP more than once every X seconds
alert_suppression_window = 300

[EmailAlerts]
enabled = false
smtp_server = smtp.gmail.com
smtp_port = 587
email_account = your_email@gmail.com
email_password = your_app_password
recipient_email = recipient_email@example.com

[SlackAlerts]
enabled = false
# Your Slack Incoming Webhook URL
webhook_url = https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX

[AbuseIPDB]
enabled = false
# Sign up for a free API key at https://www.abuseipdb.com/
api_key = YOUR_API_KEY_HERE
# Alert if an IP's confidence score is above this value (0-100)
confidence_threshold = 90
"""

# --- Database Logic ---
def setup_database():
    conn = sqlite3.connect('network_traffic.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            source_ip TEXT, dest_ip TEXT, source_port INTEGER,
            dest_port INTEGER, protocol TEXT, length INTEGER,
            flags TEXT, source_country TEXT, summary TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            alert_type TEXT, description TEXT, source_ip TEXT,
            scan_type TEXT, abuseipdb_score TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS arp_log (
            ip_address TEXT PRIMARY KEY,
            mac_address TEXT,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
    return "[SUCCESS] Database 'network_traffic.db' is set up correctly."

# --- Sniffer Engine Logic ---
class SnifferEngine:
    def __init__(self, config, stop_event, pps_queue, pps_lock):
        self.config = config
        self.stop_event = stop_event
        self.pps_queue = pps_queue
        self.pps_lock = pps_lock
        self.packet_db_queue = deque()
        self.alert_db_queue = deque()
        self.db_lock = Lock()
        self.port_scan_tracker = defaultdict(lambda: defaultdict(set))
        self.flood_tracker = defaultdict(int)
        self.timestamps = defaultdict(dict)
        self.suppressed_alerts = {}
        self.geoip_cache = {}
        self.threat_intel_cache = {}
        self.db_writer_thread_active = True
        self.packet_count_sec = 0
        self.last_pps_time = time.time()

    def get_geolocation(self, ip):
        if ip.startswith(('10.', '192.168.', '172.16.')): return "Private"
        if ip in self.geoip_cache: return self.geoip_cache[ip]
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}?fields=country", timeout=2)
            r.raise_for_status()
            country = r.json().get('country', 'N/A')
            self.geoip_cache[ip] = country
            return country
        except requests.exceptions.RequestException:
            self.geoip_cache[ip] = "API Error"
            return "API Error"

    def check_threat_intel(self, ip):
        if not self.config.getboolean('AbuseIPDB', 'enabled') or ip in self.threat_intel_cache: return
        try:
            r = requests.get("https://api.abuseipdb.com/api/v2/check",
                             headers={'Key': self.config['AbuseIPDB']['api_key'], 'Accept': 'application/json'},
                             params={'ipAddress': ip, 'maxAgeInDays': '90'}, timeout=3)
            if r.status_code == 200:
                data = r.json()['data']
                score = data.get('abuseConfidenceScore', 0)
                self.threat_intel_cache[ip] = score
                if score >= self.config.getint('AbuseIPDB', 'confidence_threshold'):
                    desc = f"IP {ip} has abuse score of {score}. Reports: {data.get('totalReports', 0)}."
                    self.log_alert("KNOWN_THREAT", desc, ip, abuse_score=str(score))
            else:
                self.threat_intel_cache[ip] = -1
        except requests.exceptions.RequestException: pass

    def detect_arp_spoofing(self, packet):
        if packet[ARP].op == 2:
            src_ip, src_mac = packet[ARP].psrc, packet[ARP].hwsrc
            try:
                with self.db_lock:
                    conn = sqlite3.connect('network_traffic.db')
                    cursor = conn.cursor()
                    res = cursor.execute("SELECT mac_address FROM arp_log WHERE ip_address = ?", (src_ip,)).fetchone()
                    if res and res[0] != src_mac:
                        desc = f"ARP spoof! IP {src_ip} seen with new MAC: {src_mac} (old: {res[0]})"
                        self.log_alert("ARP_SPOOF", desc, src_ip)
                    elif not res:
                        cursor.execute("INSERT INTO arp_log (ip_address, mac_address) VALUES (?, ?)", (src_ip, src_mac))
                    conn.commit()
                    conn.close()
            except sqlite3.Error: pass

    def detect_anomalies(self, p_info):
        src_ip = p_info['src_ip']
        dst_ip = p_info['dst_ip']
        dst_port = p_info['dst_port']
        ts = time.time()

        # Flood Detection
        flood_window = self.config.getint('Thresholds', 'flood_window')
        if ts - self.timestamps[src_ip].get('flood', 0) > flood_window:
            self.timestamps[src_ip]['flood'] = ts
            self.flood_tracker[src_ip] = 0
        self.flood_tracker[src_ip] += 1
        if self.flood_tracker[src_ip] > self.config.getint('Thresholds', 'flood_threshold'):
            if self.check_and_throttle_alert(src_ip, "IP_FLOOD"):
                desc = f"{src_ip} sent {self.flood_tracker[src_ip]} packets in {flood_window}s."
                self.log_alert("IP_FLOOD", desc, src_ip)
                self.flood_tracker[src_ip] = 0 # Reset after alert to avoid spamming

        # Port Scan Detection
        scan_window = self.config.getint('Thresholds', 'port_scan_window')
        if ts - self.timestamps[src_ip].get('scan', 0) > scan_window:
            self.timestamps[src_ip]['scan'] = ts
            self.port_scan_tracker[src_ip].clear()

        if dst_port:
            self.port_scan_tracker[src_ip][dst_ip].add(dst_port)
            port_count = len(self.port_scan_tracker[src_ip][dst_ip])
            if port_count > self.config.getint('Thresholds', 'port_scan_threshold'):
                if self.check_and_throttle_alert(src_ip, "PORT_SCAN"):
                    ports = sorted(list(self.port_scan_tracker[src_ip][dst_ip]))[:5]
                    desc = f"{src_ip} scanned {port_count} ports on {dst_ip} in {scan_window}s. (e.g., {ports}...)"
                    self.log_alert("PORT_SCAN", desc, src_ip, scan_type="TCP/UDP Scan")
                    self.port_scan_tracker[src_ip][dst_ip].clear() # Reset after alert

    def log_alert(self, a_type, desc, ip, scan_type="", abuse_score="N/A"):
        with self.db_lock:
            self.alert_db_queue.append((a_type, desc, ip, scan_type, abuse_score))
        Thread(target=self.send_alert, args=(f"ALERT: {a_type} from {ip}", desc), daemon=True).start()

    def send_alert(self, subject, body):
        if self.config.getboolean('EmailAlerts', 'enabled'):
            try:
                msg = MIMEText(body)
                msg['Subject'], msg['From'], msg['To'] = subject, self.config['EmailAlerts']['email_account'], self.config['EmailAlerts']['recipient_email']
                with smtplib.SMTP(self.config['EmailAlerts']['smtp_server'], self.config.getint('EmailAlerts', 'smtp_port')) as server:
                    server.starttls()
                    server.login(self.config['EmailAlerts']['email_account'], self.config['EmailAlerts']['email_password'])
                    server.send_message(msg)
                    print(f"Email alert sent to {self.config['EmailAlerts']['recipient_email']}")
            except Exception as e:
                print(f"Failed to send email alert: {e}")
        if self.config.getboolean('SlackAlerts', 'enabled'):
            try:
                payload = {'text': f"*{subject}*\n{body}"}
                requests.post(self.config['SlackAlerts']['webhook_url'], json=payload, timeout=5)
                print("Slack alert sent.")
            except Exception as e:
                print(f"Failed to send Slack alert: {e}")

    def check_and_throttle_alert(self, ip, alert_type):
        key = (ip, alert_type)
        if time.time() - self.suppressed_alerts.get(key, 0) > self.config.getint('Alert Throttling', 'alert_suppression_window'):
            self.suppressed_alerts[key] = time.time()
            return True
        return False

    def packet_handler(self, packet):
        self.packet_count_sec += 1
        if time.time() - self.last_pps_time >= 1:
            with self.pps_lock:
                self.pps_queue.append(self.packet_count_sec)
            self.packet_count_sec = 0
            self.last_pps_time = time.time()

        if ARP in packet:
            Thread(target=self.detect_arp_spoofing, args=(packet,), daemon=True).start()
            return
        if IP not in packet: return

        src_ip, dst_ip = packet[IP].src, packet[IP].dst
        proto, sport, dport, flags = "Other", None, None, ''
        if TCP in packet: proto, sport, dport, flags = "TCP", packet[TCP].sport, packet[TCP].dport, str(packet[TCP].flags)
        elif UDP in packet: proto, sport, dport = "UDP", packet[UDP].sport, packet[UDP].dport
        
        country = self.get_geolocation(src_ip)
        summary = packet.summary()
        
        p_info = {'src_ip': src_ip, 'dst_ip': dst_ip, 'src_port': sport, 'dst_port': dport,
                  'protocol': proto, 'length': len(packet), 'flags': flags, 'country': country, 'summary': summary}
        
        with self.db_lock:
            self.packet_db_queue.append((src_ip, dst_ip, sport, dport, proto, len(packet), flags, country, summary))

        Thread(target=self.detect_anomalies, args=(p_info,), daemon=True).start()
        Thread(target=self.check_threat_intel, args=(src_ip,), daemon=True).start()

    def db_writer_thread(self):
        while self.db_writer_thread_active:
            time.sleep(self.config.getint('General', 'batch_write_interval'))
            p_batch, a_batch = [], []
            with self.db_lock:
                while self.packet_db_queue: p_batch.append(self.packet_db_queue.popleft())
                while self.alert_db_queue: a_batch.append(self.alert_db_queue.popleft())
            if p_batch or a_batch:
                try:
                    conn = sqlite3.connect('network_traffic.db')
                    if p_batch: 
                        conn.cursor().executemany("INSERT INTO packets(source_ip, dest_ip, source_port, dest_port, protocol, length, flags, source_country, summary) VALUES(?,?,?,?,?,?,?,?,?)", p_batch)
                    if a_batch: 
                        conn.cursor().executemany("INSERT INTO alerts(alert_type, description, source_ip, scan_type, abuseipdb_score) VALUES(?,?,?,?,?)", a_batch)
                    conn.commit()
                    conn.close()
                except sqlite3.Error as e: 
                    print(f"DB Writer Error: {e}")
    
    def start(self):
        writer = Thread(target=self.db_writer_thread, daemon=True)
        writer.start()
        sniff(prn=self.packet_handler, store=0, 
              iface=self.config['General']['network_interface'] or None, 
              filter="ip or arp", stop_filter=lambda p: self.stop_event.is_set())
        self.db_writer_thread_active = False
        print("Sniffer stopped.")

# --- Main Application GUI ---
class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Security Monitor")
        self.root.geometry("1600x1000")
        self.sniffer_thread = None
        self.stop_sniffer_event = Event()
        self.pps_queue = deque([0]*60, maxlen=60)
        self.pps_lock = Lock()

        style = ttk.Style()
        style.theme_use('clam')
        
        self.create_control_panel()
        self.create_dashboard_panel()
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_control_panel(self):
        control_frame = ttk.LabelFrame(self.root, text="Controls", padding="10")
        control_frame.pack(side="top", fill="x", padx=10, pady=5)

        self.btn_gen_config = ttk.Button(control_frame, text="Generate/Edit config.ini", command=self.edit_config)
        self.btn_gen_config.pack(side="left", padx=5)
        self.btn_setup_db = ttk.Button(control_frame, text="Setup Database", command=self.setup_db)
        self.btn_setup_db.pack(side="left", padx=5)
        self.btn_start = ttk.Button(control_frame, text="Start Sniffer", command=self.start_sniffer)
        self.btn_start.pack(side="left", padx=5)
        self.btn_stop = ttk.Button(control_frame, text="Stop Sniffer", state="disabled", command=self.stop_sniffer)
        self.btn_stop.pack(side="left", padx=5)
        self.btn_clear_db = ttk.Button(control_frame, text="Clear Logs", command=self.clear_logs)
        self.btn_clear_db.pack(side="left", padx=5)

        self.status_label = ttk.Label(control_frame, text="Status: Idle", font=('Calibri', 12, 'bold'))
        self.status_label.pack(side="right", padx=10)

    def create_dashboard_panel(self):
        top_pane = ttk.Frame(self.root)
        top_pane.pack(fill="x", expand=False, padx=10)
        
        self.create_graph(top_pane)
        
        bottom_pane = ttk.Frame(self.root)
        bottom_pane.pack(fill="both", expand=True, padx=10)
        
        self.create_log_views(bottom_pane)

    def create_graph(self, parent):
        graph_frame = ttk.LabelFrame(parent, text="Live Traffic (Packets/Sec)", padding="5")
        graph_frame.pack(fill="x", expand=True)

        self.fig = plt.Figure(figsize=(5, 2.5), dpi=100, facecolor='#F0F0F0')
        self.ax = self.fig.add_subplot(111)
        self.ax.set_facecolor('#FFFFFF')
        self.ax.tick_params(axis='x', colors='black')
        self.ax.tick_params(axis='y', colors='black')
        self.ax.spines['bottom'].set_color('black')
        self.ax.spines['top'].set_color('black') 
        self.ax.spines['right'].set_color('black')
        self.ax.spines['left'].set_color('black')

        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        self.fig.tight_layout()

    def create_log_views(self, parent):
        for frame_text, tree_cols, dbl_click_handler in [
            ("Alert Log", ('ID', 'Timestamp', 'Type', 'Source IP', 'Abuse Score', 'Scan Type'), self.on_alert_double_click),
            ("Packet Log", ('ID', 'Timestamp', 'Protocol', 'Source', 'Destination', 'Country', 'Summary'), self.on_packet_double_click)
        ]:
            frame = ttk.LabelFrame(parent, text=frame_text, padding="10")
            frame.pack(fill="both", expand=True, pady=5, side="left", anchor="n")
            
            filter_frame = ttk.Frame(frame); filter_frame.pack(fill="x", pady=(0, 5))
            ttk.Label(filter_frame, text="Filter:").pack(side="left")
            filter_var = tk.StringVar(); filter_var.trace_add("write", lambda *args: self.filter_changed())
            ttk.Entry(filter_frame, textvariable=filter_var, width=50).pack(side="left", padx=5)
            
            tree = ttk.Treeview(frame, columns=tree_cols, show='headings')
            for col in tree_cols: tree.heading(col, text=col); tree.column(col, anchor="w", width=100)
            tree.column('ID', width=50, stretch=False); tree.column('Timestamp', width=160, stretch=False)
            tree.bind("<Double-1>", dbl_click_handler)
            tree.pack(fill="both", expand=True)
            
            if "Alert" in frame_text: self.alert_tree, self.alert_filter_var = tree, filter_var
            else: self.packet_tree, self.packet_filter_var = tree, filter_var

    def edit_config(self):
        if not os.path.exists('config.ini'):
            with open('config.ini', 'w') as f: f.write(DEFAULT_CONFIG)
        try:
            if sys.platform == "win32": os.startfile('config.ini')
            else: subprocess.call(('open', 'config.ini'))
        except Exception: messagebox.showerror("Error", "Could not open config.ini. Please open it manually.")

    def setup_db(self): messagebox.showinfo("Database Setup", setup_database())

    def clear_logs(self):
        if messagebox.askyesno("Confirm", "Are you sure you want to delete all packet and alert logs? This cannot be undone."):
            try:
                conn = sqlite3.connect('network_traffic.db')
                conn.execute("DELETE FROM packets"); conn.execute("DELETE FROM alerts")
                conn.commit(); conn.close()
                self.filter_changed()
                messagebox.showinfo("Success", "All logs have been cleared.")
            except Exception as e: messagebox.showerror("Error", f"Could not clear logs: {e}")

    def start_sniffer(self):
        if not os.path.exists('config.ini'):
            messagebox.showerror("Error", "'config.ini' not found. Please generate it first.")
            return
        if not os.path.exists('network_traffic.db'):
            messagebox.showerror("Error", "'network_traffic.db' not found. Please set it up first.")
            return
            
        self.config = configparser.ConfigParser(); self.config.read('config.ini')
        self.stop_sniffer_event.clear()
        
        engine = SnifferEngine(self.config, self.stop_sniffer_event, self.pps_queue, self.pps_lock)
        self.sniffer_thread = Thread(target=engine.start, daemon=True)
        self.sniffer_thread.start()

        self.btn_start.config(state="disabled"); self.btn_stop.config(state="normal")
        self.status_label.config(text="Status: Running", foreground="green")
        
        self.update_gui_data()

    def stop_sniffer(self):
        self.stop_sniffer_event.set()
        self.btn_start.config(state="normal"); self.btn_stop.config(state="disabled")
        self.status_label.config(text="Status: Stopped", foreground="red")
        if hasattr(self, 'update_job'): self.root.after_cancel(self.update_job)
        if hasattr(self, 'graph_update_job'): self.root.after_cancel(self.graph_update_job)

    def filter_changed(self):
        if hasattr(self, 'update_job'): self.root.after_cancel(self.update_job)
        self.update_gui_data()

    def show_detail_window(self, title, content):
        win = Toplevel(self.root); win.title(title); win.geometry("800x400")
        text = Text(win, wrap="word", font=('Courier New', 11)); text.pack(expand=True, fill="both")
        text.insert("1.0", content); text.config(state="disabled")
        win.transient(self.root); win.grab_set(); self.root.wait_window(win)

    def on_packet_double_click(self, event):
        item_id = self.packet_tree.focus()
        if not item_id: return
        try:
            conn = sqlite3.connect('network_traffic.db')
            res = conn.cursor().execute("SELECT summary FROM packets WHERE id=?", (self.packet_tree.item(item_id)['values'][0],)).fetchone()
            conn.close()
            if res: self.show_detail_window("Packet Detail", res[0])
        except Exception as e: print(f"DB Error: {e}")

    def on_alert_double_click(self, event):
        item_id = self.alert_tree.focus()
        if not item_id: return
        try:
            conn = sqlite3.connect('network_traffic.db')
            res = conn.cursor().execute("SELECT description FROM alerts WHERE id=?", (self.alert_tree.item(item_id)['values'][0],)).fetchone()
            conn.close()
            if res: self.show_detail_window("Alert Detail", res[0])
        except Exception as e: print(f"DB Error: {e}")

    def update_gui_data(self):
        try:
            conn = sqlite3.connect('network_traffic.db')
            # Update Alerts
            a_q = "SELECT id, timestamp, alert_type, source_ip, abuseipdb_score, scan_type FROM alerts WHERE source_ip LIKE ? OR alert_type LIKE ? ORDER BY id DESC LIMIT 100"
            self.alert_tree.delete(*self.alert_tree.get_children())
            for row in conn.cursor().execute(a_q, (f'%{self.alert_filter_var.get()}%', f'%{self.alert_filter_var.get()}%')): self.alert_tree.insert('', 'end', values=row)
            # Update Packets
            p_q = "SELECT id, timestamp, protocol, source_ip || ':' || source_port, dest_ip || ':' || dest_port, source_country, summary FROM packets WHERE source_ip LIKE ? OR dest_ip LIKE ? OR protocol LIKE ? ORDER BY id DESC LIMIT 100"
            self.packet_tree.delete(*self.packet_tree.get_children())
            for row in conn.cursor().execute(p_q, (f'%{self.packet_filter_var.get()}%', f'%{self.packet_filter_var.get()}%', f'%{self.packet_filter_var.get()}%')): self.packet_tree.insert('', 'end', values=row)
            conn.close()
        except Exception: pass
        self.update_job = self.root.after(2000, self.update_gui_data)
        self.update_graph()

    def update_graph(self):
        with self.pps_lock:
            data = list(self.pps_queue)
        
        self.ax.clear()
        self.ax.plot(data, color='blue', linewidth=1.5)
        self.ax.set_ylabel("Packets/Sec", color='black')
        self.ax.set_ylim(bottom=0)
        self.ax.grid(True, linestyle='--', alpha=0.6)
        self.fig.tight_layout()
        self.canvas.draw()
        
        self.graph_update_job = self.root.after(1000, self.update_graph)

    def on_closing(self):
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.stop_sniffer()
        self.root.destroy()

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() == 1
    except AttributeError:
        return os.getuid() == 0

def main():
    if not is_admin():
        messagebox.showerror("Admin Rights Required", 
                             "This application requires administrator/root privileges to capture network packets. Please restart it as an administrator.")
        return
        
    root = tk.Tk()
    app = App(root)
    root.mainloop()

if __name__ == '__main__':
    main()

