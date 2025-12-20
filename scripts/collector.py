import os
import sys
import csv
import time
import hashlib
import argparse
import logging
import psutil
from datetime import datetime, date
from collections import deque

# Attempt to import Scapy
try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Ether
except ImportError:
    print("CRITICAL: Scapy not installed. Please install it using 'pip install scapy'.")
    sys.exit(1)

# Attempt to import Windows Event Log utilities
try:
    import win32evtlogutil
    import win32evtlog
    import win32api
    import winerror
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False

# Logging configuration
LOG_SOURCE = "KodiakAiOps-Collector"
CSV_FILE = "data/network_traffic_data.csv"
CSV_HEADER = [
    "timestamp", "process_path", "process_hash", "source_ip", "dest_ip",
    "dest_domain", "dest_port", "bytes_sent", "bytes_recv", "protocol",
    "dns_query", "parent_process", "user_context"
]

def log_event(message, event_type="info"):
    """Logs to file and optionally to Windows Event Log."""
    logging.info(message)
    if not HAS_WIN32:
        return
    
    try:
        if event_type == "info":
            win32evtlogutil.ReportEvent(LOG_SOURCE, 1, eventType=win32evtlog.EVENTLOG_INFORMATION_TYPE, strings=[message])
        elif event_type == "warning":
            win32evtlogutil.ReportEvent(LOG_SOURCE, 2, eventType=win32evtlog.EVENTLOG_WARNING_TYPE, strings=[message])
        elif event_type == "error":
            win32evtlogutil.ReportEvent(LOG_SOURCE, 3, eventType=win32evtlog.EVENTLOG_ERROR_TYPE, strings=[message])
    except Exception as e:
        logging.error(f"Failed to write to Windows Event Log: {e}")

class TrafficCollector:
    def __init__(self, output_file, start_date=None, end_date=None):
        self.output_file = output_file
        self.start_date = start_date
        self.end_date = end_date
        self.process_cache = {}
        self.dns_cache = {}
        self.buffer = deque(maxlen=1000)
        
        # Ensure data directory exists
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        # Initialize CSV if it doesn't exist
        if not os.path.exists(output_file):
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(CSV_HEADER)

    def get_process_info(self, remote_ip, remote_port, local_port):
        """Finds the process associated with a network connection."""
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.laddr.port == local_port and conn.raddr and conn.raddr.ip == remote_ip and conn.raddr.port == remote_port:
                    pid = conn.pid
                    if not pid: continue
                    
                    if pid in self.process_cache:
                        return self.process_cache[pid]
                    
                    try:
                        proc = psutil.Process(pid)
                        pproc = proc.parent()
                        
                        path = proc.exe()
                        name = proc.name()
                        ppath = pproc.exe() if pproc else "unknown"
                        
                        # Process Hash
                        file_hash = "unknown"
                        if os.path.exists(path):
                            with open(path, "rb") as f:
                                file_hash = hashlib.md5(f.read()).hexdigest()
                        
                        # User Context / IIS detection
                        user_context = proc.username()
                        if name.lower() == "w3wp.exe":
                            cmdline = proc.cmdline()
                            # IIS AppPool detection: -ap "AppPoolName"
                            for i, arg in enumerate(cmdline):
                                if arg == "-ap" and i + 1 < len(cmdline):
                                    user_context = f"IIS: {cmdline[i+1]}"
                                    break
                        
                        info = {
                            "path": path,
                            "hash": file_hash,
                            "parent": ppath,
                            "user_context": user_context
                        }
                        self.process_cache[pid] = info
                        return info
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
        except Exception:
            pass
        return None

    def packet_callback(self, pkt):
        """Processes each captured packet."""
        if not IP in pkt:
            return

        timestamp = datetime.now().isoformat()
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        protocol = "OTHER"
        src_port = 0
        dst_port = 0
        bytes_val = len(pkt)
        dns_query = ""

        if TCP in pkt:
            protocol = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif UDP in pkt:
            protocol = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            
            # DNS Query Detection
            if pkt.haslayer(DNSQR):
                dns_query = pkt[DNSQR].qname.decode('utf-8').rstrip('.')
                self.dns_cache[dst_ip] = dns_query

        # Correlate with process
        # We try both directions because we might be seeing the response or the request
        proc_info = self.get_process_info(dst_ip, dst_port, src_port)
        if not proc_info:
            proc_info = self.get_process_info(src_ip, src_port, dst_port)
        
        info = {
            "timestamp": timestamp,
            "process_path": proc_info["path"] if proc_info else "unknown",
            "process_hash": proc_info["hash"] if proc_info else "unknown",
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "dest_domain": self.dns_cache.get(dst_ip, ""),
            "dest_port": dst_port,
            "bytes_sent": bytes_val if src_ip == socket.gethostbyname(socket.gethostname()) else 0,
            "bytes_recv": bytes_val if dst_ip == socket.gethostbyname(socket.gethostname()) else 0,
            "protocol": protocol,
            "dns_query": dns_query,
            "parent_process": proc_info["parent"] if proc_info else "unknown",
            "user_context": proc_info["user_context"] if proc_info else "unknown"
        }

        self.buffer.append(info)
        
        # Flush buffer to CSV every 10 packets or so for performance vs safety
        if len(self.buffer) >= 10:
            self.flush_to_csv()

    def flush_to_csv(self):
        """Writes buffered events to the CSV file."""
        if not self.buffer:
            return
        
        try:
            with open(self.output_file, 'a', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=CSV_HEADER)
                while self.buffer:
                    writer.writerow(self.buffer.popleft())
        except Exception as e:
            logging.error(f"Error writing to CSV: {e}")

    def run(self):
        """Main loop with scheduling."""
        log_event(f"Collector agent starting. Target: {self.output_file}")
        
        while True:
            now = datetime.now()
            today = now.date()
            
            # Check Start Date
            if self.start_date and today < self.start_date:
                time.sleep(60)
                continue
            
            # Check End Date
            if self.end_date and today > self.end_date:
                log_event("End date reached. Stopping collector.")
                self.flush_to_csv()
                break
            
            # Sniffing
            try:
                log_event("Starting network capture...")
                sniff(prn=self.packet_callback, store=0, timeout=10) # 10s chunks to allow check end_date
                self.flush_to_csv()
            except Exception as e:
                log_event(f"Capture error: {e}", "error")
                time.sleep(5)

def main():
    parser = argparse.ArgumentParser(description="Antigravity Network Traffic Collector")
    parser.add_argument("--output", default=CSV_FILE, help="Path to output CSV")
    parser.add_argument("--start-date", help="Start date (YYYY-MM-DD)")
    parser.add_argument("--end-date", help="End date (YYYY-MM-DD)")
    args = parser.parse_args()

    start_date = None
    if args.start_date:
        start_date = datetime.strptime(args.start_date, "%Y-%m-%d").date()
    
    end_date = None
    if args.end_date:
        end_date = datetime.strptime(args.end_date, "%Y-%m-%d").date()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    
    collector = TrafficCollector(args.output, start_date, end_date)
    
    try:
        collector.run()
    except KeyboardInterrupt:
        log_event("Collector stopped by user.")
        collector.flush_to_csv()

if __name__ == "__main__":
    import socket # needed for bytes tracking logic
    main()
