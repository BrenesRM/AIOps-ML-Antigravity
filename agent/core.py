import os
import sys
import csv
import time
import logging
import socket
from datetime import datetime
from collections import deque
from .config import CSV_FILE, CSV_HEADER
from .logger import log_event
from .process import ProcessTracker

# Attempt to import Scapy
try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR
except ImportError:
    print("CRITICAL: Scapy not installed. Please install it using 'pip install scapy'.")
    sys.exit(1)

class TrafficCollector:
    def __init__(self, output_file, start_date=None, end_date=None):
        self.output_file = output_file
        self.start_date = start_date
        self.end_date = end_date
        self.dns_cache = {}
        self.buffer = deque(maxlen=1000)
        self.process_tracker = ProcessTracker()
        
        # Ensure data directory exists
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        # Initialize CSV if it doesn't exist
        if not os.path.exists(output_file):
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(CSV_HEADER)

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

        # Correlate with process using the tracker
        proc_info = self.process_tracker.get_process_info(dst_ip, dst_port, src_port)
        if not proc_info:
            proc_info = self.process_tracker.get_process_info(src_ip, src_port, dst_port)
        
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
                
                # Check cache before sniffing batch
                self.process_tracker.refresh_cache()
                
                # store=0 is critical for memory management in long-running captures
                sniff(prn=self.packet_callback, store=0, timeout=2) 
                self.flush_to_csv()
            except Exception as e:
                error_msg = str(e).lower()
                if "winpcap" in error_msg or "npcap" in error_msg or "layer 2" in error_msg:
                    log_event("CRITICAL ERROR: Npcap/WinPcap is not installed or not working.", "error")
                    sys.exit(1)
                
                log_event(f"Capture error: {e}", "error")
                time.sleep(5)

def main():
    import argparse
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

    from .logger import setup_logging
    setup_logging()
    
    collector = TrafficCollector(args.output, start_date, end_date)
    
    try:
        collector.run()
    except KeyboardInterrupt:
        log_event("Collector stopped by user.")
        collector.flush_to_csv()
