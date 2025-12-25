import os

# Logging configuration
LOG_SOURCE = "KodiakAiOps-Collector"

# Data configuration
CSV_FILE = "data/network_traffic_data.csv"
CSV_HEADER = [
    "timestamp", "process_path", "process_hash", "source_ip", "dest_ip",
    "dest_domain", "dest_port", "bytes_sent", "bytes_recv", "protocol",
    "dns_query", "parent_process", "user_context"
]

# Cache configuration
CACHE_DURATION = 2.0  # Seconds
