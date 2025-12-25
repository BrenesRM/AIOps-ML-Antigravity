import psutil
import time
import os
import hashlib
import logging
from .config import CACHE_DURATION

class ProcessTracker:
    def __init__(self):
        self.process_details_cache = {} # PID -> {path, hash, user}
        self.connection_map = {} # (local_port, remote_ip, remote_port) -> PID
        self.last_cache_update = 0
        self.CACHE_DURATION = CACHE_DURATION

    def refresh_cache(self):
        """Builds a snapshot of current network connections."""
        current_time = time.time()
        if current_time - self.last_cache_update < self.CACHE_DURATION:
            return

        self.connection_map.clear()
        try:
            # Snapshot all connections at once
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    # Key: (LocalPort, RemoteIP, RemotePort)
                    key = (conn.laddr.port, conn.raddr.ip, conn.raddr.port)
                    self.connection_map[key] = conn.pid
            
            self.last_cache_update = current_time
        except Exception as e:
            logging.error(f"Cache refresh failed: {e}")

    def get_process_info(self, remote_ip, remote_port, local_port):
        """Finds the process associated with a network connection using cached snapshot."""
        # 1. Look up PID in connection map
        key = (local_port, remote_ip, remote_port)
        pid = self.connection_map.get(key)
        
        if not pid:
            return None

        # 2. Look up Process Details (Path, User, etc.)
        if pid in self.process_details_cache:
            return self.process_details_cache[pid]
        
        # 3. If details missing, fetch and cache them
        try:
            proc = psutil.Process(pid)
            pproc = proc.parent()
            
            path = proc.exe()
            name = proc.name()
            ppath = pproc.exe() if pproc else "unknown"
            
            # Process Hash
            file_hash = "unknown"
            if os.path.exists(path):
                try:
                    with open(path, "rb") as f:
                        file_hash = hashlib.md5(f.read()).hexdigest()
                except (PermissionError, OSError):
                    pass
            
            # User Context / IIS detection
            user_context = proc.username()
            if name.lower() == "w3wp.exe":
                cmdline = proc.cmdline()
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
            self.process_details_cache[pid] = info
            return info

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None
        except Exception:
            return None
