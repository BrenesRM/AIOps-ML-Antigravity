import logging
import sys
from .config import LOG_SOURCE

# Attempt to import Windows Event Log utilities
try:
    import win32evtlogutil
    import win32evtlog
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False

def setup_logging():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

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
