import win32evtlog
import datetime
from collections import defaultdict

# === CONFIG ===
LOG_TYPE = 'Security'
EVENT_IDS = [4625, 4624]  # 4625 = failed, 4624 = successful

def parse_event(record):
    data = record.StringInserts
    if not data: return None

    return {
        'event_id': record.EventID,
        'username': data[5],   # User Name
        'workstation': data[11],  # Workstation
        'ip': data[18],        # IP Address (if any)
        'status': 'FAILED' if record.EventID == 4625 else 'SUCCESS',
        'time': record.TimeGenerated.strftime("%Y-%m-%d %H:%M:%S")
    }

def monitor_logins():
    print(f"\n[🔐 LOGIN MONITOR STARTED - {LOG_TYPE} LOG]")

    failed_attempts = defaultdict(int)

    server = 'localhost'
    hand = win32evtlog.OpenEventLog(server, LOG_TYPE)

    total = win32evtlog.GetNumberOfEventLogRecords(hand)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    read = 0
    while read < 200:  # Adjust how many logs to check
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if not events:
            break

        for event in events:
            if event.EventID in EVENT_IDS:
                entry = parse_event(event)
                if entry:
                    if entry['status'] == 'FAILED':
                        failed_attempts[entry['username']] += 1
                    print(f"[{entry['status']}] {entry['username']} | {entry['time']} | IP: {entry['ip'] or 'N/A'}")
                    read += 1
                    if read >= 200:
                        break

    print("\n[📊 SUMMARY OF FAILED ATTEMPTS]")
    for user, count in failed_attempts.items():
        print(f" - {user}: {count} failed attempts")

    win32evtlog.CloseEventLog(hand)

if __name__ == "__main__":
    try:
        monitor_logins()
    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")
