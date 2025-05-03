import win32evtlog
import time
from collections import defaultdict

server = 'localhost'
log_type = 'Security'
event_ids = [4624, 4625]  # 4624 = login success, 4625 = login failure

# Keep track of already seen records to avoid duplicates
seen_records = set()
failed_attempts = defaultdict(int)

def get_events():
    hand = win32evtlog.OpenEventLog(server, log_type)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    events = win32evtlog.ReadEventLog(hand, flags, 0)
    new_logs = []

    for event in events:
        if event.EventID not in event_ids:
            continue

        if event.RecordNumber in seen_records:
            continue

        seen_records.add(event.RecordNumber)
        data = event.StringInserts
        if not data: continue

        entry = {
            'event_id': event.EventID,
            'username': data[5],
            'ip': data[18],
            'status': 'FAILED' if event.EventID == 4625 else 'SUCCESS',
            'time': event.TimeGenerated.strftime("%Y-%m-%d %H:%M:%S")
        }
        new_logs.append(entry)

    win32evtlog.CloseEventLog(hand)
    return new_logs

print("[🔍 Real-Time Login Monitor Started]")
try:
    while True:
        events = get_events()
        if events:
            for e in reversed(events):  # Show newest first
                if e['status'] == 'FAILED':
                    failed_attempts[e['username']] += 1
                print(f"[{e['status']}] {e['username']} at {e['time']} | IP: {e['ip'] or 'N/A'}")

        time.sleep(2)  # Adjust frequency of polling here

except KeyboardInterrupt:
    print("\n[🛑 Stopped by user]")
    print("\n[📊 Failed Attempt Summary]")
    for user, count in failed_attempts.items():
        print(f" - {user}: {count} failed attempts")
