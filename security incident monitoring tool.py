import os
import time
import psutil
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SENDER_EMAIL = "youremail@example.com"
RECEIVER_EMAIL = "receiver@example.com"
EMAIL_PASSWORD = "yourpassword"
SMTP_SERVER = "smtp.example.com"
SMTP_PORT = 587

def send_alert(subject, message):
    msg = MIMEMultipart()
    msg['From'] = SENDER_EMAIL
    msg['To'] = RECEIVER_EMAIL
    msg['Subject'] = subject

    msg.attach(MIMEText(message, 'plain'))
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, EMAIL_PASSWORD)
            text = msg.as_string()
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, text)
    except Exception as e:
        print(f"Failed to send email: {e}")

def monitor_failed_logins():
    failed_logins = "/var/log/auth.log"
    with open(failed_logins, "r") as f:
        lines = f.readlines()
    
    for line in lines[-20:]:
        if "Failed password" in line:
            print(f"Suspicious failed login attempt detected: {line}")
            send_alert("Suspicious Failed Login Attempt", f"Detected: {line}")

def monitor_network():
    net_io = psutil.net_io_counters()
    sent_before = net_io.bytes_sent
    recv_before = net_io.bytes_recv

    time.sleep(5)

    net_io = psutil.net_io_counters()
    sent_after = net_io.bytes_sent
    recv_after = net_io.bytes_recv

    sent_diff = sent_after - sent_before
    recv_diff = recv_after - recv_before

    if sent_diff > 1000000 or recv_diff > 1000000:
        print(f"Network traffic spike detected: Sent={sent_diff} bytes, Received={recv_diff} bytes")
        send_alert("Network Traffic Spike", f"Sent: {sent_diff} bytes, Received: {recv_diff} bytes")

if __name__ == "__main__":
    while True:
        monitor_failed_logins()
        monitor_network()
        time.sleep(10)
