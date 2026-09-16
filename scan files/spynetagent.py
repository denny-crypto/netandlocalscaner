import time
import threading
import socket
import subprocess
import sys
from pathlib import Path
from collections import defaultdict

# =========================
# DATA
# =========================
threat_score = defaultdict(int)
packet_times = defaultdict(list)
known_devices = set()
last_alert_level = {}

LOG_FILE = Path(__file__).with_name("spynetagent.log")

# =========================
# ALERT SYSTEM (FILE LOG)
# =========================
def log(message, level="INFO"):
    timestamp = time.strftime("%H:%M:%S")
    line = f"[{timestamp}] [{level}] {message}"

    print(line)

    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

# =========================
# THREAT SYSTEM
# =========================
def update_score(ip, event):
    if event == "packet":
        threat_score[ip] += 1
    elif event == "spike":
        threat_score[ip] += 10
    elif event == "new_device":
        threat_score[ip] += 20

    evaluate(ip)

def evaluate(ip):
    score = threat_score[ip]

    if score > 100:
        level = "CRITICAL"
        message = f"{ip} HIGH THREAT"
    elif score > 50:
        level = "HIGH"
        message = f"{ip} suspicious"
    elif score > 20:
        level = "MEDIUM"
        message = f"{ip} unusual"
    else:
        return

    if last_alert_level.get(ip) != level:
        log(message, level)
        last_alert_level[ip] = level

# =========================
# NETWORK SCAN
# =========================
def ping(ip):
    return subprocess.run(
        ["ping", "-n", "1", "-w", "200", ip],
        stdout=subprocess.DEVNULL
    ).returncode == 0

def scan_network(base_ip):
    active = set()

    def check(i):
        ip = f"{base_ip}{i}"
        if ping(ip):
            active.add(ip)

    threads = []
    for i in range(1, 255):
        t = threading.Thread(target=check, args=(i,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    return active

# =========================
# MONITOR DEVICES
# =========================
def monitor_devices(base_ip):
    global known_devices

    known_devices = scan_network(base_ip)
    log(f"Baseline: {len(known_devices)} devices")

    while True:
        current = scan_network(base_ip)

        for ip in current:
            if ip not in known_devices:
                log(f"New device: {ip}", "HIGH")
                update_score(ip, "new_device")
                known_devices.add(ip)

        time.sleep(20)

# =========================
# OPTIONAL SIMULATED TRAFFIC
# =========================
def simulate_traffic():
    import random

    while True:
        if known_devices:
            ip = random.choice(list(known_devices))

            now = time.time()
            packet_times[ip].append(now)

            packet_times[ip] = [t for t in packet_times[ip] if now - t < 5]

            count = len(packet_times[ip])

            update_score(ip, "packet")

            if count > 20:
                update_score(ip, "spike")

        time.sleep(0.1)

# =========================
# DECAY
# =========================
def decay():
    while True:
        for ip in list(threat_score.keys()):
            threat_score[ip] = max(0, threat_score[ip] - 1)
        time.sleep(10)

# =========================
# MAIN
# =========================
def main():
    if len(sys.argv) > 1:
        base_ip = sys.argv[1]
    else:
        local_ip = socket.gethostbyname(socket.gethostname())
        base_ip = local_ip.rsplit(".", 1)[0] + "."

    log("Starting SpyNet Agent...")

    threading.Thread(target=monitor_devices, args=(base_ip,), daemon=True).start()
    if "--simulate" in sys.argv[1:]:
        log("Simulated traffic enabled", "WARNING")
        threading.Thread(target=simulate_traffic, daemon=True).start()
    threading.Thread(target=decay, daemon=True).start()

    while True:
        time.sleep(60)  # keep alive

if __name__ == "__main__":
    main()