import re
import socket
import subprocess
import time
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "virus_scanner.log"
DEFENDER = Path(r"C:\Program Files\Windows Defender\MpCmdRun.exe")


def network_host():
    local_ip = socket.gethostbyname(socket.gethostname())
    return r"\\" + local_ip


def log(message, level="INFO"):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] [{level}] {message}"
    print(line, flush=True)
    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(line + "\n")


def scan_path(path, label):
    log(f"Starting {label}: {path}")
    result = subprocess.run(
        [str(DEFENDER), "-Scan", "-ScanType", "3", "-File", path],
        capture_output=True,
        text=True,
        timeout=8 * 60 * 60,
    )
    if result.stdout:
        log(result.stdout.strip())
    if result.stderr:
        log(result.stderr.strip(), "WARNING")
    if result.returncode == 0:
        log(f"Completed {label}: no threats reported")
    else:
        log(f"{label} returned Defender exit code {result.returncode}", "HIGH")
    return result.returncode


def network_shares():
    host = network_host()
    result = subprocess.run(
        ["net", "view", host],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        log(f"Could not enumerate network shares on {host}: {result.stderr.strip()}", "WARNING")
        return []

    shares = []
    for line in result.stdout.splitlines():
        match = re.match(r"^\s{2,}([^\s$]+)\s+Disk", line, re.IGNORECASE)
        if match:
            shares.append(f"{host}\\{match.group(1)}")
    return shares


def main():
    if not DEFENDER.exists():
        log(f"Windows Defender executable not found: {DEFENDER}", "CRITICAL")
        return 2

    log("Starting local and network virus scan")
    exit_codes = [scan_path(str(BASE_DIR.anchor), "local drive scan")]

    shares = network_shares()
    if not shares:
            log(f"No visible disk shares found on {network_host()}", "WARNING")
    for share in shares:
        exit_codes.append(scan_path(share, "network share scan"))

    if any(code != 0 for code in exit_codes):
        log("Scan completed with warnings or detected threats", "HIGH")
        return 1
    log("Local and network scan completed successfully")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())