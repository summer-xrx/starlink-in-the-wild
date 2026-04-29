import schedule
import datetime
import time
import ipaddress
import platform
import subprocess
import re
import sys
from pathlib import Path
import os
import stat
import argparse

"""
Daily automated pipeline for:

1. Expand IPv4 prefixes into individual IPs
2. Run liveness scan
3. Run PTR scan
4. Build prefix-to-domain mappings
5. Extract POP deployment information
"""


# =========================
# Path Configuration
# =========================
BASE_DIR = Path(__file__).resolve().parent
# print(BASE_DIR)
INPUT_DIR = BASE_DIR / "input"
OUTPUT_DIR = BASE_DIR / "output"

INPUT_PREFIX_FILE = INPUT_DIR / "ipv4_splitted_24.txt"
INPUT_SINGLE_FILE = INPUT_DIR / "IPv4single.txt"

PTR_RESULT_DIR = OUTPUT_DIR / "ptrScanResult"
LIVENESS_RESULT_DIR = OUTPUT_DIR / "LivenessScanResult"
MONITOR_RESULT_DIR = OUTPUT_DIR / "monitorresult"
POP_RESULT_DIR = OUTPUT_DIR / "popresult"


def init_dirs():
    """
    Create required directories.
    """
    for path in [
        INPUT_DIR,
        OUTPUT_DIR,
        PTR_RESULT_DIR,
        LIVENESS_RESULT_DIR,
        MONITOR_RESULT_DIR,
        POP_RESULT_DIR
    ]:
        path.mkdir(parents=True, exist_ok=True)


def get_date():
    """
    Return current date in YYYYMMDD format.
    """
    return datetime.datetime.now().strftime("%Y%m%d")


def get_short_date():
    """
    Return current date in MMDD format.
    """
    return datetime.datetime.now().strftime("%m%d")


def extract_domain(line):
    """
    Extract PTR domain from dnsx output.

    Compatible with:
    - Windows output
    - Linux output (with ANSI colors)
    """
    # Remove ANSI color codes
    line = re.sub(r'\x1b\[[0-9;]*m', '', line)

    # Extract content inside []
    matches = re.findall(r'\[([^\]]+)\]', line)

    # Skip PTR tag itself
    for item in matches:
        if item.upper() != "PTR":
            return item

    return None


def aggregate_ipv4_networks(networks):
    """
    Aggregate multiple IPv4 prefixes into larger CIDRs.

    Args:
        networks: list of IPv4 CIDRs

    Returns:
        [total_ip_count, aggregated_prefixes]
    """
    try:
        ipv4_networks = [
            ipaddress.ip_network(net)
            for net in networks
        ]

        aggregated = list(
            ipaddress.collapse_addresses(ipv4_networks)
        )

        result = []
        total_ips = 0

        for net in aggregated:
            total_ips += net.num_addresses
            result.append(str(net))

        return [total_ips, sorted(result)]

    except ValueError as e:
        print(f"[ERROR] {e}")
        return []
    
def ensure_executable(file_path):
    """
    Ensure the file is executable on Unix-like systems.
    """
    if platform.system() != "Windows":
        current_mode = os.stat(file_path).st_mode

        # Add execute permission: chmod +x
        os.chmod(
            file_path,
            current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        )

def expand_ip():
    """
    Expand IPv4 prefixes into individual IPs.
    """
    command = [
    sys.executable,
    str(BASE_DIR / "expand_ips.py"),
    str(INPUT_PREFIX_FILE),
    str(INPUT_SINGLE_FILE)
    ]
    subprocess.run(command)

    print("[EXPAND] Finished")


def scan_liveness():
    """
    Run liveness scan using xmap.
    """
    filename = (
        LIVENESS_RESULT_DIR /
        f"LivenessScanResult{get_short_date()}.txt"
    )

    command = [
        "xmap",
        "-4",
        "-I",
        str(INPUT_SINGLE_FILE),
        "-R",
        "1000",
        "-o",
        str(filename)
    ]

    subprocess.run(command)

    print(f"[LIVENESS] Finished: {filename}")


def scan_ptr():
    """
    Run PTR scan using dnsx.
    """
    filename = (
        PTR_RESULT_DIR /
        f"scanresult{get_date()}.txt"
    )


    dnsx = BASE_DIR / (
    "dnsx.exe"
    if platform.system() == "Windows"
    else "dnsx"
    )

    # Auto chmod +x on Linux/macOS
    ensure_executable(dnsx)

    command = [
        dnsx,
        "-l",
        str(INPUT_PREFIX_FILE),
        "-rl",
        "10000",
        "-silent",
        "-resp",
        "-ptr"
    ]

    with open(filename, "w", encoding="utf-8") as f:
        subprocess.run(command, stdout=f)

    print(f"[PTR] Finished: {filename}")


def monitor():
    """
    Build prefix-to-PTR-domain mapping.
    """
    filename = get_date()

    mapping_relationship = {}

    with open(INPUT_PREFIX_FILE, "r") as f:
        ipsegments = f.readlines()

    for ipsegment in ipsegments:
        prefix = ".".join(
            ipsegment.strip().split(".")[:3]
        )

        mapping_relationship[prefix] = set()

    scan_result_file = (
        PTR_RESULT_DIR /
        f"scanresult{filename}.txt"
    )

    with open(scan_result_file, "r") as f:
        scanned_items = f.readlines()

    for scanned_item in scanned_items:
        ip = ".".join(
            scanned_item.split(" ")[0].split(".")[:3]
        )

        domain = extract_domain(scanned_item)

        if domain:
            mapping_relationship[ip].add(domain)

    output_file = (
        MONITOR_RESULT_DIR /
        f"monitorresult{filename}.txt"
    )

    with open(output_file, "w") as f:
        for prefix, domains in mapping_relationship.items():
            result = prefix + '\t'

            for domain in domains:
                result += domain + ','

            result += '\n'

            f.write(result)

    print(f"[MONITOR] Finished: {output_file}")


def get_pop():
    """
    Extract POP deployment information.
    """
    filename = get_date()

    monitor_file = (
        MONITOR_RESULT_DIR /
        f"monitorresult{filename}.txt"
    )

    with open(monitor_file, "r") as f:
        items = f.readlines()

    result_pop = {}
    result_spacex = {}
    result_debate = {}

    for item in items:
        prefix = item.split('\t')[0]
        ptr = item.split('\t')[1].strip()

        ip_range = prefix + '.0/24'

        if 'starlink' in item:
            if len(ptr.split(',')) > 2:
                result_debate.setdefault(
                    ptr, set()
                ).add(ip_range)

            elif len(ptr.split(',')) == 2:
                ptr_name = ptr.split(',')[0]

                result_pop.setdefault(
                    ptr_name, set()
                ).add(ip_range)

        elif 'spacex' in item:
            result_spacex.setdefault(
                ptr, set()
            ).add(ip_range)

    output_file = (
        POP_RESULT_DIR /
        f"popresult{filename}.txt"
    )

    with open(output_file, "w") as f:
        for dataset in [
            result_pop,
            result_debate,
            result_spacex
        ]:
            for hostname in sorted(dataset.keys()):
                tmp = aggregate_ipv4_networks(
                    dataset[hostname]
                )

                ip_ranges = ",".join(tmp[1])

                result = (
                    hostname
                    + '\t'
                    + str(tmp[0])
                    + '\t'
                    + ip_ranges
                )

                f.write(result + '\n')

    print(f"[POP] Finished: {output_file}")


def run_pipeline():
    """
    Run the full pipeline sequentially.
    """
    print("[SYSTEM] Pipeline started")

    expand_ip()
    scan_liveness()
    scan_ptr()
    monitor()
    get_pop()

    print("[SYSTEM] Pipeline finished")


def main():
    """
    Main entry point.

    Modes:
    1. Immediate mode:
       Run the full pipeline immediately.

    2. Scheduled mode:
       Run the full pipeline once per day
       at a specified time.
    """
    init_dirs()

    parser = argparse.ArgumentParser(
        description="Daily IP scanning pipeline"
    )

    parser.add_argument(
        "--mode",
        choices=["immediate", "scheduled"],
        default="immediate",
        help="Run mode"
    )

    parser.add_argument(
        "--time",
        default="10:00",
        help="Scheduled execution time (HH:MM)"
    )

    args = parser.parse_args()

    # Immediate mode
    if args.mode == "immediate":
        run_pipeline()

    # Scheduled mode
    elif args.mode == "scheduled":
        schedule.every().day.at(args.time).do(
            run_pipeline
        )

        print(
            f"[SYSTEM] Scheduler started "
            f"(daily at {args.time})"
        )

        while True:
            schedule.run_pending()
            time.sleep(1)


if __name__ == "__main__":
    main()