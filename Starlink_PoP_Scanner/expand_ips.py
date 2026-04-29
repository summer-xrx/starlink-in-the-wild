#!/usr/bin/env python3
"""
expand_ips.py

Expand IPv4 ranges from an input file into individual IPv4 addresses
and write them into a new output file.

Supported input formats (one or multiple entries per line, comma-separated):
- Single IP: 1.2.3.4
- CIDR: 10.0.0.0/24
- Hyphenated range: 192.168.0.1-192.168.0.255
- Netmask notation: 10.0.0.0/255.255.255.0

Usage:
    python expand_ips.py input.txt output.txt

Parameters and behavior:
- Deduplication is enabled by default (dedupe=True).
  If the input file is extremely large and memory is limited,
  set DEDUPE=False.
- Output will be sorted by default when deduplication is enabled.
  Disable SORT_WHEN_DEDUPE if sorting is unnecessary.
- The script expands addresses in a streaming manner,
  making it suitable for large files.
"""

import sys
import ipaddress
from typing import Iterator


# ========== Configuration ==========
DEDUPE = True              # Whether to remove duplicate IPs
SORT_WHEN_DEDUPE = True    # Whether to sort output when deduplication is enabled
PROGRESS_EVERY = 100000    # Print progress every N written IPs (0 disables progress output)
# ==================================


def parse_item(item: str) -> Iterator[ipaddress.IPv4Address]:
    """
    Parse a single input item into an iterator of IPv4Address objects.

    Supported formats:
    - Single IP
    - CIDR
    - IP range (start-end)
    - IP/netmask
    """
    if not item:
        return
        yield  # Keep it as a generator (never reached)

    # 1) Try CIDR or netmask format
    # ip_network supports formats like /255.255.255.0
    if '/' in item:
        try:
            net = ipaddress.ip_network(item.strip(), strict=False)

            # Include all addresses in the network
            # (including network and broadcast addresses)
            for ip in net.hosts() if False else net:
                yield ip
            return
        except Exception:
            # If parsing fails, continue trying other formats
            pass

    # 2) Hyphenated range: start-end
    if '-' in item:
        parts = item.split('-')
        if len(parts) == 2:
            a = parts[0].strip()
            b = parts[1].strip()

            try:
                ia = int(ipaddress.IPv4Address(a))
                ib = int(ipaddress.IPv4Address(b))

                if ia <= ib:
                    for n in range(ia, ib + 1):
                        yield ipaddress.IPv4Address(n)
                    return
                else:
                    # Reverse range: still process in ascending order
                    for n in range(ib, ia + 1):
                        yield ipaddress.IPv4Address(n)
                    return

            except Exception:
                pass

    # 3) Single IP
    try:
        ip = ipaddress.IPv4Address(item)
        yield ip
        return
    except Exception:
        pass

    # 4) If all parsing attempts fail, print warning and ignore
    print(f"Warning: Unable to parse entry: {item}", file=sys.stderr)
    return


def expand_file(in_path: str, out_path: str):
    """
    Expand all IPv4 entries from the input file and write results to output file.
    """
    seen = set() if DEDUPE else None
    buffer = []  # Temporary buffer for sorting when deduplication is enabled
    written = 0

    try:
        with open(in_path, 'r', encoding='utf-8') as fin:

            # If deduplication and sorting are both enabled,
            # collect all IPs first (memory intensive)
            if DEDUPE and SORT_WHEN_DEDUPE:
                for lineno, raw in enumerate(fin, 1):
                    line = raw.strip()

                    if not line or line.startswith('#'):
                        continue

                    # Support multiple comma-separated entries per line
                    for part in [p.strip() for p in line.split(',') if p.strip()]:
                        for ip in parse_item(part):
                            s = str(ip)

                            if s not in seen:
                                seen.add(s)
                                buffer.append(s)

                    if (lineno % 100000) == 0:
                        print(f"Read {lineno} lines...", file=sys.stderr)

                # Sort and write results
                buffer.sort(key=lambda x: int(ipaddress.IPv4Address(x)))

                with open(out_path, 'w', encoding='utf-8') as fout:
                    for i, s in enumerate(buffer, 1):
                        fout.write(s + '\n')

                        if PROGRESS_EVERY and (i % PROGRESS_EVERY == 0):
                            print(f"Wrote {i} IPs...", file=sys.stderr)

                written = len(buffer)
                print(f"Done. Wrote {written} unique IPs to {out_path}.")
                return

            # Otherwise process and write in streaming mode
            with open(out_path, 'w', encoding='utf-8') as fout:
                for lineno, raw in enumerate(fin, 1):
                    line = raw.strip()

                    if not line or line.startswith('#'):
                        continue

                    for part in [p.strip() for p in line.split(',') if p.strip()]:
                        for ip in parse_item(part):
                            s = str(ip)

                            if DEDUPE:
                                if s in seen:
                                    continue
                                seen.add(s)

                            fout.write(s + '\n')
                            written += 1

                            if PROGRESS_EVERY and (written % PROGRESS_EVERY == 0):
                                print(f"Wrote {written} IPs...", file=sys.stderr)

                print(f"Done. Wrote {written} IPs to {out_path}.")

    except FileNotFoundError:
        print(f"Error: Input file not found: {in_path}", file=sys.stderr)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)


def main():
    """
    Program entry point.
    """
    if len(sys.argv) < 3:
        print("Usage: python expand_ips.py input.txt output.txt")
        sys.exit(1)

    in_path = sys.argv[1]
    out_path = sys.argv[2]

    expand_file(in_path, out_path)


if __name__ == "__main__":
    main()