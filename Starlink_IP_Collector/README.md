# Starlink IP Collector

Minimal Python script for collecting, aggregating, and splitting Starlink-related IP prefixes from multiple public sources.  
Requires Python 3.9+. Install dependencies with: `pip install requests beautifulsoup4`.

Usage example:
`python starlink_ip_collector.py --run-id 20250912`

Common usage:
`python starlink_ip_collector.py --run-id 20250912 --asn 14593 27277 45700 397763 --split-prefix 24`

Arguments:  
`--run-id` output directory name;  
`--out` base output directory (default: `out`);  
`--asn` target ASNs;  
`--split-prefix` split IPv4 into `/N` (default: `24`);  
`--timeout` HTTP timeout (default: `10`);  
`--retries` HTTP retries (default: `3`);  
`--workers` concurrent workers;  
`--verbose` enable debug logging.

Output files are written to `out/<run-id>/final/`, including aggregated IPv4/IPv6 prefix lists and an IPv4 `/N` split list.

Notes: built-in timeout, retry, and concurrency support; intended as a small reusable module rather than a standalone product.
