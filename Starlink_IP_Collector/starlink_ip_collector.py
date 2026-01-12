#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Starlink IP Collector (Engineering-grade)

Collect prefixes for given ASNs from:
- bgp.he.net
- bgp.tools
- whois.ipip.net
- geoip.starlinkisp.net (CSV feed)

Outputs:
out/<run_id>/
  ├─ HE/
  ├─ BGP.tools/
  ├─ IPIP/
  ├─ geoip/
  └─ final/
      ├─ collected_ipv4.txt
      ├─ collected_ipv6.txt
      ├─ all_target_ipv4_aggregated.txt
      ├─ all_target_ipv6_aggregated.txt
      └─ ipv4_splitted_<prefix>.txt
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import dataclasses
import logging
import re
import sys
from pathlib import Path
from typing import Iterable, List, Set, Tuple, Optional, Dict

import ipaddress
import requests
from bs4 import BeautifulSoup

try:
    from urllib3.util.retry import Retry
    from requests.adapters import HTTPAdapter
except Exception:
    Retry = None
    HTTPAdapter = None


DEFAULT_ASNS = [14593, 27277, 45700, 397763]
DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

CIDR_HINT_RE = re.compile(r"^[0-9a-fA-F:.]+/\d{1,3}$")


@dataclasses.dataclass(frozen=True)
class FetchConfig:
    timeout: float
    retries: int
    backoff: float
    user_agent: str


@dataclasses.dataclass
class SourceResult:
    source: str
    asn: Optional[int]
    ipv4: Set[str]
    ipv6: Set[str]
    raw: List[str]


def setup_logger(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def build_session(cfg: FetchConfig) -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": cfg.user_agent})

    if Retry is not None and HTTPAdapter is not None:
        retry = Retry(
            total=cfg.retries,
            connect=cfg.retries,
            read=cfg.retries,
            status=cfg.retries,
            backoff_factor=cfg.backoff,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET"]),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        s.mount("http://", adapter)
        s.mount("https://", adapter)

    return s


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def classify_prefixes(candidates: Iterable[str]) -> Tuple[Set[str], Set[str], List[str]]:
    ipv4, ipv6 = set(), set()
    raw_valid: List[str] = []

    for x in candidates:
        if not x:
            continue
        x = x.strip()
        if not x or "/" not in x:
            continue
        if not CIDR_HINT_RE.match(x):
            continue

        try:
            net = ipaddress.ip_network(x, strict=False)
        except ValueError:
            continue

        raw_valid.append(str(net))
        if isinstance(net, ipaddress.IPv4Network):
            ipv4.add(str(net))
        else:
            ipv6.add(str(net))

    return ipv4, ipv6, raw_valid


def write_lines(path: Path, lines: Iterable[str]) -> None:
    ensure_dir(path.parent)
    with path.open("w", encoding="utf-8") as f:
        for line in lines:
            f.write(f"{line}\n")


def fetch_text(session: requests.Session, url: str, timeout: float) -> str:
    r = session.get(url, timeout=timeout)
    r.raise_for_status()
    return r.text


def parse_he(html: str) -> List[str]:
    soup = BeautifulSoup(html, "html.parser")
    res: List[str] = []

    for block_id in ("prefixes", "prefixes6"):
        block = soup.find("div", id=block_id)
        if not block:
            continue
        for a in block.find_all("a"):
            txt = (a.get_text() or "").strip()
            if txt:
                res.append(txt)
    return res


def parse_bgp_tools(html: str) -> List[str]:
    soup = BeautifulSoup(html, "html.parser")
    res: List[str] = []

    tables = soup.find_all("table", id="fhTable")
    if len(tables) > 2:
        tables = tables[:2]

    for t in tables:
        for a in t.find_all("a"):
            txt = (a.get_text() or "").strip()
            if txt:
                res.append(txt)
    return res


def parse_ipip(html: str) -> List[str]:
    soup = BeautifulSoup(html, "html.parser")
    res: List[str] = []

    blocks = soup.find_all("div", class_="table-responsive")
    if len(blocks) > 2:
        blocks = blocks[:2]

    for b in blocks:
        for a in b.find_all("a"):
            txt = (a.get_text() or "").strip()
            if txt:
                res.append(txt)
    return res


def collect_from_he(session: requests.Session, asn: int, cfg: FetchConfig) -> SourceResult:
    url = f"https://bgp.he.net/AS{asn}"
    logging.debug(f"[HE] Fetching {url}")
    html = fetch_text(session, url, cfg.timeout)
    candidates = parse_he(html)
    ipv4, ipv6, raw_valid = classify_prefixes(candidates)
    return SourceResult("HE", asn, ipv4, ipv6, raw_valid)


def collect_from_bgp_tools(session: requests.Session, asn: int, cfg: FetchConfig) -> SourceResult:
    url = f"https://bgp.tools/as/{asn}"
    logging.debug(f"[BGP.tools] Fetching {url}")
    html = fetch_text(session, url, cfg.timeout)
    candidates = parse_bgp_tools(html)
    ipv4, ipv6, raw_valid = classify_prefixes(candidates)
    return SourceResult("BGP.tools", asn, ipv4, ipv6, raw_valid)


def collect_from_ipip(session: requests.Session, asn: int, cfg: FetchConfig) -> SourceResult:
    url = f"https://whois.ipip.net/AS{asn}"
    logging.debug(f"[IPIP] Fetching {url}")
    html = fetch_text(session, url, cfg.timeout)
    candidates = parse_ipip(html)
    ipv4, ipv6, raw_valid = classify_prefixes(candidates)
    return SourceResult("IPIP", asn, ipv4, ipv6, raw_valid)


def collect_from_geoip(session: requests.Session, cfg: FetchConfig) -> SourceResult:
    url = "https://geoip.starlinkisp.net/feed.csv"
    logging.debug(f"[geoip] Fetching {url}")
    text = fetch_text(session, url, cfg.timeout)

    candidates = []
    for line in text.splitlines():
        if not line.strip():
            continue
        prefix = line.split(",", 1)[0].strip()
        if prefix:
            candidates.append(prefix)

    ipv4, ipv6, raw_valid = classify_prefixes(candidates)
    return SourceResult("geoip", None, ipv4, ipv6, raw_valid)


def aggregate_networks(prefixes: Iterable[str]) -> List[str]:
    nets = []
    for p in prefixes:
        try:
            nets.append(ipaddress.ip_network(p, strict=False))
        except ValueError:
            continue
    return [str(x) for x in ipaddress.collapse_addresses(nets)]


def split_ipv4_to_prefix(prefixes: Iterable[str], new_prefix: int) -> List[str]:
    out = []
    for p in prefixes:
        try:
            net = ipaddress.ip_network(p, strict=False)
        except ValueError:
            continue
        if not isinstance(net, ipaddress.IPv4Network):
            continue
        if net.prefixlen > new_prefix:
            out.append(str(net))
        else:
            out.extend(str(s) for s in net.subnets(new_prefix=new_prefix))
    return out


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description="Collect and aggregate Starlink-related IP prefixes.")
    parser.add_argument("--run-id", default=None, help="Output folder name (e.g. 20260112).")
    parser.add_argument("--out", default="out", help="Base output directory.")
    parser.add_argument("--asn", nargs="*", type=int, default=DEFAULT_ASNS, help="Target ASNs.")
    parser.add_argument("--split-prefix", type=int, default=24, help="Split IPv4 to /N.")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--backoff", type=float, default=0.6)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--no-concurrency", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    setup_logger(args.verbose)

    run_id = args.run_id or input("Enter run identifier (e.g. 20260112): ").strip()
    if not run_id:
        logging.error("run-id must not be empty")
        return 2

    base = Path(args.out) / run_id
    ensure_dir(base)

    cfg = FetchConfig(args.timeout, args.retries, args.backoff, DEFAULT_UA)
    session = build_session(cfg)

    results: List[SourceResult] = []

    def safe(fn, *a):
        try:
            return fn(*a)
        except Exception as e:
            logging.warning(f"Failed: {e}")
            return None

    tasks = []
    for asn in args.asn:
        tasks += [
            lambda a=asn: collect_from_he(session, a, cfg),
            lambda a=asn: collect_from_bgp_tools(session, a, cfg),
            lambda a=asn: collect_from_ipip(session, a, cfg),
        ]

    if args.no_concurrency:
        for t in tasks:
            r = safe(t)
            if r:
                results.append(r)
        r = safe(lambda: collect_from_geoip(session, cfg))
        if r:
            results.append(r)
    else:
        with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = [ex.submit(safe, t) for t in tasks]
            futs.append(ex.submit(safe, lambda: collect_from_geoip(session, cfg)))
            for f in cf.as_completed(futs):
                r = f.result()
                if r:
                    results.append(r)

    all_v4, all_v6 = set(), set()
    for r in results:
        all_v4 |= r.ipv4
        all_v6 |= r.ipv6

    final = base / "final"
    ensure_dir(final)

    write_lines(final / "collected_ipv4.txt", sorted(all_v4))
    write_lines(final / "collected_ipv6.txt", sorted(all_v6))

    agg_v4 = aggregate_networks(all_v4)
    agg_v6 = aggregate_networks(all_v6)

    write_lines(final / "all_target_ipv4_aggregated.txt", agg_v4)
    write_lines(final / "all_target_ipv6_aggregated.txt", agg_v6)

    split_v4 = split_ipv4_to_prefix(agg_v4, args.split_prefix)
    write_lines(final / f"ipv4_splitted_{args.split_prefix}.txt", sorted(set(split_v4)))

    logging.info("Completed successfully.")
    logging.info(f"IPv4 collected: {len(all_v4)}, aggregated: {len(agg_v4)}, split: {len(set(split_v4))}")
    logging.info(f"IPv6 collected: {len(all_v6)}, aggregated: {len(agg_v6)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
