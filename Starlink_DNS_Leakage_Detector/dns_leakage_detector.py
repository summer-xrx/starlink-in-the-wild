import json
import argparse
import asyncio
import itertools
from collections import Counter

import dns.asyncresolver
import dns.resolver
from tqdm import tqdm


DNS_SERVERS = [
    "1.1.1.1",
    "8.8.8.8",
    "9.9.9.9",
]

DEFAULT_CONCURRENCY = 1000
DEFAULT_TIMEOUT = 5.0


stats = Counter()


def create_resolver(nameserver):
    resolver = dns.asyncresolver.Resolver(configure=False)

    resolver.nameservers = [nameserver]
    resolver.timeout = DEFAULT_TIMEOUT
    resolver.lifetime = DEFAULT_TIMEOUT

    return resolver


async def resolve_record(
    resolver,
    domain,
    record_type
):
    try:
        answer = await resolver.resolve(
            domain,
            record_type
        )

        return sorted(
            str(record)
            for record in answer
        )

    except dns.resolver.NXDOMAIN:
        stats["NXDOMAIN"] += 1

    except dns.resolver.NoAnswer:
        stats["NoAnswer"] += 1

    except dns.resolver.NoNameservers:
        stats["NoNameservers"] += 1

    except dns.exception.Timeout:
        stats["Timeout"] += 1

    except Exception:
        stats["OtherError"] += 1

    return None


async def resolve_domain(
    domain,
    resolver
):
    domain = domain.strip()

    ipv4_task = resolve_record(
        resolver,
        domain,
        "A"
    )

    ipv6_task = resolve_record(
        resolver,
        domain,
        "AAAA"
    )

    ipv4, ipv6 = await asyncio.gather(
        ipv4_task,
        ipv6_task
    )

    if not ipv4 and not ipv6:
        return None

    return {
        "domain": domain,
        "ipv4": ipv4,
        "ipv6": ipv6
    }


async def worker(
    queue,
    outfile,
    pbar,
    resolver
):
    while True:
        domain = await queue.get()

        if domain is None:
            queue.task_done()
            break

        try:
            result = await resolve_domain(
                domain,
                resolver
            )

            if result:
                outfile.write(
                    json.dumps(
                        result,
                        ensure_ascii=False
                    )
                    + "\n"
                )

        finally:
            pbar.update(1)
            queue.task_done()


async def process_domains(
    input_file,
    output_file,
    concurrency
):
    with open(
        input_file,
        "r",
        encoding="utf-8"
    ) as f:
        domains = [
            line.strip()
            for line in f
            if line.strip()
        ]

    queue = asyncio.Queue()

    for domain in domains:
        queue.put_nowait(domain)

    resolvers = [
        create_resolver(server)
        for server in DNS_SERVERS
    ]

    pbar = tqdm(
        total=len(domains),
        desc="Resolving"
    )

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as outfile:

        workers = []

        resolver_cycle = itertools.cycle(
            resolvers
        )

        for _ in range(concurrency):
            workers.append(
                asyncio.create_task(
                    worker(
                        queue,
                        outfile,
                        pbar,
                        next(resolver_cycle)
                    )
                )
            )

        await queue.join()

        for _ in workers:
            queue.put_nowait(None)

        await asyncio.gather(*workers)

    pbar.close()

    print()
    print(
        f"Results saved to: "
        f"{output_file}"
    )

    print("\nStatistics:")

    for key, value in stats.items():
        print(f"{key}: {value}")


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Starlink DNS leakage "
            "detection via candidate "
            "domain resolution."
        )
    )

    parser.add_argument(
        "-i",
        "--input",
        default="generated_domains.txt",
        help="Input domain list file"
    )

    parser.add_argument(
        "-o",
        "--output",
        default="resolved_domains.jsonl",
        help="Output JSONL file"
    )

    parser.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=DEFAULT_CONCURRENCY,
        help="Concurrent coroutines"
    )

    return parser.parse_args()


async def main():
    args = parse_args()

    await process_domains(
        input_file=args.input,
        output_file=args.output,
        concurrency=args.concurrency
    )


if __name__ == "__main__":
    asyncio.run(main())
