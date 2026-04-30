import json
import argparse
from multiprocessing import Pool
import dns.resolver


DEFAULT_DNS_SERVER = "8.8.8.8"
DEFAULT_WORKERS = 16


def create_resolver(nameserver=DEFAULT_DNS_SERVER):
    """
    Create a DNS resolver instance.
    """
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [nameserver]
    return resolver


def resolve_record(domain, record_type, nameserver=DEFAULT_DNS_SERVER):
    """
    Resolve DNS records of a given type.
    """
    resolver = create_resolver(nameserver)

    try:
        response = resolver.resolve(domain, record_type)
        return sorted(str(record) for record in response)
    except Exception:
        return None


def resolve_domain(domain):
    """
    Resolve both A and AAAA records for a domain.
    """
    domain = domain.strip()

    ipv4_records = resolve_record(domain, "A")
    ipv6_records = resolve_record(domain, "AAAA")

    if not ipv4_records and not ipv6_records:
        return None

    return {
        "domain": domain,
        "ipv4": ipv4_records,
        "ipv6": ipv6_records
    }


def process_domains(input_file, output_file, workers):
    """
    Process domains in parallel and save results.
    """
    with open(input_file, "r", encoding="utf-8") as f:
        domains = f.readlines()

    with Pool(workers) as pool:
        results = pool.map(resolve_domain, domains)

    with open(output_file, "w", encoding="utf-8") as f:
        for result in results:
            if result:
                f.write(json.dumps(result) + "\n")

    print(f"Results saved to: {output_file}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Starlink DNS leakage detection via candidate domain resolution."
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
        "-w",
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help="Number of worker processes"
    )

    return parser.parse_args()


def main():
    args = parse_args()

    process_domains(
        input_file=args.input,
        output_file=args.output,
        workers=args.workers
    )


if __name__ == "__main__":
    main()