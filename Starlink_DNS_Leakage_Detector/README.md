# Domain Generator

This module implements a rule-based domain generation algorithm for Starlink infrastructure hostname enumeration.

The naming patterns are summarized from observed infrastructure device naming conventions and are used to generate candidate domains for large-scale DNS resolution and infrastructure discovery.

## Usage

```bash
python domain_generator.py
```

## Generated output:

```
generated_domains.txt
```

This component is part of the Starlink DNS leakage measurement pipeline.

# DNS Leakage Detector

This module performs large-scale DNS resolution on generated Starlink infrastructure candidate domain names. By identifying resolvable domains and their associated IP addresses, it discovers potential infrastructure nodes and provides data support for subsequent network topology analysis and infrastructure identification.

The program adopts an asynchronous DNS resolution architecture and supports high-concurrency batch queries. It can simultaneously resolve:

- A records (IPv4 addresses)
- AAAA records (IPv6 addresses)

Resolution results are stored in JSON Lines (JSONL) format, facilitating subsequent data processing and analysis.

## Requirements

- Python 3.9 or later

Install dependencies:

```bash
pip install dnspython tqdm
```

## Usage

Run with default settings:

```bash
python dns_leakage_detector.py
```

Specify input and output files:

```bash
python dns_leakage_detector.py --input generated_domains.txt --output resolved_domains.jsonl
```

Specify concurrency level:

```bash
python dns_leakage_detector.py --input generated_domains.txt --output resolved_domains.jsonl --concurrency 1000
```

## Parameters

| Parameter       | Description                               |
| --------------- | ----------------------------------------- |
| `--input`       | Input file containing candidate domains   |
| `--output`      | Output JSONL file                         |
| `--concurrency` | Number of concurrent asynchronous queries |

## Output Format

Each successfully resolved domain is stored as a single JSON object per line:

```json
{
  "domain": "example.starlinkisp.net",
  "ipv4": ["1.2.3.4"],
  "ipv6": ["2001:db8::1"]
}
```

Field descriptions:

| Field    | Description                       |
| -------- | --------------------------------- |
| `domain` | Successfully resolved domain name |
| `ipv4`   | List of associated IPv4 addresses |
| `ipv6`   | List of associated IPv6 addresses |

## Features

- High-concurrency DNS resolution based on asynchronous coroutines
- Simultaneous resolution of A and AAAA records
- Load balancing across multiple public DNS resolvers
- Built-in DNS timeout control mechanism
- Real-time progress monitoring
- Automatic statistics for resolution exceptions (e.g., NXDOMAIN, Timeout)
- JSONL output format for efficient downstream processing
- Support for large-scale batch resolution of candidate domains

## Recommended Configuration

| Number of Domains        | Recommended Concurrency |
| ------------------------ | ----------------------- |
| Less than 100K           | 200                     |
| 100K – 1M                | 500                     |
| More than 1M             | 1000                    |
| High-performance servers | 1000–2000               |

## Notes

This module is one of the core components of the Starlink DNS Leakage Measurement Pipeline. By performing large-scale DNS resolution on candidate domains, it can identify infrastructure information exposed through DNS configurations and provide foundational data for subsequent infrastructure identification, network measurements, and topology construction.