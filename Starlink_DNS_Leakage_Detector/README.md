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

This module performs large-scale DNS resolution over generated candidate Starlink infrastructure domains to identify exposed infrastructure assets through DNS leakage.

It resolves both:

- A records (IPv4)
- AAAA records (IPv6)

and stores all responsive domains for downstream infrastructure analysis.

## Usage

```bash
python dns_leakage_detector.py \
    --input generated_domains.txt \
    --output resolved_domains.jsonl \
    --workers 16
```

## Output Format

Each responsive domain is stored as one JSON object per line:

```json
{
  "domain": "example.starlinkisp.net",
  "ipv4": ["1.2.3.4"],
  "ipv6": ["2001:db8::1"]
}
```

This component is part of the Starlink DNS leakage measurement pipeline.