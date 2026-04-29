<<<<<<< HEAD
# Starlink_PoP_Scanner

StarlinkPoPScanner is an automated measurement pipeline for discovering and monitoring Starlink Point-of-Presence (PoP) deployments through large-scale IPv4 PTR scanning and liveness probing.

The pipeline performs:

1. Liveness scanning
2. PTR record scanning

------

## Features

- Cross-platform support (Linux / Windows)
- Automated daily scheduled scanning
- Immediate one-shot scanning mode
- PTR record extraction
- SpaceX infrastructure identification

------

## Project Structure

```text
StarlinkPoPScanner/
├── PoP2.py
├── expand_ips.py
├── dnsx              # Linux binary
├── dnsx.exe          # Windows binary
├── input/
│   └── ipv4_splitted_24.txt
└── output/
    ├── ptrScanResult/
    ├── LivenessScanResult/
    ├── monitorresult/
    └── popresult/
```

------

## Requirements

### Python

Python 3.10+

Install dependencies:

```bash
pip install schedule
```

------

### External Tools

#### dnsx

Used for PTR scanning.

Place the binary in the project root:

Linux:

```text
dnsx
```

Windows:

```text
dnsx.exe
```

------

#### xmap

Used for IPv4 liveness scanning.

Please install GitHub project **xmap** before running the pipeline:

Repository:

https://github.com/idealeer/xmap

Make sure `xmap` is correctly installed and available in your system `PATH`.

You can verify the installation by running:

```bash
xmap -h
```

If installed successfully, the help information should be displayed.

## Input Format

Input file:

```text
input/ipv4_splitted_24.txt
```

Before running the scanner, copy the generated IPv4 prefix file from:

```text
Starlink_IP_Collector/out/***/final/ipv4_splitted_24.txt
```

to:

```text
Starlink_PoP_Scanner/input/
```

Make sure the file is renamed as:

```text
ipv4_splitted_24.txt
```

Supported format:

CIDR prefixes only:

```text
10.0.0.0/24
```

## Usage

## Immediate Mode

Run the full pipeline immediately:

```bash
python3 starlink_pop_scanner.py
```

or

```bash
python3 starlink_pop_scanner.py --mode immediate
```

Execution order:

```text
expand_ip
scan_liveness
scan_ptr
monitor
get_pop
```

------

## Scheduled Mode

Run the pipeline every day at a fixed time.

Example:

```bash
python3 starlink_pop_scanner.py --mode scheduled --time 13:00
```

This will execute the full pipeline every day at 13:00.

------

## Output Files

### Liveness Scan Result

```text
output/LivenessScanResult/
```

Stores responsive IP addresses.

------

### PTR Scan Result

```text
output/ptrScanResult/
```

Stores PTR lookup results.

------

### Monitor Result

```text
output/monitorresult/
```

Stores prefix-to-domain mappings.

Format:

```text
prefix<TAB>domain1,domain2,...
```

------

### PoP Result

```text
output/popresult/
```

Stores inferred Starlink PoP deployments.

Format:

```text
hostname<TAB>ip_count<TAB>aggregated_prefixes
```

------

## Workflow

```text
IPv4 Prefixes
     |
     v
expand_ips.py
     |
     v
Liveness Scan (xmap)
     |
     v
PTR Scan (dnsx)
     |
     v
Prefix-Domain Mapping
     |
     v
PoP Extraction
```

------

## Notes

Linux users:

The script automatically grants execute permission to dnsx:

```bash
chmod +x dnsx
```

No manual chmod is required.

=======
# starlink-in-the-wild

📦 Data Availability & Update Status

The dataset associated with this repository is currently under active curation and organization. We are continuously cleaning, validating, and expanding the data, and additional contents will be released in future updates.

A preliminary version of the dataset has been made publicly available via Zenodo and can be accessed through the following DOI:

🔗 https://doi.org/10.5281/zenodo.17221250

Please note that:

The dataset is not yet final and may be subject to changes.

File structures, field definitions, and data coverage may be updated as the curation process progresses.

A more complete and stable release is coming soon.

We recommend checking this repository and the Zenodo record periodically for the latest updates.
If you use the current version of the dataset in your work, please make sure to cite the corresponding Zenodo DOI.
>>>>>>> 7b0228caf8becbee3eb99646726e7e84e9256791
