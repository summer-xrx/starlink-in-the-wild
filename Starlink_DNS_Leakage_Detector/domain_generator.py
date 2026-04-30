from pathlib import Path


"""
Starlink internal domain generation utility.

This script generates candidate domain names based on manually summarized
naming conventions observed from infrastructure devices.

Output:
    generated_domains.txt
"""


FEATURE1 = [
    'aafbgux', 'acklnzl', 'ashnvax', 'atlagax', 'bgtacol', 'bnssarg',
    'brckcan', 'chcoilx', 'chrhnzl', 'clgycan', 'cpclspx', 'dllstxx',
    'dnvrcox', 'dohaqat', 'dtcrakx', 'frntdeu', 'frtabra', 'gtmygtm',
    'iqltcan', 'jhngzaf', 'jtnaidn', 'kentwax', 'kjjqcan', 'krcipak',
    'lgosnga', 'lhrrpng', 'limaper', 'lndngbr', 'lsancax', 'mdrdesp',
    'mlbeaus', 'mlnnita', 'mmbiind', 'mmmiflx', 'mnlaphl', 'mplsmnx',
    'msctomn', 'nrbiken', 'nwyynyx', 'prthaus', 'pthpak', 'qrtomex',
    'rcxship', 'rdmdwax', 'rdmdwax3rk', 'sea', 'sfiabgr', 'sltyutx',
    'sngesgp', 'snjecax', 'sntochl', 'splobra', 'spxship', 'strespx',
    'sttlwax', 'sydyaus', 'tkyojpn', 'tmpeazx', 'wrswpol'
]

FEATURE2 = [
    'agg', 'edg', 'gws', 'iot', 'li', 'mgt', 'oob',
    'opt', 'rrr', 'sdc', 'sec', 'spi', 'spx', 'tor', 'vpn'
]

FEATURE3 = [
    'con', 'edg', 'fwl', 'mgt', 'nbz', 'oad',
    'pdu', 'rtr', 'spi', 'swc', 'tor', 'rkc'
]


def write_standard_domains(output, prefix):
    """
    Generate standard device naming patterns.
    """
    for role in FEATURE2:
        for device in FEATURE3:
            for idx in range(1, 30):
                domain = f"{prefix}-{role}-{device}{idx}.starlinkisp.net"
                output.write(domain + "\n")

                if device in {"tor", "pdu"}:
                    for suffix in ("a", "b", "c"):
                        output.write(
                            f"{prefix}-{role}-{device}{idx}{suffix}.starlinkisp.net\n"
                        )

            for idx in range(1, 6):
                num = idx * 100
                domain = f"{prefix}-{role}-{device}{num}.starlinkisp.net"
                output.write(domain + "\n")

                if device in {"tor", "pdu"}:
                    for suffix in ("a", "b", "c"):
                        output.write(
                            f"{prefix}-{role}-{device}{num}{suffix}.starlinkisp.net\n"
                        )


def write_srv_domains(output, prefix):
    """
    Generate service node naming patterns.
    """
    srv_feature2 = [x for x in FEATURE2 if x not in {"iot", "rrr", "li"}] + ["pkp"]

    for role in srv_feature2:
        for group in range(1, 7):
            for suffix in "abcdefghijk":
                domain = f"{prefix}-{role}-srv-{group}{suffix}.starlinkisp.net"
                output.write(domain + "\n")


def write_oob_domains(output, prefix):
    """
    Generate out-of-band management naming patterns.
    """
    oob_feature3 = [x for x in FEATURE3 if x not in {"pdu", "tor"}]
    oob_feature2 = [x for x in FEATURE2 if x not in {"iot", "rrr", "li"}] + ["pkp"]

    for role in oob_feature2:
        for device in oob_feature3:
            for idx in range(1, 11):
                domain = f"{prefix}-{role}-{device}{idx}-oob.starlinkisp.net"
                output.write(domain + "\n")

            for idx in range(1, 6):
                domain = f"{prefix}-{role}-{device}{idx * 100}-oob.starlinkisp.net"
                output.write(domain + "\n")


def generate_domains(output_file="generated_domains.txt"):
    """
    Main generation logic.
    """
    output_path = Path(output_file)

    with output_path.open("w", encoding="utf-8") as f:
        for base in FEATURE1:
            write_standard_domains(f, base)
            write_srv_domains(f, base)
            write_oob_domains(f, base)

        for num in range(1, 11):
            for base in FEATURE1:
                prefix = f"{base}{num}"
                write_standard_domains(f, prefix)
                write_srv_domains(f, prefix)
                write_oob_domains(f, prefix)


def main():
    generate_domains()
    print("Domain generation completed.")


if __name__ == "__main__":
    main()