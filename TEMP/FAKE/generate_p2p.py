import requests
import ipaddress
import subprocess

asn_list = {
    "LeaseWeb": [60781, 28753],
    "OVH": [16276],
    "Google": [15169],
    "M247": [9009],
    "Vultr": [20473],
    "QuadraNet": [8100],
    "AWS": [16509],
}

def fetch_from_radb(asn):
    try:
        result = subprocess.run(
            ["whois", "-h", "whois.radb.net", f"-i origin AS{asn}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=15
        )
        prefixes = set()
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("route:") or line.startswith("route6:"):
                prefix = line.split()[1]
                prefixes.add(prefix)
        return list(prefixes)
    except Exception as e:
        print(f"[!] RADb ошибка для AS{asn}: {e}")
        return []

def fetch_prefixes(asn):
    try:
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        data = r.json()
        prefixes = [item["prefix"] for item in data.get("data", {}).get("prefixes", [])]
        if prefixes:
            print(f"[RIPEstat] OK: AS{asn} ({len(prefixes)} префиксов)")
            return prefixes
    except Exception as e:
        print(f"[!] RIPEstat ошибка для AS{asn}: {e}")

    try:
        url = f"https://api.bgpview.io/asn/{asn}/prefixes"
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        data = r.json()
        ipv4 = [p["prefix"] for p in data.get("data", {}).get("ipv4_prefixes", [])]
        ipv6 = [p["prefix"] for p in data.get("data", {}).get("ipv6_prefixes", [])]
        prefixes = ipv4 + ipv6
        if prefixes:
            print(f"[BGPView] OK: AS{asn} ({len(prefixes)} префиксов)")
            return prefixes
    except Exception as e:
        print(f"[!] BGPView ошибка для AS{asn}: {e}")

    print(f"[→] Попытка получить AS{asn} через RADb...")
    return fetch_from_radb(asn)

def convert_to_p2p(prefixes, org):
    ipv4, ipv6 = [], []
    for prefix in prefixes:
        try:
            net = ipaddress.ip_network(prefix)
            start_ip = str(net.network_address)
            end_ip = str(net.broadcast_address if net.version == 4 else net[-1])
            line = f"{org}:0:{start_ip}-{end_ip}"
            if net.version == 4:
                ipv4.append(line)
            else:
                ipv6.append(line)
        except Exception:
            continue
    return ipv4, ipv6

def range_to_cidr(start_ip, end_ip):
    return [str(cidr) for cidr in ipaddress.summarize_address_range(
        ipaddress.ip_address(start_ip),
        ipaddress.ip_address(end_ip)
    )]

def p2p_to_cidr_txt(p2p_file, txt_file):
    cidrs = []
    with open(p2p_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                _, _, iprange = line.split(":", 2)
                ip_start, ip_end = iprange.split("-")
                cidrs.extend(range_to_cidr(ip_start.strip(), ip_end.strip()))
            except Exception:
                continue
    with open(txt_file, "w") as f_out:
        f_out.write("\n".join(cidrs) + "\n")
    print(f"[→] {txt_file}: {len(cidrs)} CIDR записей")

# Основной блок
all_ipv4, all_ipv6 = [], []

for org, asns in asn_list.items():
    for asn in asns:
        prefixes = fetch_prefixes(asn)
        ipv4, ipv6 = convert_to_p2p(prefixes, org)
        all_ipv4.extend(ipv4)
        all_ipv6.extend(ipv6)

with open("ipfilter_ipv4.p2p", "w") as f:
    f.write("# IPv4 list for Tixati/PeerGuardian\n" + "\n".join(all_ipv4))
with open("ipfilter_ipv6.p2p", "w") as f:
    f.write("# IPv6 list for Tixati/PeerGuardian\n" + "\n".join(all_ipv6))

# .txt → CIDR
p2p_to_cidr_txt("ipfilter_ipv4.p2p", "ipfilter_ipv4.txt")
p2p_to_cidr_txt("ipfilter_ipv6.p2p", "ipfilter_ipv6.txt")

print("[✔] Готово: p2p + CIDR txt (IPv4/IPv6)")
