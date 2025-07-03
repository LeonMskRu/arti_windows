import requests
import ipaddress

asn_list = {
    "LeaseWeb": [60781, 28753],
    "OVH": [16276],
    "Google": [15169],
    "M247": [9009],
    "Vultr": [20473],
    "QuadraNet": [8100],
}

def fetch_prefixes(asn):
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        data = r.json()
        return [item["prefix"] for item in data.get("data", {}).get("prefixes", [])]
    except Exception as e:
        print(f"[!] Ошибка при получении AS{asn}: {e}")
        return []

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
        except Exception as e:
            continue
    return ipv4, ipv6

all_ipv4, all_ipv6 = [], []

for org, asns in asn_list.items():
    for asn in asns:
        prefixes = fetch_prefixes(asn)
        ipv4, ipv6 = convert_to_p2p(prefixes, org)
        all_ipv4.extend(ipv4)
        all_ipv6.extend(ipv6)

# Сохраняем
with open("ipfilter_ipv4.p2p", "w") as f:
    f.write("# IPv4 list for Tixati/PeerGuardian\n" + "\n".join(all_ipv4))

with open("ipfilter_ipv6.p2p", "w") as f:
    f.write("# IPv6 list for Tixati/PeerGuardian\n" + "\n".join(all_ipv6))

print("[✔] Готово: ipfilter_ipv4.p2p и ipfilter_ipv6.p2p")

aws_prefixes = fetch_prefixes(16509)
aws_ipv4, aws_ipv6 = convert_to_p2p(aws_prefixes, "AWS")
with open("aws_ipv4.p2p", "w") as f:
    f.write("# AWS IPv4\n" + "\n".join(aws_ipv4))
with open("aws_ipv6.p2p", "w") as f:
    f.write("# AWS IPv6\n" + "\n".join(aws_ipv6))
