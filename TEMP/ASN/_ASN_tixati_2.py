import requests
import os
import time
import ipaddress
import random

# Список ASN не изменился
ASN_LIST = {
    # ... (ваш список ASN остается здесь) ...
    # Китай
    "4134": "China_Telecom",
    "4837": "China_Unicom",
    "9808": "China_Mobile",
    "56046": "China_Mobile_2",
    "4538": "CERNET",
    "9299": "China_Mobile_3",

    # Облака
    "16509": "Amazon_AWS",
    "14618": "Amazon_Old",
    "15169": "Google_Cloud",
    "8075": "Microsoft_Azure",
    "14061": "DigitalOcean",
    "16276": "OVH",
    "20473": "Vultr",
    "60068": "Datacamp",
    "212238": "Datacamp2",
    "53667": "PONYNET",

    # Восточная Европа / СНГ
    "9009": "M247",
    "202425": "WorldStream",
    "49505": "Selectel",
    "47583": "HosterBY",
    "197695": "ITL_Bulgaria",
    "44477": "Stark_Industries",
}

OUTPUT_DIR = "ipfilter2"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Раздельные списки для общего файла
all_ipv4_lines = []
all_ipv6_lines = []
all_ipv4_cidr_lines = []

def get_prefixes_from_bgpview(asn):
    """Источник 1: Получаем v4 и v6 префиксы с BGPView."""
    print("  -> Пробую основной источник (BGPView)...")
    url = f"https://api.bgpview.io/asn/{asn}/prefixes"
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    data = r.json().get("data", {})
    ipv4_prefixes = [p["prefix"] for p in data.get("ipv4_prefixes", [])]
    ipv6_prefixes = [p["prefix"] for p in data.get("ipv6_prefixes", [])]
    return ipv4_prefixes, ipv6_prefixes

def get_prefixes_from_ripe(asn):
    """Источник 2: Получаем и разделяем v4/v6 префиксы с RIPE."""
    print("  -> Пробую резервный источник (RIPE)...")
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    data = r.json().get("data", {})
    ipv4_prefixes = []
    ipv6_prefixes = []
    for item in data.get("prefixes", []):
        prefix = item["prefix"]
        if ":" in prefix:
            ipv6_prefixes.append(prefix)
        else:
            ipv4_prefixes.append(prefix)
    return ipv4_prefixes, ipv6_prefixes

def process_and_write_prefixes(prefixes, asn, name, ip_version):
    """Обрабатывает список префиксов и записывает в файл."""
    if not prefixes:
        print(f"  -> Префиксы IPv{ip_version} не найдены.")
        return [], []

    lines = []
    cidr_lines = []

    for cidr in prefixes:
        try:
            # Логика для IPv6 и IPv4 CIDR
            cidr_lines.append(cidr)
            
            # Логика для IPv4 с диапазонами
            if ip_version == "4":
                network = ipaddress.ip_network(cidr, strict=False)
                start_ip = network.network_address
                end_ip = network.broadcast_address
                line = f"{start_ip}-{end_ip} , 000 , ASN{asn} {name}"
                lines.append(line)
        except ValueError:
            print(f"  -> Некорректный префикс '{cidr}', пропускаю.")
            continue
            
    # Запись файла с диапазонами и комментариями (только для IPv4)
    if lines:
        filename_dat = os.path.join(OUTPUT_DIR, f"ASN{asn}_{name}_v{ip_version}.dat")
        with open(filename_dat, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(f"  -> Файл {filename_dat} создан ({len(lines)} диапазонов)")

    # Запись файла с CIDR (для IPv4 и IPv6)
    if cidr_lines:
        filename_cidr = os.path.join(OUTPUT_DIR, f"ASN{asn}_{name}_v{ip_version}.cidr.dat")
        with open(filename_cidr, "w", encoding="utf-8") as f:
            f.write("\n".join(cidr_lines))
        print(f"  -> Файл {filename_cidr} создан ({len(cidr_lines)} CIDR)")

    return lines, cidr_lines

# --- Основной цикл ---
for asn, name in ASN_LIST.items():
    print(f"Обрабатываю ASN{asn} ({name})...")
    
    ipv4_prefixes, ipv6_prefixes = [], []
    try:
        ipv4_prefixes, ipv6_prefixes = get_prefixes_from_bgpview(asn)
    except Exception as e:
        print(f"  -> Ошибка основного источника: {e}")
        try:
            ipv4_prefixes, ipv6_prefixes = get_prefixes_from_ripe(asn)
        except Exception as e_fallback:
            print(f"  -> Ошибка резервного источника: {e_fallback}")
            print(f"Не удалось загрузить данные для ASN{asn}. Пропускаю.")
            continue
    
    # Обрабатываем и записываем IPv4
    ipv4_lines, ipv4_cidr_lines = process_and_write_prefixes(ipv4_prefixes, asn, name, "4")
    all_ipv4_lines.extend(ipv4_lines)
    all_ipv4_cidr_lines.extend(ipv4_cidr_lines)

    # Обрабатываем и записываем IPv6
    _, ipv6_cidr_lines = process_and_write_prefixes(ipv6_prefixes, asn, name, "6")
    all_ipv6_lines.extend(ipv6_cidr_lines)
    
    wait_time = random.uniform(15, 20)
    print(f"  -> Пауза: {wait_time:.2f} сек.\n")
    time.sleep(wait_time)

# --- Создание общих файлов ---
if all_ipv4_lines:
    combined_filename = os.path.join(OUTPUT_DIR, "_ALL_ASN_Filters_v4.dat")
    all_ipv4_lines.sort()
    with open(combined_filename, "w", encoding="utf-8") as f:
        f.write("\n".join(all_ipv4_lines))
    print(f"Создан общий IPv4 файл: {combined_filename} ({len(all_ipv4_lines)} всего диапазонов)")

if all_ipv4_cidr_lines:
    combined_filename = os.path.join(OUTPUT_DIR, "_ALL_ASN_Filters_v4.cidr.dat")
    all_ipv4_cidr_lines.sort()
    with open(combined_filename, "w", encoding="utf-8") as f:
        f.write("\n".join(all_ipv4_cidr_lines))
    print(f"Создан общий IPv4 CIDR файл: {combined_filename} ({len(all_ipv4_cidr_lines)} всего CIDR)")

if all_ipv6_lines:
    combined_filename = os.path.join(OUTPUT_DIR, "_ALL_ASN_Filters_v6.cidr.dat")
    all_ipv6_lines.sort()
    with open(combined_filename, "w", encoding="utf-8") as f:
        f.write("\n".join(all_ipv6_lines))
    print(f"Создан общий IPv6 CIDR файл: {combined_filename} ({len(all_ipv6_lines)} всего CIDR)")

print("\nРабота завершена.")
