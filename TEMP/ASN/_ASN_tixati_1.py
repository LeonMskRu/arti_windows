import requests
import os
import time
import ipaddress

ASN_LIST = {
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

OUTPUT_DIR = "ipfilter"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Фиксированная задержка между запросами
REQUEST_DELAY = 15  # 15 секунд между запросами
last_request_time = 0

def get_asn_prefixes(asn):
    """Получить префиксы для ASN из различных источников с задержками"""
    global last_request_time
    
    sources = [
        # Основной источник
        f"https://api.bgpview.io/asn/{asn}/prefixes",
        # Резервный источник
        f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
    ]
    
    # Добавляем фиксированную задержку между запросами
    current_time = time.time()
    if last_request_time > 0:  # Пропускаем для первого запроса
        time_since_last = current_time - last_request_time
        if time_since_last < REQUEST_DELAY:
            sleep_time = REQUEST_DELAY - time_since_last
            print(f"Ожидание {sleep_time:.2f} секунд перед запросом ASN{asn}...")
            time.sleep(sleep_time)
    
    for url in sources:
        try:
            last_request_time = time.time()
            print(f"Запрос ASN{asn} к {url.split('/')[2]}...")
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            # Обработка ответа от BGPView
            if "bgpview.io" in url:
                ipv4_prefixes = []
                ipv6_prefixes = []
                ipv4_data = data.get("data", {}).get("ipv4_prefixes", [])
                ipv6_data = data.get("data", {}).get("ipv6_prefixes", [])
                
                for prefix in ipv4_data:
                    ipv4_prefixes.append(prefix["prefix"])
                for prefix in ipv6_data:
                    ipv6_prefixes.append(prefix["prefix"])
                
                return ipv4_prefixes, ipv6_prefixes
            
            # Обработка ответа от RIPE
            elif "stat.ripe.net" in url:
                ipv4_prefixes = []
                ipv6_prefixes = []
                prefix_data = data.get("data", {}).get("prefixes", [])
                
                for prefix_info in prefix_data:
                    prefix = prefix_info["prefix"]
                    if ":" in prefix:
                        ipv6_prefixes.append(prefix)
                    else:
                        ipv4_prefixes.append(prefix)
                
                return ipv4_prefixes, ipv6_prefixes
                
        except Exception as e:
            print(f"Ошибка при запросе ASN{asn} к {url.split('/')[2]}: {e}")
            continue
    
    return [], []  # Если все источники не сработали

def cidr_to_ip_range(cidr):
    """Преобразовать CIDR в диапазон IP-адресов для Tixati (только для IPv4)"""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        if network.version == 4:  # Только для IPv4
            start_ip = network.network_address
            end_ip = network.broadcast_address
            return f"{start_ip}-{end_ip}"
        else:  # Для IPv6 возвращаем None, будем использовать чистый CIDR
            return None
    except ValueError:
        return None

def process_asn(asn, name):
    """Обработать один ASN и вернуть результаты"""
    print(f"Обрабатываю ASN{asn} ({name})...")
    ipv4_prefixes, ipv6_prefixes = get_asn_prefixes(asn)
    
    if not ipv4_prefixes and not ipv6_prefixes:
        print(f"Не удалось получить префиксы для ASN{asn}")
        return asn, name, [], [], []
    
    ipv4_range_lines = []  # IPv4 в формате диапазонов (для Tixati)
    ipv4_cidr_lines = []   # IPv4 в формате CIDR (чистые)
    ipv6_lines = []        # IPv6 в формате CIDR (чистые)
    
    # Обрабатываем IPv4 - создаем оба формата
    for prefix in ipv4_prefixes:
        # Проверяем валидность CIDR
        try:
            ipaddress.IPv4Network(prefix, strict=False)
            
            # Формат диапазонов для Tixati
            ip_range = cidr_to_ip_range(prefix)
            if ip_range:
                ipv4_range_lines.append(f"{ip_range} , 000 , ASN{asn} {name}")
            
            # Чистый CIDR формат
            ipv4_cidr_lines.append(prefix)
                
        except ValueError:
            print(f"Пропускаем невалидный IPv4 префикс: {prefix}")
            continue
    
    # Обрабатываем IPv6 - оставляем чистый CIDR без комментариев
    for prefix in ipv6_prefixes:
        # Проверяем валидность IPv6 CIDR
        try:
            ipaddress.IPv6Network(prefix, strict=False)
            ipv6_lines.append(prefix)  # Только CIDR, без комментариев
        except ValueError:
            print(f"Пропускаем невалидный IPv6 префикс: {prefix}")
            continue
    
    return asn, name, ipv4_range_lines, ipv4_cidr_lines, ipv6_lines

# Основной код
all_ipv4_range_lines = []  # Все IPv4 диапазоны
all_ipv4_cidr_lines = []   # Все IPv4 CIDR
all_ipv6_lines = []        # Все IPv6 CIDR

print(f"Фиксированная задержка между запросами: {REQUEST_DELAY} секунд")

# Обрабатываем ASN последовательно
for asn, name in ASN_LIST.items():
    asn_result, name_result, ipv4_range_lines, ipv4_cidr_lines, ipv6_lines = process_asn(asn, name)
    
    # Сохраняем индивидуальные файлы для ASN
    if ipv4_range_lines:
        # IPv4 в формате диапазонов
        filename_v4_range = os.path.join(OUTPUT_DIR, f"ASN{asn}_{name}_v4.dat")
        with open(filename_v4_range, "w", encoding="utf-8") as f:
            f.write("\n".join(ipv4_range_lines))
        print(f"Файл {filename_v4_range} создан ({len(ipv4_range_lines)} IPv4 диапазонов)")
        all_ipv4_range_lines.extend(ipv4_range_lines)
    
    if ipv4_cidr_lines:
        # IPv4 в формате CIDR
        filename_v4_cidr = os.path.join(OUTPUT_DIR, f"ASN{asn}_{name}_v4.cidr")
        with open(filename_v4_cidr, "w", encoding="utf-8") as f:
            f.write("\n".join(ipv4_cidr_lines))
        print(f"Файл {filename_v4_cidr} создан ({len(ipv4_cidr_lines)} IPv4 CIDR)")
        all_ipv4_cidr_lines.extend(ipv4_cidr_lines)
    
    if ipv6_lines:
        # IPv6 в формате CIDR
        filename_v6 = os.path.join(OUTPUT_DIR, f"ASN{asn}_{name}_v6.cidr")
        with open(filename_v6, "w", encoding="utf-8") as f:
            f.write("\n".join(ipv6_lines))
        print(f"Файл {filename_v6} создан ({len(ipv6_lines)} IPv6 CIDR)")
        all_ipv6_lines.extend(ipv6_lines)

# Создаем общие файлы со всеми фильтрами
if all_ipv4_range_lines:
    common_filename_v4_range = os.path.join(OUTPUT_DIR, "ALL_ASN_FILTERS_v4.dat")
    with open(common_filename_v4_range, "w", encoding="utf-8") as f:
        f.write("\n".join(all_ipv4_range_lines))
    print(f"Общий IPv4 файл (диапазоны) {common_filename_v4_range} создан ({len(all_ipv4_range_lines)} диапазонов)")

if all_ipv4_cidr_lines:
    common_filename_v4_cidr = os.path.join(OUTPUT_DIR, "ALL_ASN_FILTERS_v4.cidr")
    with open(common_filename_v4_cidr, "w", encoding="utf-8") as f:
        f.write("\n".join(all_ipv4_cidr_lines))
    print(f"Общий IPv4 файл (CIDR) {common_filename_v4_cidr} создан ({len(all_ipv4_cidr_lines)} CIDR)")

if all_ipv6_lines:
    common_filename_v6 = os.path.join(OUTPUT_DIR, "ALL_ASN_FILTERS_v6.cidr")
    with open(common_filename_v6, "w", encoding="utf-8") as f:
        f.write("\n".join(all_ipv6_lines))
    print(f"Общий IPv6 файл (CIDR) {common_filename_v6} создан ({len(all_ipv6_lines)} CIDR)")

print("Все операции завершены!")
