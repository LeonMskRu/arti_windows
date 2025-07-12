import requests
import re
from concurrent.futures import ThreadPoolExecutor
import time
import logging
from pathlib import Path
from typing import Tuple, Set, Dict, List
from collections import defaultdict

# Настройки
DOWNLOAD_TIMEOUT = 30
MAX_RETRIES = 2
RETRY_DELAY = 30
MAX_WORKERS = 8
MIN_FILE_SIZE = 1024  # 1KB минимальный размер файла

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('adblock_merger.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Создаем папки
RAW_FILES_DIR = Path("source_lists")
RAW_FILES_DIR.mkdir(exist_ok=True)
OUTPUT_DIR = Path("result")
OUTPUT_DIR.mkdir(exist_ok=True)


SOURCES = [
    # ======================
    # Основные EasyList фильтры
    # ======================
    "https://easylist.to/easylist/easylist.txt",
    "https://easylist-downloads.adblockplus.org/easyprivacy.txt",
    
    # ======================
    # Fanboy's фильтры
    # ======================
    "https://secure.fanboy.co.nz/fanboy-annoyance.txt",
    "https://secure.fanboy.co.nz/fanboy-cookiemonster.txt",
    "https://secure.fanboy.co.nz/fanboy-social.txt",
    
    # ======================
    # Дополнительные фильтры
    # ======================
    "https://easylist-downloads.adblockplus.org/abp-filters-anti-cv.txt",
    "https://easylist-downloads.adblockplus.org/bitblock.txt",
    "https://www.i-dont-care-about-cookies.eu/abp/",
    "https://filters.adtidy.org/extension/ublock/filters/11.txt",  # AdGuard Base
    "https://filters.adtidy.org/extension/ublock/filters/3.txt",   # AdGuard Tracking
    "https://filters.adtidy.org/extension/ublock/filters/4.txt",   # AdGuard Social
    "https://filters.adtidy.org/extension/ublock/filters/14.txt",  # AdGuard Annoyances
       
    # ======================
    # Формат hosts
    # ======================
    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt",
    "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
    
    # ======================
    # DNS фильтры
    # ======================
    "https://raw.githubusercontent.com/notracking/hosts-blocklists/master/dnscrypt-proxy/dnscrypt-proxy.blacklist.txt",
    "https://badmojr.gitlab.io/1hosts/Lite/domains.wildcards",
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt",
    "https://big.oisd.nl/domainswild2",
    
    # ======================
    # Специальные фильтры
    # ======================
    "https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt"
]

def get_source_filename(url: str) -> str:
    """Генерирует имя файла из URL"""
    domain = url.split('//')[-1].split('/')[0].replace('.', '_')
    filename = url.split('/')[-1].split('?')[0][:50] or 'list'
    return f"{domain}_{filename}.txt"

def download_with_retry(url: str) -> Tuple[str, str]:
    """Загрузка с повторами и проверкой"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AdBlockParser/1.0',
        'Accept-Encoding': 'gzip, deflate'
    }
    
    for attempt in range(MAX_RETRIES + 1):
        try:
            logger.info(f"Попытка {attempt + 1}/{MAX_RETRIES + 1}: {url}")
            
            with requests.get(url, headers=headers, stream=True, timeout=DOWNLOAD_TIMEOUT) as response:
                response.raise_for_status()
                
                content_length = int(response.headers.get('Content-Length', 0))
                if content_length > 10_000_000:
                    logger.warning(f"Большой файл: {content_length/1024/1024:.2f} MB")
                
                content = response.text
                
                if content_length > 0 and len(content) < content_length * 0.9:
                    raise ValueError(f"Неполная загрузка: {len(content)}/{content_length} байт")
                
                return content, url
                
        except Exception as e:
            logger.warning(f"Ошибка загрузки (попытка {attempt + 1}): {str(e)}")
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
    
    logger.error(f"Не удалось загрузить после {MAX_RETRIES + 1} попыток: {url}")
    return "", url

def save_raw_file(content: str, url: str) -> bool:
    """Сохранение исходного файла с проверкой"""
    try:
        filename = get_source_filename(url)
        filepath = RAW_FILES_DIR / filename
        
        if len(content) < MIN_FILE_SIZE:
            logger.warning(f"Файл слишком мал ({len(content)} байт): {filename}")
            return False
            
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        if filepath.stat().st_size < MIN_FILE_SIZE:
            logger.warning(f"Файл сохранен не полностью: {filename}")
            return False
            
        logger.debug(f"Успешно сохранен: {filename}")
        return True
        
    except Exception as e:
        logger.error(f"Ошибка сохранения файла: {str(e)}")
        return False

def is_valid_domain(domain: str) -> bool:
    """Проверка валидности домена"""
    domain = domain.lower().strip('.*|^/~')
    if len(domain) > 253 or len(domain) < 4:
        return False
    return bool(re.match(r'^(?!-)[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$', domain))


def is_unsupported_in_brave(rule: str) -> bool:
    """Определяет, является ли правило неподдерживаемым в Brave AdBlock"""
    rule = rule.strip()
    if rule.startswith("#@#"):
        return True
    if ":style(" in rule or ":has(" in rule or ":nth-" in rule:
        return True
    if "$popup" in rule or "$csp=" in rule or "$removeparam" in rule:
        return True
    if "$" in rule and "domain=" in rule:
        return True
    if rule.startswith("*") and is_valid_domain(rule.strip("*")):
        return True
    if "$redirect=" in rule or "$rewrite=" in rule or "$cookie=" in rule:
        return True
    return False

def is_css_rule(line: str) -> bool:
    """Определение CSS правил"""
    line = line.strip()
    return (line.startswith('##') and len(line) > 2 and 
            not line.startswith(('###', '## ', '##^', '##$')))

def is_exception_rule(line: str) -> bool:
    """Определение исключений"""
    line = line.strip()
    return line.startswith('@@') and len(line) > 2

def is_complex_rule(rule: str) -> bool:
    """Определение сложных правил"""
    rule = rule.strip()
    return (any(c in rule for c in ['^', '*', '$', '?', '=', '/', '_', '-', '~']) and 
            not rule.startswith(('#', '!')))

def process_content(content: str, url: str) -> Dict[str, Set[str]]:
    """Обработка контента с улучшенным сбором правил"""
    rules = {
        'complex': set(),
        'domains': set(),
        'css': set(),
        'exceptions': set(),
        'hosts': set(),
        'unsupported': set()
    }
    
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
            
        # Исключения (высший приоритет)
        if is_exception_rule(line):
            rules['exceptions'].add(line)
            continue
            
        # CSS правила
        if is_css_rule(line):
            rules['css'].add(line)
            continue
            
        # Hosts формат
        if re.match(r'^\d+\.\d+\.\d+\.\d+\s+[\w.-]+$', line):
            domain = line.split()[1]
            if is_valid_domain(domain):
                rules['hosts'].add(f"||{domain}^")
            continue
            
        # Простые домены
        clean_line = line.strip('|^*/')
        if is_valid_domain(clean_line):
            rules['domains'].add(clean_line)
            continue
            

        # Неподдерживаемые Brave-правила (после всех проверок)
        if is_unsupported_in_brave(line):
            rules['unsupported'].add(line)
            continue
        # Сложные правила
        if is_complex_rule(line):
            rules['complex'].add(line)
    
    return rules

def save_result(rules: Set[str], filename: str, description: str) -> bool:
    """Сохранение результатов"""
    if not rules:
        logger.warning(f"Нет правил для сохранения в {filename}")
        return False
        
    filepath = OUTPUT_DIR / filename
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(f"! {description}\n")
            f.write(f"! Generated: {time.strftime('%Y-%m-%d %H:%M')}\n")
            f.write(f"! Total rules: {len(rules):,}\n\n")
            f.write("\n".join(sorted(rules)))
        
        logger.info(f"Сохранено {len(rules):,} правил в {filename}")
        return True
    except Exception as e:
        logger.error(f"Ошибка сохранения {filename}: {str(e)}")
        return False

def analyze_duplicates(all_rules: List[str]) -> Dict[str, int]:
    """Анализ дубликатов правил"""
    duplicates = defaultdict(int)
    for rule in all_rules:
        duplicates[rule] += 1
    return {rule: count for rule, count in duplicates.items() if count > 1}

def save_duplicates_report(duplicates: Dict[str, int]):
    """Сохранение отчета о дубликатах"""
    if not duplicates:
        return
    
    report_path = "duplicates_report.log"
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write("=== Отчет о дублирующихся правилах ===\n")
        f.write(f"Дата генерации: {time.strftime('%Y-%m-%d %H:%M')}\n")
        f.write(f"Всего дубликатов: {len(duplicates)}\n")
        f.write(f"Общее количество повторений: {sum(duplicates.values())}\n\n")
        
        for rule, count in sorted(duplicates.items(), key=lambda x: x[1], reverse=True)[:100]:
            f.write(f"{count}x {rule}\n")
    
    logger.warning(f"Обнаружены дубликаты правил. Отчет сохранен в {report_path}")

def find_category_conflicts(rules: Dict[str, Set[str]]) -> Dict[Tuple[str, str], Set[str]]:
    """Поиск пересечений между категориями"""
    conflicts = {}
    categories = list(rules.keys())
    
    for i in range(len(categories)):
        for j in range(i + 1, len(categories)):
            cat1, cat2 = categories[i], categories[j]
            intersection = rules[cat1] & rules[cat2]
            if intersection:
                conflicts[(cat1, cat2)] = intersection
    
    return conflicts

def save_conflicts_report(conflicts: Dict[Tuple[str, str], Set[str]]):
    """Сохранение детального отчета о конфликтах между категориями"""
    if not conflicts:
        logger.info("✓ Нет пересечений между категориями правил")
        return
    
    report_path = "category_conflicts.log"
    try:
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("=== Детальный отчет о пересечениях между категориями ===\n")
            f.write(f"Дата генерации: {time.strftime('%Y-%m-%d %H:%M')}\n\n")
            f.write(f"Всего конфликтующих пар категорий: {len(conflicts)}\n")
            
            total_conflicts = 0
            for (cat1, cat2), rules in conflicts.items():
                f.write(f"\n◆ Конфликт {cat1} ↔ {cat2} ({len(rules)} правил)\n")
                f.write("Примеры конфликтующих правил:\n")
                for rule in sorted(rules)[:20]:  # Первые 20 примеров
                    f.write(f"  - {rule}\n")
                total_conflicts += len(rules)
            
            f.write(f"\n◆ Итого пересечений: {total_conflicts}\n")
            f.write("◆ Источники дубликатов можно проверить командой:\n")
            f.write("  grep 'правило' source_lists/*.txt\n")
        
        logger.warning(f"Обнаружены пересечения между категориями. Полный отчет в {report_path}")
        
        # Дополнительно сохраняем все конфликты в CSV
        csv_path = "category_conflicts.csv"
        with open(csv_path, 'w', encoding='utf-8') as f:
            f.write("Category1,Category2,Rule\n")
            for (cat1, cat2), rules in conflicts.items():
                for rule in rules:
                    f.write(f"{cat1},{cat2},{rule}\n")
        
        logger.info(f"CSV версия отчета сохранена в {csv_path}")
        
    except Exception as e:
        logger.error(f"Ошибка при сохранении отчета о конфликтах: {str(e)}")

def analyze_and_report_duplicates():
    """Анализ и отчет о дубликатах с поиском источников"""
    try:
        # Собираем все правила из всех файлов
        all_rules = []
        for file in RAW_FILES_DIR.glob("*.txt"):
            with open(file, 'r', encoding='utf-8') as f:
                for line in f:
                    rule = line.strip()
                    if rule and not rule.startswith(('#', '!', '/')):
                        all_rules.append((rule, file.name))
        
        # Анализ дубликатов
        duplicates = defaultdict(list)
        for rule, filename in all_rules:
            duplicates[rule].append(filename)
        
        # Фильтруем только настоящие дубликаты
        real_duplicates = {rule: files for rule, files in duplicates.items() if len(files) > 1}
        
        if not real_duplicates:
            logger.info("✓ Дубликаты не обнаружены")
            return
        
        # Сохраняем полный отчет
        report_path = "duplicates_report.txt"
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("=== Полный отчет о дублирующихся правилах ===\n")
            f.write(f"Дата генерации: {time.strftime('%Y-%m-%d %H:%M')}\n\n")
            f.write(f"Всего дублирующихся правил: {len(real_duplicates)}\n")
            f.write(f"Общее количество повторений: {sum(len(files) for files in real_duplicates.values())}\n\n")
            
            # Сортируем по количеству повторений
            sorted_duplicates = sorted(real_duplicates.items(), key=lambda x: len(x[1]), reverse=True)
            
            f.write("Топ 100 самых частых дубликатов:\n")
            for rule, files in sorted_duplicates[:100]:
                f.write(f"\n{len(files)}x {rule}\n")
                f.write("  Источники:\n")
                for file in sorted(files):
                    f.write(f"  - {file}\n")
        
        logger.warning(f"Обнаружены дубликаты в {len(real_duplicates)} правилах. Полный отчет в {report_path}")
        
        # Пример для stats.rip
        example_rule = "stats.rip"
        if example_rule in real_duplicates:
            logger.info(f"Пример анализа для '{example_rule}':")
            for file in real_duplicates[example_rule]:
                logger.info(f"  - Найден в: {file}")
        
    except Exception as e:
        logger.error(f"Ошибка при анализе дубликатов: {str(e)}")
        
def main():
    start_time = time.time()
    logger.info("=== Запуск AdBlock Merger ===")
    logger.info(f"Всего источников: {len(SOURCES)}")
    
    # Итоговые наборы правил
    final_rules = {
        'complex': set(),
        'domains': set(),
        'css': set(),
        'exceptions': set(),
        'hosts': set(),
        'unsupported': set()
    }
    all_rules = []
    
    # Загрузка и обработка
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        results = list(executor.map(download_with_retry, SOURCES))
    
    saved_files = 0
    for content, url in results:
        if not content:
            continue
            
        if save_raw_file(content, url):
            saved_files += 1
            processed = process_content(content, url)
            
            # Добавляем правила в итоговые наборы
            for category in final_rules:
                final_rules[category].update(processed[category])
            
            # Собираем все правила для проверки дубликатов
            for rules in processed.values():
                all_rules.extend(rules)
    
    # Сохранение результатов
    save_result(final_rules['complex'], "complex_rules.txt", "Сложные правила блокировки")
    save_result(final_rules['domains'], "simple_domains.txt", "Простые домены")
    save_result(final_rules['css'], "css_rules.txt", "CSS правила")
    save_result(final_rules['exceptions'], "exception_rules.txt", "Исключения")
    save_result(final_rules['hosts'], "converted_hosts.txt", "Конвертированные hosts/DNS")
    save_result(final_rules['unsupported'], "unsupported_in_brave.txt", "Неподдерживаемые Brave AdBlock правила")

    
    # Анализ и сохранение дубликатов
    duplicates = analyze_duplicates(all_rules)
    save_duplicates_report(duplicates)

    # После сохранения всех правил добавляем:
    analyze_and_report_duplicates()
    
    # Поиск пересечений между категориями
    conflicts = find_category_conflicts(final_rules)
    save_conflicts_report(conflicts)
    
    # Статистика
    logger.info("\n=== Итоги обработки ===")
    logger.info(f"Успешно обработано источников: {saved_files}/{len(SOURCES)}")
    logger.info(f"Сложные правила: {len(final_rules['complex']):,}")
    logger.info(f"Простые домены: {len(final_rules['domains']):,}")
    logger.info(f"CSS правила: {len(final_rules['css']):,}")
    logger.info(f"Исключения: {len(final_rules['exceptions']):,}")
    logger.info(f"Конвертированные hosts/DNS: {len(final_rules['hosts']):,}")
    logger.info(f"Неподдерживаемые Brave правила: {len(final_rules['unsupported']):,}")
    
    # Проверка уникальности
    unique_rules = set(all_rules)
    logger.info(f"\nОбщее количество правил: {len(all_rules):,}")
    logger.info(f"Уникальных правил: {len(unique_rules):,}")
    
    if duplicates:
        logger.warning(f"Обнаружено {len(duplicates)} дублирующихся правил")
    else:
        logger.info("✓ Все правила уникальны (нет дубликатов)")
    
    if conflicts:
        total_conflicts = sum(len(rules) for rules in conflicts.values())
        logger.warning(f"Обнаружено {total_conflicts} пересечений между категориями")
    else:
        logger.info("✓ Нет пересечений между категориями")
    
    logger.info(f"Общее время выполнения: {time.time() - start_time:.2f} сек")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.critical("Критическая ошибка в работе скрипта", exc_info=True)
        raise