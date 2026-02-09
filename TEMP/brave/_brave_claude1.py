import requests
import re
from concurrent.futures import ThreadPoolExecutor
import time
import logging
from pathlib import Path
from typing import Tuple, Set, Dict, Optional
from collections import defaultdict
import unicodedata

# ==============================================================================
# Settings
# ==============================================================================

# Network settings
DOWNLOAD_TIMEOUT = 30  # seconds
MAX_RETRIES = 2
RETRY_DELAY = 30  # seconds
MAX_WORKERS = 8  # for concurrent downloads

# File settings
MIN_FILE_SIZE = 1024  # 1KB minimum file size to be considered valid

# Directories
SOURCE_DIR = Path("source_lists")
RESULT_DIR = Path("result_lists")

# Create directories if they don't exist
SOURCE_DIR.mkdir(exist_ok=True)
RESULT_DIR.mkdir(exist_ok=True)

# ==============================================================================
# Logging Configuration
# ==============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('adblock_merger.log', mode='w', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ==============================================================================
# Filter Lists Sources
# ==============================================================================

SOURCES = [
    # AdGuard
    "https://filters.adtidy.org/extension/ublock/filters/11.txt",  # AdGuard Base
    # Other Lists
    "https://easylist-downloads.adblockplus.org/abp-filters-anti-cv.txt",
    "https://easylist-downloads.adblockplus.org/bitblock.txt",
    "https://dblw.oisd.nl/basic/"
]

# ==============================================================================
# Helper Functions
# ==============================================================================

def get_source_filename(url: str) -> str:
    """Generates a safe filename from a URL."""
    try:
        domain = url.split('//')[-1].split('/')[0].replace('.', '_')
        filename_part = url.split('/')[-1].split('?')[0] or 'list'
        # Sanitize filename part
        safe_filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename_part)[:50]
        return f"{domain}_{safe_filename}.txt"
    except Exception as e:
        logger.warning(f"Failed to generate filename for {url}: {e}")
        return f"list_{hash(url)}.txt"


def is_valid_domain(domain: str) -> bool:
    """
    Validates a domain name, including Internationalized Domain Names (IDN).
    """
    if not domain or len(domain) > 253:
        return False
    
    # Remove wildcard prefix if present
    domain = domain.lstrip('*').lstrip('.')
    
    # Normalize Punycode and Unicode domains
    try:
        domain = unicodedata.normalize('NFC', domain)
        domain = domain.encode('idna').decode('ascii')
    except (UnicodeError, UnicodeDecodeError, IndexError):
        return False
    
    # Check for valid characters and structure
    if '..' in domain or domain.startswith('.') or domain.endswith('.'):
        return False
    
    # Basic domain regex - allows single-label domains for localhost, etc.
    pattern = re.compile(
        r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$',
        re.IGNORECASE
    )
    return bool(re.match(pattern, domain))

# ==============================================================================
# Core Logic: Downloading and Processing
# ==============================================================================

def download_file(url: str) -> Optional[Tuple[str, str]]:
    """
    Downloads a single file with retries and returns its content and URL.
    
    Args:
        url: The URL of the file to download.
    
    Returns:
        A tuple of (content, url) on success, or None on failure.
    """
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AdBlockParser/1.0',
        'Accept-Encoding': 'gzip, deflate'
    }
    
    for attempt in range(MAX_RETRIES + 1):
        try:
            logger.info(f"Attempt {attempt + 1}/{MAX_RETRIES + 1}: Downloading {url}")
            response = requests.get(url, headers=headers, timeout=DOWNLOAD_TIMEOUT)
            response.raise_for_status()
            
            # Use apparent_encoding for better accuracy with text files
            if response.encoding is None or response.encoding.lower() == 'iso-8859-1':
                response.encoding = response.apparent_encoding or 'utf-8'
            
            content = response.text
            
            if len(content.encode('utf-8')) < MIN_FILE_SIZE:
                logger.warning(f"File from {url} is too small ({len(content)} bytes). Skipping.")
                return None
            
            logger.info(f"Successfully downloaded {url} ({len(content)} chars)")
            return content, url
            
        except requests.RequestException as e:
            logger.warning(f"Error downloading {url} (attempt {attempt + 1}): {e}")
            if attempt < MAX_RETRIES:
                logger.info(f"Retrying in {RETRY_DELAY} seconds...")
                time.sleep(RETRY_DELAY)
    
    logger.error(f"Failed to download {url} after {MAX_RETRIES + 1} attempts.")
    return None


def save_source_file(content: str, url: str) -> Path:
    """Saves the raw content to a file in the source directory."""
    filename = get_source_filename(url)
    filepath = SOURCE_DIR / filename
    
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        logger.info(f"Saved source file: {filename}")
        return filepath
    except IOError as e:
        logger.error(f"Failed to save source file {filename}: {e}")
        raise


def parse_and_classify_rules(content: str) -> Dict[str, Set[str]]:
    """
    Parses the content of a filter list and classifies rules into categories.
    
    Args:
        content: The text content of the filter list.
    
    Returns:
        A dictionary with rule categories as keys and sets of rules as values.
    """
    rules = defaultdict(set)
    
    unsupported_options = [
        ":style", ":has", ":nth-", "$popup", "$csp=", "$removeparam",
        "$redirect=", "$rewrite=", "$cookie=", ":has-text", ":matches-css"
    ]
    
    for line in content.splitlines():
        line = line.strip()
        
        # Ignore empty lines, comments, and metadata
        if not line or line.startswith(('!', '[', '#')):
            continue
        
        # Skip comment lines that might have slashes
        if line.startswith('//'):
            continue
        
        # --- Rule Classification ---
        
        # 1. Exception rules (highest priority)
        if line.startswith('@@'):
            rules['exceptions'].add(line)
            continue
        
        # 2. Unsupported Brave rules (e.g., advanced CSS, scriptlets)
        if any(opt in line for opt in unsupported_options) or line.startswith("#@#"):
            rules['unsupported_brave'].add(line)
            continue
        
        # 3. CSS element hiding rules
        if '##' in line or '#?#' in line:
            rules['css_rules'].add(line)
            continue
        
        # 4. Hosts format (e.g., 0.0.0.0 example.com)
        match = re.match(r'^(0\.0\.0\.0|127\.0\.0\.1)\s+([\w.\-]+)', line)
        if match:
            domain = match.group(2)
            if is_valid_domain(domain):
                rules['domain_rules'].add(f"||{domain}^")
            continue
        
        # 5. Domain/Network rules
        # Check if line looks like a network rule
        if '||' in line or line.startswith('|') or '^' in line or '$' in line:
            rules['complex_rules'].add(line)
            continue
        
        # Try to parse as simple domain
        # Remove common decorators for validation
        clean_line = re.sub(r'^[|*]+|[\^/*~]+$', '', line)
        
        # Check if it's a valid domain
        if is_valid_domain(clean_line):
            # Standardize simple domains to ABP format
            if not line.startswith('||'):
                line = f"||{clean_line}^"
            rules['domain_rules'].add(line)
        else:
            # If it's not empty after cleaning, treat as complex rule
            if clean_line:
                rules['complex_rules'].add(line)
    
    return rules


def save_result_list(rules: Set[str], filename: str, description: str):
    """Saves a set of rules to a file in the result directory."""
    if not rules:
        logger.info(f"No rules to save for {filename}.")
        return
    
    filepath = RESULT_DIR / filename
    
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(f"! Title: Brave Optimized List - {description}\n")
            f.write(f"! Description: A merged and optimized list of {description.lower()}.\n")
            f.write(f"! Last Updated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n")
            f.write(f"! Total Rules: {len(rules)}\n\n")
            
            # Write rules sorted for consistency
            for rule in sorted(rules):
                f.write(f"{rule}\n")
        
        logger.info(f"Successfully saved {len(rules):,} rules to {filename}")
    except IOError as e:
        logger.error(f"Failed to save {filename}: {e}")

# ==============================================================================
# Analysis and Reporting
# ==============================================================================

def analyze_duplicates_and_sources():
    """Analyzes all source files to find duplicate rules and their origins."""
    logger.info("Starting duplicate analysis...")
    rule_sources = defaultdict(list)
    
    for file in sorted(SOURCE_DIR.glob("*.txt")):
        try:
            with open(file, 'r', encoding='utf-8') as f:
                content = f.read()
                # Use the same classification logic to get comparable rules
                processed_rules = parse_and_classify_rules(content)
                
                for category_rules in processed_rules.values():
                    for rule in category_rules:
                        rule_sources[rule].append(file.name)
        except Exception as e:
            logger.error(f"Could not process {file.name} for duplicate analysis: {e}")
    
    # Filter for rules that appear in more than one file
    duplicates = {rule: sources for rule, sources in rule_sources.items() if len(sources) > 1}
    
    if not duplicates:
        logger.info("✓ No duplicate rules found across different source files.")
        return
    
    report_path = RESULT_DIR / "duplicates_report.txt"
    logger.warning(f"Found {len(duplicates)} duplicate rules. Report saved to {report_path}")
    
    # Sort duplicates by frequency
    sorted_duplicates = sorted(duplicates.items(), key=lambda item: len(item[1]), reverse=True)
    
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write("=== Duplicate Rules Report ===\n")
        f.write(f"Generated on: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n")
        f.write(f"Total unique rules with duplicates: {len(duplicates)}\n\n")
        
        for rule, sources in sorted_duplicates:
            f.write(f"Rule: {rule} (Found in {len(sources)} files)\n")
            for source_file in sorted(sources):
                f.write(f"  - {source_file}\n")
            f.write("\n")

# ==============================================================================
# Main Execution
# ==============================================================================

def main():
    """Main function to run the ad-block list merger."""
    start_time = time.time()
    
    logger.info("=== Brave AdBlock List Merger Initialized ===")
    logger.info(f"Found {len(SOURCES)} sources to process.")
    
    final_rules = defaultdict(set)
    
    # --- Step 1: Download all source files ---
    logger.info("\n=== Downloading Sources ===")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        download_results = list(executor.map(download_file, SOURCES))
    
    # Filter out failed downloads
    successful_downloads = [res for res in download_results if res is not None]
    
    if not successful_downloads:
        logger.error("No files were successfully downloaded. Exiting.")
        return
    
    # --- Step 2: Process and classify rules from each file ---
    logger.info("\n=== Processing and Classifying Rules ===")
    for content, url in successful_downloads:
        try:
            save_source_file(content, url)
            processed_rules = parse_and_classify_rules(content)
            
            for category, rules_set in processed_rules.items():
                final_rules[category].update(rules_set)
                
        except Exception as e:
            logger.error(f"Failed to process {url}: {e}")
    
    # --- Step 3: Save the final categorized lists ---
    logger.info("\n=== Saving Final Lists ===")
    save_result_list(final_rules['domain_rules'], "01_domain_rules.txt", "Domain & Network Rules")
    save_result_list(final_rules['css_rules'], "02_css_rules.txt", "Element Hiding Rules")
    save_result_list(final_rules['complex_rules'], "03_complex_rules.txt", "Complex Blocking Rules")
    save_result_list(final_rules['exceptions'], "04_exception_rules.txt", "Exception Rules")
    save_result_list(final_rules['unsupported_brave'], "05_unsupported_brave.txt", "Unsupported Brave Rules")
    
    # --- Step 4: Analyze sources for duplicates ---
    analyze_duplicates_and_sources()
    
    # --- Step 5: Final Summary ---
    logger.info("\n=== Processing Summary ===")
    logger.info(f"Successfully processed {len(successful_downloads)} out of {len(SOURCES)} sources.")
    
    total_unique_rules = 0
    for category, rules_set in final_rules.items():
        count = len(rules_set)
        logger.info(f"- {category.replace('_', ' ').title()}: {count:,} rules")
        total_unique_rules += count
    
    logger.info(f"\nTotal unique rules collected: {total_unique_rules:,}")
    
    end_time = time.time()
    logger.info(f"Total execution time: {end_time - start_time:.2f} seconds.")
    logger.info("=== Merger Finished ===")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("\nScript interrupted by user.")
    except Exception:
        logger.critical("A critical error occurred in the main execution block.", exc_info=True)
