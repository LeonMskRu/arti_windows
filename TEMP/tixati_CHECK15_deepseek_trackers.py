#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import asyncio
import aiohttp
import socket
import struct
import random
import string
import time
import ipaddress
import csv
from urllib.parse import urlparse, parse_qs, quote_from_bytes
import bencodepy
import binascii
import base64
import os
from collections import defaultdict
import zipfile
import io
from pathlib import Path
import hashlib
import re
import datetime

# -----------------------
# Tracker List Management with caching
# -----------------------
TRACKER_SOURCES = {
    "ngosang_udp": "https://github.com/ngosang/trackerslist/raw/refs/heads/master/trackers_all_udp.txt",
    "ngosang_http": "https://github.com/ngosang/trackerslist/raw/refs/heads/master/trackers_all_http.txt", 
    "ngosang_https": "https://github.com/ngosang/trackerslist/raw/refs/heads/master/trackers_all_https.txt",
    "xiu2_http": "https://github.com/XIU2/TrackersListCollection/raw/refs/heads/master/http.txt",
    "xiu2_nohttp": "https://github.com/XIU2/TrackersListCollection/raw/refs/heads/master/nohttp.txt",
    "trackers_run": "https://trackers.run/s/wp_up_hp_hs_v4_v6.txt"
}

TRACKER_CACHE_DIR = "tracker_cache"
TRACKER_CACHE_MAX_AGE = 24 * 3600  # 24 hours in seconds

# -----------------------
# IBlocklist Management with caching
# -----------------------
IBLOCKLIST_CACHE_FILE = "iblocklist.txt"
IBLOCKLIST_CACHE_MAX_AGE = 24 * 3600  # 24 hours in seconds
IBLOCKLIST_URL = "https://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=cidr&archiveformat=zip"

BAD_NETWORKS = []

# -----------------------
# Tracker List Management
# -----------------------
def ensure_cache_dir():
    """Ensure cache directory exists"""
    os.makedirs(TRACKER_CACHE_DIR, exist_ok=True)

def get_cache_filename(source_name):
    """Get cache filename for tracker source"""
    return os.path.join(TRACKER_CACHE_DIR, f"{source_name}.txt")

def is_cache_valid(cache_file):
    """Check if cache file is valid (exists and not too old)"""
    if not os.path.exists(cache_file):
        return False
    
    file_age = time.time() - os.path.getmtime(cache_file)
    return file_age <= TRACKER_CACHE_MAX_AGE

async def download_tracker_list(session, url, source_name):
    """Download tracker list from URL"""
    print(f"Downloading trackers from {url}...")
    try:
        timeout = aiohttp.ClientTimeout(total=30)
        async with session.get(url, timeout=timeout) as resp:
            if resp.status == 200:
                content = await resp.text()
                return content.splitlines()
            else:
                print(f"Failed to download {source_name}: HTTP {resp.status}")
                return []
    except Exception as e:
        print(f"Error downloading {source_name}: {e}")
        return []

def load_cached_trackers(source_name):
    """Load trackers from cache file"""
    cache_file = get_cache_filename(source_name)
    if not is_cache_valid(cache_file):
        return None
    
    try:
        with open(cache_file, 'r', encoding='utf-8') as f:
            trackers = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        print(f"Loaded {len(trackers)} trackers from {source_name} cache")
        return trackers
    except Exception as e:
        print(f"Error reading cache for {source_name}: {e}")
        return None

def save_trackers_to_cache(trackers, source_name):
    """Save trackers to cache file"""
    try:
        cache_file = get_cache_filename(source_name)
        with open(cache_file, 'w', encoding='utf-8') as f:
            f.write(f"# {source_name} cache\n")
            f.write(f"# Generated at: {time.ctime()}\n")
            f.write(f"# Trackers: {len(trackers)}\n")
            for tracker in trackers:
                f.write(f"{tracker}\n")
        print(f"Saved {len(trackers)} trackers to {source_name} cache")
    except Exception as e:
        print(f"Error saving cache for {source_name}: {e}")

async def load_all_trackers(trackers_file="trackers.txt"):
    """Load all trackers from local file and online sources"""
    ensure_cache_dir()
    
    all_trackers = set()
    
    # Load local trackers file
    if os.path.exists(trackers_file):
        with open(trackers_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    all_trackers.add(line)
        print(f"Loaded {len(all_trackers)} trackers from {trackers_file}")
    
    # Load from online sources
    connector = aiohttp.TCPConnector(limit=5, ssl=False)
    timeout = aiohttp.ClientTimeout(total=30)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        tasks = []
        for source_name, url in TRACKER_SOURCES.items():
            # Try cache first
            cached = load_cached_trackers(source_name)
            if cached is not None:
                all_trackers.update(cached)
            else:
                # Download fresh
                tasks.append(download_tracker_list(session, url, source_name))
        
        # Wait for all downloads to complete
        if tasks:
            downloaded_lists = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, (source_name, url) in enumerate(TRACKER_SOURCES.items()):
                if i < len(downloaded_lists):
                    result = downloaded_lists[i]
                    if isinstance(result, list) and result:
                        all_trackers.update(result)
                        save_trackers_to_cache(result, source_name)
    
    # Convert to list and remove duplicates
    unique_trackers = remove_duplicate_trackers(list(all_trackers))
    print(f"Total unique trackers after combining all sources: {len(unique_trackers)}")
    return unique_trackers

def load_iblocklist_cache():
    """Load iblocklist from cache file if exists and not too old"""
    if not os.path.exists(IBLOCKLIST_CACHE_FILE):
        return None
    
    file_age = time.time() - os.path.getmtime(IBLOCKLIST_CACHE_FILE)
    if file_age > IBLOCKLIST_CACHE_MAX_AGE:
        print(f"Cache file is {file_age/3600:.1f} hours old, will update")
        return None
    
    networks = []
    try:
        with open(IBLOCKLIST_CACHE_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    try:
                        net = ipaddress.ip_network(line, strict=False)
                        networks.append(net)
                    except Exception as e:
                        print(f"Invalid network in cache: {line} - {e}")
        print(f"Loaded {len(networks)} networks from cache")
        return networks
    except Exception as e:
        print(f"Error reading cache: {e}")
        return None

def save_iblocklist_cache(networks):
    """Save networks to cache file"""
    try:
        with open(IBLOCKLIST_CACHE_FILE, 'w', encoding='utf-8') as f:
            f.write("# IBlocklist cache\n")
            f.write(f"# Generated at: {time.ctime()}\n")
            f.write(f"# Networks: {len(networks)}\n")
            for net in networks:
                f.write(f"{net}\n")
        print(f"Saved {len(networks)} networks to cache")
    except Exception as e:
        print(f"Error saving cache: {e}")

async def download_iblocklist():
    """Download and parse iblocklist"""
    print("Downloading iblocklist...")
    try:
        timeout = aiohttp.ClientTimeout(total=60)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(IBLOCKLIST_URL) as resp:
                if resp.status != 200:
                    raise Exception(f"HTTP {resp.status}")
                data = await resp.read()
        
        networks = []
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for name in z.namelist():
                content = z.read(name).decode("utf-8", errors="ignore")
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        net = ipaddress.ip_network(line, strict=False)
                        networks.append(net)
                    except Exception as e:
                        print(f"Invalid network {line}: {e}")
                        continue
        
        print(f"Downloaded {len(networks)} networks from iblocklist")
        return networks
    except Exception as e:
        print(f"Error downloading iblocklist: {e}")
        return []

async def load_iblocklist():
    """Load iblocklist with cache support"""
    global BAD_NETWORKS
    
    # Try cache first
    cached = load_iblocklist_cache()
    if cached is not None:
        BAD_NETWORKS = cached
        return
    
    # Download fresh
    networks = await download_iblocklist()
    if networks:
        BAD_NETWORKS = networks
        save_iblocklist_cache(networks)
    else:
        # Fallback to empty list if download fails
        print("Using empty blocklist due to download failure")
        BAD_NETWORKS = []

def ip_in_blocklist(ip):
    """Check if IP is in blocklist"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for net in BAD_NETWORKS:
            if ip_obj in net:
                return True
    except Exception:
        return False
    return False

# -----------------------
# Load bad trackers (domains)
# -----------------------
def load_bad_trackers(path="trackers_BAD.txt"):
    bad_domains = set()
    if not os.path.exists(path):
        return bad_domains
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                bad_domains.add(line.lower())
    return bad_domains

# -----------------------
# Get external IPs (both IPv4 and IPv6) with HTTPS support
# -----------------------
async def get_external_ips(session):
    """Get external IPv4 and IPv6 addresses"""
    ipv4_services = [
        'https://ipv4.icanhazip.com',
        'https://api.ipify.org',
        'https://ident.me',
        'https://checkip.amazonaws.com',
        'https://ipecho.net/plain'
    ]
    
    ipv6_services = [
        'https://ipv6.icanhazip.com',
        'https://v6.ident.me',
        'https://ipv6.seeip.org'
    ]
    
    external_ipv4 = None
    external_ipv6_networks = set()
    
    # Get IPv4
    for service in ipv4_services:
        try:
            # Disable proxy for this request
            connector = aiohttp.TCPConnector(family=socket.AF_INET, ssl=True)
            timeout = aiohttp.ClientTimeout(total=8)
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as no_proxy_session:
                async with no_proxy_session.get(service, timeout=timeout, allow_redirects=True) as resp:
                    if resp.status == 200:
                        ip_text = (await resp.text()).strip()
                        # Extract IP using regex to handle any extra content
                        ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', ip_text)
                        if ip_match:
                            ip = ipaddress.ip_address(ip_match.group(0))
                            if ip.version == 4:
                                external_ipv4 = str(ip)
                                print(f"External IPv4 detected: {external_ipv4} from {service}")
                                break
        except Exception as e:
            print(f"Failed to get IPv4 from {service}: {e}")
            continue
    
    # Get IPv6
    for service in ipv6_services:
        try:
            # Disable proxy for this request
            connector = aiohttp.TCPConnector(family=socket.AF_INET6, ssl=True)
            timeout = aiohttp.ClientTimeout(total=8)
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as no_proxy_session:
                async with no_proxy_session.get(service, timeout=timeout, allow_redirects=True) as resp:
                    if resp.status == 200:
                        resp_text = await resp.text()
                        # Improved IPv6 regex pattern
                        ipv6_pattern = r'(?:(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})|(?:(?:[0-9a-fA-F]{1,4}:){1,7}:)|(?:(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})|(?:(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2})|(?:(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3})|(?:(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4})|(?:(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5})|(?:[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6})|(?::(?::[0-9a-fA-F]{1,4}){1,7}|:))'
                        ip_matches = re.findall(ipv6_pattern, resp_text)
                        
                        for ip_match in ip_matches:
                            try:
                                ip = ipaddress.ip_address(ip_match.strip())
                                if ip.version == 6:
                                    ip_str = str(ip)
                                    # Filter only IPv6 addresses with our prefix and create /64 network
                                    if ip_str.startswith('2a00:62c0:'):
                                        # Create /64 network from the IPv6 address (first 4 hextets)
                                        ip_parts = ip_str.split(':')
                                        if len(ip_parts) >= 4:
                                            # Reconstruct first 4 hextets for /64 network
                                            network_str = ':'.join(ip_parts[:4]) + '::/64'
                                            try:
                                                network = ipaddress.IPv6Network(network_str, strict=False)
                                                external_ipv6_networks.add(network)
                                                print(f"External IPv6 detected: {ip_str} from {service}")
                                                print(f"  Added network: {network}")
                                            except Exception as e:
                                                print(f"Error creating network from {ip_str}: {e}")
                            except Exception as e:
                                print(f"Invalid IPv6 address {ip_match} from {service}: {e}")
                                continue
        except Exception as e:
            print(f"Failed to get IPv6 from {service}: {e}")
            continue
    
    if not external_ipv4:
        raise Exception("Could not determine external IPv4 from any service")
    
    return external_ipv4, external_ipv6_networks

# -----------------------
# Filter trackers with bad domains and blocklisted IPs + remove duplicates
# -----------------------
async def filter_bad_trackers(trackers, bad_domains, session):
    """Filter trackers by bad domains and blocklisted IPs, and remove duplicates"""
    if not bad_domains and not BAD_NETWORKS:
        # Still remove duplicates even if no bad domains/blocklists
        return remove_duplicate_trackers(trackers)
    
    filtered = []
    seen_trackers = set()
    semaphore = asyncio.Semaphore(10)  # Limit concurrent DNS lookups
    
    async def check_tracker(tracker):
        try:
            # Check for duplicates first
            tracker_key = get_tracker_key(tracker)
            if tracker_key in seen_trackers:
                print(f"Skipping duplicate tracker: {tracker}")
                return None
            seen_trackers.add(tracker_key)
            
            domain = urlparse(tracker).hostname
            if not domain:
                return tracker  # Keep trackers without valid hostname for now
            
            # Check bad domains
            if domain.lower() in bad_domains:
                print(f"Skipping bad domain: {tracker}")
                return None
            
            # Check blocklisted IPs
            async with semaphore:
                try:
                    addrs = await asyncio.get_event_loop().getaddrinfo(
                        domain, None, family=socket.AF_UNSPEC
                    )
                    tracker_ips = {addr[4][0] for addr in addrs}
                    
                    for ip in tracker_ips:
                        if ip_in_blocklist(ip):
                            print(f"Skipping tracker {tracker} (IP {ip} in blocklist)")
                            return None
                except (socket.gaierror, Exception) as e:
                    print(f"DNS lookup failed for {domain}: {e}")
                    # Keep tracker if DNS fails - might be temporary
            
            return tracker
        except Exception as e:
            print(f"Error checking tracker {tracker}: {e}")
            return tracker  # Keep on error
    
    # Check all trackers concurrently
    tasks = [check_tracker(tracker) for tracker in trackers]
    results = await asyncio.gather(*tasks)
    
    filtered = [r for r in results if r is not None]
    print(f"Filtered {len(trackers) - len(filtered)} bad/duplicate trackers")
    return filtered

def get_tracker_key(tracker_url):
    """Generate unique key for tracker based on protocol, domain, and port"""
    try:
        parsed = urlparse(tracker_url)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname.lower() if parsed.hostname else ""
        port = parsed.port
        
        # Set default ports if not specified
        if port is None:
            if scheme == 'http':
                port = 80
            elif scheme == 'https':
                port = 443
            elif scheme == 'udp':
                port = 80  # Default UDP port
        
        return f"{scheme}://{hostname}:{port}"
    except Exception:
        # Fallback to full URL if parsing fails
        return tracker_url.lower()

def remove_duplicate_trackers(trackers):
    """Remove duplicate trackers based on protocol, domain, and port"""
    seen = set()
    unique_trackers = []
    duplicates_removed = 0
    
    for tracker in trackers:
        key = get_tracker_key(tracker)
        if key not in seen:
            seen.add(key)
            unique_trackers.append(tracker)
        else:
            duplicates_removed += 1
    
    if duplicates_removed > 0:
        print(f"Removed {duplicates_removed} duplicate trackers")
    
    return unique_trackers

# -----------------------
# Peer consistency
# -----------------------
def analyze_peer_consistency(all_results):
    ip_tracker_count = defaultdict(int)
    total_trackers = 0
    for result in all_results:
        if result["status"] == "OK" and result["all_peer_ips"]:
            total_trackers += 1
            unique_ips = set(ip for ip, port in result["all_peer_ips"])
            for ip in unique_ips:
                ip_tracker_count[ip] += 1
    common_ips = set()
    threshold = max(1, int(total_trackers * 0.3))
    for ip, count in ip_tracker_count.items():
        if count >= threshold:
            common_ips.add(ip)
    print(f"Found {len(common_ips)} common IPs across {total_trackers} trackers (threshold: {threshold})")
    return common_ips

# -----------------------
# Suspicious check
# -----------------------
def is_suspicious_tracker(result, common_ips, external_ipv4, external_ipv6_networks):
    if result["status"] != "OK":
        return True
    if not result["all_peer_ips"]:
        return False
    unique_ips = set(ip for ip, port in result["all_peer_ips"])
    if not unique_ips:
        return False
    common_peer_count = sum(1 for ip in unique_ips if ip in common_ips)
    common_ratio = common_peer_count / len(unique_ips)
    if common_ratio < 0.3 and len(unique_ips) > 2:
        print(f"Suspicious tracker {urlparse(result['tracker']).netloc}: only {common_ratio:.1%} common peers")
        return True
    return False

# -----------------------
# Improved bogon/private check (now includes blocklist)
# -----------------------
def is_bad_ip(ip):
    """Check if IP is bad (bogon/private/blocklisted)"""
    try:
        addr = ipaddress.ip_address(ip)
        
        # Standard bogon checks
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved:
            return True
        
        # IPv4 specific bogons
        if addr.version == 4:
            # Carrier-grade NAT 100.64.0.0/10
            if ipaddress.IPv4Address('100.64.0.0') <= addr <= ipaddress.IPv4Address('100.127.255.255'):
                return True
            # 0.0.0.0/8
            if ipaddress.IPv4Address('0.0.0.0') <= addr <= ipaddress.IPv4Address('0.255.255.255'):
                return True
            # APIPA 169.254.0.0/16
            if ipaddress.IPv4Address('169.254.0.0') <= addr <= ipaddress.IPv4Address('169.254.255.255'):
                return True
            # 192.0.0.0/24 (IETF)
            if ipaddress.IPv4Address('192.0.0.0') <= addr <= ipaddress.IPv4Address('192.0.0.255'):
                return True
            # TEST-NET-1 192.0.2.0/24
            if ipaddress.IPv4Address('192.0.2.0') <= addr <= ipaddress.IPv4Address('192.0.2.255'):
                return True
            # 198.18.0.0/15
            if ipaddress.IPv4Address('198.18.0.0') <= addr <= ipaddress.IPv4Address('198.19.255.255'):
                return True
            # TEST-NET-2 198.51.100.0/24
            if ipaddress.IPv4Address('198.51.100.0') <= addr <= ipaddress.IPv4Address('198.51.100.255'):
                return True
            # TEST-NET-3 203.0.113.0/24
            if ipaddress.IPv4Address('203.0.113.0') <= addr <= ipaddress.IPv4Address('203.0.113.255'):
                return True
# Cloudflare Warp IPv4 ranges
            if ipaddress.IPv4Address('104.28.198.0') <= addr <= ipaddress.IPv4Address('104.28.198.255'):
                return True
            if ipaddress.IPv4Address('172.71.184.0') <= addr <= ipaddress.IPv4Address('172.71.184.255'):
                return True
        
        # IPv6 specific bogons
        if addr.version == 6:
            # IPv4-mapped IPv6 addresses
            if addr.ipv4_mapped is not None:
                return True
            # IPv4-compatible (deprecated)
            if hasattr(addr, 'is_ipv4_compatible') and addr.is_ipv4_compatible:
                return True
            # Unique local addresses (fc00::/7)
            if addr.is_private:
                return True
            # Documentation addresses (2001:db8::/32)
            if ipaddress.IPv6Address('2001:db8::') <= addr <= ipaddress.IPv6Address('2001:db8:ffff:ffff:ffff:ffff:ffff:ffff'):
                return True
            # 6to4 addresses (2002::/16)
            if ipaddress.IPv6Address('2002::') <= addr <= ipaddress.IPv6Address('2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff'):
                return True
            # Teredo addresses (2001::/32)
            if ipaddress.IPv6Address('2001::') <= addr <= ipaddress.IPv6Address('2001:0:ffff:ffff:ffff:ffff:ffff:ffff'):
                return True
            # Benchmarking (2001:2::/48)
            if ipaddress.IPv6Address('2001:2::') <= addr <= ipaddress.IPv6Address('2001:2:0:ffff:ffff:ffff:ffff:ffff'):
                return True
            # Orchid (2001:10::/28)
            if ipaddress.IPv6Address('2001:10::') <= addr <= ipaddress.IPv6Address('2001:1f:ffff:ffff:ffff:ffff:ffff:ffff'):
                return True
            # Discard-only (100::/64)
            if ipaddress.IPv6Address('100::') <= addr <= ipaddress.IPv6Address('100::ffff:ffff:ffff:ffff'):
                return True
            # Cloudflare Warp IPv6 ranges
            if ipaddress.IPv6Address('2a09:bac5::') <= addr <= ipaddress.IPv6Address('2a09:bac5:ffff:ffff:ffff:ffff:ffff:ffff'):
                return True
            # 2a0a:e5c0
            if ipaddress.IPv6Address('2a0a:e5c0::') <= addr <= ipaddress.IPv6Address('2a0a:e5c0:ffff:ffff:ffff:ffff:ffff:ffff'):
                return True

        # Check blocklist
        if ip_in_blocklist(ip):
            return True
        
        return False
    except Exception:
        return True

# -----------------------
# Check if peer is bad external IP
# -----------------------
def is_bad_external_ip_peer(ip, port, external_ipv4, external_ipv6_networks):
    """Check if peer is external IP with port 6881 (bad)"""
    if ip == external_ipv4 and port == 6881:
        return True
    
    # Check IPv6 addresses in our /64 networks
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version == 6:
            for network in external_ipv6_networks:
                if ip_obj in network and port == 6881:
                    return True
    except Exception:
        pass
    
    return False

# -----------------------
# Check if peer is good external IP
# -----------------------
def is_good_external_ip_peer(ip, port, external_ipv4, external_ipv6_networks):
    """Check if peer is external IP with port != 6881 (working)"""
    if ip == external_ipv4 and port != 6881:
        return True
    
    # Check IPv6 addresses in our /64 networks
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version == 6:
            for network in external_ipv6_networks:
                if ip_obj in network and port != 6881:
                    return True
    except Exception:
        pass
    
    return False

# -----------------------
# Check if IP is our external IP (any version)
# -----------------------
def is_our_external_ip(ip, external_ipv4, external_ipv6_networks):
    """Check if IP is one of our external IPs"""
    if ip == external_ipv4:
        return True
    
    # Check IPv6 addresses in our /64 networks
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version == 6:
            for network in external_ipv6_networks:
                if ip_obj in network:
                    return True
    except Exception:
        pass
    
    return False

# -----------------------
# Infohash utils
# -----------------------
def parse_infohash(s):
    s = s.strip()
    if s.startswith("magnet:?"):
        qs = parse_qs(s[8:])
        xt = qs.get("xt", [""])[0]
        if xt.startswith("urn:btih:"):
            h = xt[9:]
            return normalize_infohash(h)
        raise ValueError("Cannot find infohash in magnet link")
    return normalize_infohash(s)

def normalize_infohash(h):
    h = h.strip().lower()
    if len(h) == 40 and all(c in "0123456789abcdef" for c in h):
        return binascii.unhexlify(h)
    try:
        raw = base64.b32decode(h.upper())
        if len(raw) == 20:
            return raw
    except Exception:
        pass
    raise ValueError("infohash must be 40 hex chars, base32, or magnet link")

def get_infohash_hex(info_hash_bytes):
    """Convert infohash bytes to hex string"""
    return binascii.hexlify(info_hash_bytes).decode('ascii')

def load_magnets_from_file(magnet_file):
    """Load magnet links from file"""
    magnets = []
    if not os.path.exists(magnet_file):
        return magnets
    
    with open(magnet_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and line.startswith('magnet:'):
                magnets.append(line)
    
    return magnets

# -----------------------
# Handshake check
# -----------------------
def is_bittorrent_peer(ip, port, info_hash, timeout=3):
    try:
        # Determine address family based on IP version
        if ':' in ip:  # IPv6
            family = socket.AF_INET6
        else:  # IPv4
            family = socket.AF_INET
            
        s = socket.create_connection((ip, port), timeout=timeout, family=family)
        s.settimeout(timeout)
        pstr = b"BitTorrent protocol"
        pstrlen = bytes([len(pstr)])
        reserved = b"\x00" * 8
        peer_id = ("-PC0001-" + ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(12))).encode("ascii")
        handshake = pstrlen + pstr + reserved + info_hash + peer_id
        s.sendall(handshake)
        resp = s.recv(68)
        s.close()
        return len(resp) >= 68 and resp[1:20] == b"BitTorrent protocol"
    except Exception:
        return False

# -----------------------
# Parse peers from tracker response
# -----------------------
def parse_peers_from_response(info):
    peers = []
    try:
        peers_bin = info.get(b"peers", b"")
        peers6_bin = info.get(b"peers6", b"")
        
        # Compact binary format IPv4
        if isinstance(peers_bin, bytes) and len(peers_bin) % 6 == 0 and len(peers_bin) > 0:
            for i in range(0, len(peers_bin), 6):
                ip_bytes = peers_bin[i:i+4]
                port_bytes = peers_bin[i+4:i+6]
                ip = socket.inet_ntoa(ip_bytes)
                port = struct.unpack(">H", port_bytes)[0]
                peers.append((ip, port))
        
        # Compact binary format IPv6
        if isinstance(peers6_bin, bytes) and len(peers6_bin) % 18 == 0 and len(peers6_bin) > 0:
            for i in range(0, len(peers6_bin), 18):
                ip_bytes = peers6_bin[i:i+16]
                port_bytes = peers6_bin[i+16:i+18]
                try:
                    ip = socket.inet_ntop(socket.AF_INET6, ip_bytes)
                    port = struct.unpack(">H", port_bytes)[0]
                    peers.append((ip, port))
                except Exception as e:
                    print(f"Error parsing IPv6 peer: {e}")
                    continue
        
        # Dict/list format for both IPv4 and IPv6
        if isinstance(peers_bin, list):
            for peer in peers_bin:
                if isinstance(peer, dict):
                    ip_bytes = peer.get(b'ip')
                    port = peer.get(b'port', 0)
                    if ip_bytes:
                        if isinstance(ip_bytes, bytes):
                            # Try to detect if it's IPv4 or IPv6
                            if len(ip_bytes) == 4:
                                ip = socket.inet_ntoa(ip_bytes)
                            elif len(ip_bytes) == 16:
                                try:
                                    ip = socket.inet_ntop(socket.AF_INET6, ip_bytes)
                                except:
                                    continue
                            else:
                                ip = ip_bytes.decode('utf-8', errors='ignore')
                        else:
                            ip = str(ip_bytes)
                        if ip and port:
                            peers.append((ip, port))
    except Exception as e:
        print(f"Error parsing peers: {e}")
    return peers

# -----------------------
# UDP Tracker Protocol Implementation
# -----------------------
async def announce_udp_tracker(tracker, info_hash, timeout=10):
    """Announce to UDP tracker"""
    start = time.time()
    try:
        parsed = urlparse(tracker)
        hostname = parsed.hostname
        port = parsed.port or 80
        
        if not hostname:
            return tracker, "ERROR", "invalid_hostname", 0, 0, [], round(time.time()-start,2), []
        
        # Resolve hostname
        addrinfo = await asyncio.get_event_loop().getaddrinfo(
            hostname, port, family=socket.AF_UNSPEC, type=socket.SOCK_DGRAM
        )
        if not addrinfo:
            return tracker, "ERROR", "dns_resolution_failed", 0, 0, [], round(time.time()-start,2), []
        
        family, socktype, proto, canonname, sockaddr = addrinfo[0]
        
        # Create UDP socket
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        
        # Generate transaction ID
        transaction_id = random.randint(0, 0x7FFFFFFF)
        
        # Connect request
        protocol_id = 0x41727101980  # Magic constant
        connect_request = struct.pack("!QII", protocol_id, 0, transaction_id)
        
        # Send connect request
        sock.sendto(connect_request, sockaddr)
        
        # Receive connect response
        connect_response = sock.recv(16)
        if len(connect_response) < 16:
            return tracker, "ERROR", "udp_connect_response_too_short", 0, 0, [], round(time.time()-start,2), []
        
        action, transaction, connection_id = struct.unpack("!IIQ", connect_response)
        if action != 0 or transaction != transaction_id:
            return tracker, "ERROR", "udp_connect_response_mismatch", 0, 0, [], round(time.time()-start,2), []
        
        # Announce request
        peer_id = ("-PC0001-" + ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(12))).encode("ascii")
        downloaded = 0
        left = 0
        uploaded = 0
        event = 0  # 0: none, 1: completed, 2: started, 3: stopped
        ip = 0
        key = random.randint(0, 0x7FFFFFFF)
        num_want = -1  # -1 means default
        
        announce_request = struct.pack(
            "!QII20s20sQQQIIIH",
            connection_id,
            1,  # announce
            transaction_id,
            info_hash,
            peer_id,
            downloaded,
            left,
            uploaded,
            event,
            ip,
            key,
            num_want,
            0  # port (0 means use the same port we're sending from)
        )
        
        # Send announce request
        sock.sendto(announce_request, sockaddr)
        
        # Receive announce response
        announce_response = sock.recv(4096)
        if len(announce_response) < 20:
            return tracker, "ERROR", "udp_announce_response_too_short", 0, 0, [], round(time.time()-start,2), []
        
        action, transaction, interval, leechers, seeders = struct.unpack("!IIIII", announce_response[:20])
        if action != 1 or transaction != transaction_id:
            return tracker, "ERROR", "udp_announce_response_mismatch", 0, 0, [], round(time.time()-start,2), []
        
        # Parse peers from compact format
        peers_data = announce_response[20:]
        peers = []
        all_peer_ips = []
        
        if len(peers_data) >= 6 and len(peers_data) % 6 == 0:
            # IPv4 compact format
            for i in range(0, len(peers_data), 6):
                ip_bytes = peers_data[i:i+4]
                port_bytes = peers_data[i+4:i+6]
                ip = socket.inet_ntoa(ip_bytes)
                port = struct.unpack(">H", port_bytes)[0]
                peers.append((ip, port))
                all_peer_ips.append((ip, port))
        
        sock.close()
        return tracker, "OK", "", seeders, leechers, peers, round(time.time()-start,2), all_peer_ips
        
    except socket.timeout:
        return tracker, "TIMEOUT", "udp_socket_timeout", 0, 0, [], round(time.time()-start,2), []
    except Exception as e:
        return tracker, "ERROR", f"udp_{str(e)}", 0, 0, [], round(time.time()-start,2), []

# -----------------------
# HTTP/HTTPS Tracker Protocol Implementation
# -----------------------
async def announce_http_tracker(session, tracker, info_hash, timeout=10):
    """Announce to HTTP/HTTPS tracker"""
    start = time.time()
    try:
        # Generate peer ID
        peer_id = ("-PC0001-" + ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(12))).encode("ascii")
        
        # Prepare query parameters
        params = {
            'info_hash': quote_from_bytes(info_hash),
            'peer_id': quote_from_bytes(peer_id),
            'port': 6881,
            'uploaded': 0,
            'downloaded': 0,
            'left': 0,
            'compact': 1,
            'numwant': 50
        }
        
        # Check if tracker already has query parameters
        if '?' in tracker:
            url = f"{tracker}&{urlencode(params)}"
        else:
            url = f"{tracker}?{urlencode(params)}"
        
        # Make request with redirect handling
        timeout_obj = aiohttp.ClientTimeout(total=timeout)
        async with session.get(url, timeout=timeout_obj, allow_redirects=True) as resp:
            if resp.status == 200:
                content = await resp.read()
                
                # Parse bencoded response
                try:
                    info = bencodepy.decode(content)
                except Exception as e:
                    return tracker, "ERROR", f"bdecode_failed_{str(e)}", 0, 0, [], round(time.time()-start,2), []
                
                # Extract seeders and leechers
                seeders = info.get(b'complete', 0)
                leechers = info.get(b'incomplete', 0)
                if isinstance(seeders, bytes):
                    seeders = int(seeders)
                if isinstance(leechers, bytes):
                    leechers = int(leechers)
                
                # Parse peers
                all_peer_ips = parse_peers_from_response(info)
                peers = all_peer_ips[:10]  # Use first 10 peers for display
                
                return tracker, "OK", "", seeders, leechers, peers, round(time.time()-start,2), all_peer_ips
            else:
                return tracker, "ERROR", f"http_{resp.status}", 0, 0, [], round(time.time()-start,2), []
                
    except asyncio.TimeoutError:
        return tracker, "TIMEOUT", "http_timeout", 0, 0, [], round(time.time()-start,2), []
    except Exception as e:
        return tracker, "ERROR", f"http_{str(e)}", 0, 0, [], round(time.time()-start,2), []

def urlencode(params):
    """Simple URL encoding function"""
    return '&'.join([f"{k}={v}" for k, v in params.items()])

# -----------------------
# Announce to tracker (wrapper)
# -----------------------
async def announce_to_tracker(session, tracker, info_hash, timeout=10):
    """Announce to tracker (UDP or HTTP/HTTPS)"""
    if tracker.startswith('udp://'):
        return await announce_udp_tracker(tracker, info_hash, timeout)
    elif tracker.startswith('http://') or tracker.startswith('https://'):
        return await announce_http_tracker(session, tracker, info_hash, timeout)
    else:
        return tracker, "ERROR", "unsupported_protocol", 0, 0, [], 0, []

# -----------------------
# Check individual peer
# -----------------------
async def check_peer(peer, info_hash, timeout=3):
    ip, port = peer
    try:
        # Determine address family based on IP version
        if ':' in ip:  # IPv6
            family = socket.AF_INET6
        else:  # IPv4
            family = socket.AF_INET
            
        loop = asyncio.get_event_loop()
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setblocking(False)
        
        # Connect with timeout
        await asyncio.wait_for(loop.sock_connect(sock, (ip, port)), timeout)
        
        # Send handshake
        pstr = b"BitTorrent protocol"
        pstrlen = bytes([len(pstr)])
        reserved = b"\x00" * 8
        peer_id = ("-PC0001-" + ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(12))).encode("ascii")
        handshake = pstrlen + pstr + reserved + info_hash + peer_id
        
        await asyncio.wait_for(loop.sock_sendall(sock, handshake), timeout)
        
        # Receive response
        resp = await asyncio.wait_for(loop.sock_recv(sock, 68), timeout)
        
        sock.close()
        
        return len(resp) >= 68 and resp[1:20] == b"BitTorrent protocol"
    except Exception:
        return False

# -----------------------
# Check multiple peers concurrently
# -----------------------
async def check_peers_concurrently(peers, info_hash, max_concurrent=5, timeout=3):
    """Check multiple peers concurrently with limited concurrency"""
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def check_with_semaphore(peer):
        async with semaphore:
            return await check_peer(peer, info_hash, timeout)
    
    tasks = [check_with_semaphore(peer) for peer in peers]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Count successful handshakes
    successful = sum(1 for r in results if r is True)
    return successful

# -----------------------
# Process tracker results
# -----------------------
async def process_tracker_results(all_results, info_hash, external_ipv4, external_ipv6_networks):
    """Process tracker results and perform peer analysis"""
    
    # Analyze peer consistency
    common_ips = analyze_peer_consistency(all_results)
    
    # Process each result
    processed_results = []
    for result in all_results:
        tracker = result["tracker"]
        status = result["status"]
        seeders = result["seeders"]
        leechers = result["leechers"]
        response_time = result["response_time"]
        all_peer_ips = result["all_peer_ips"]
        
        # Skip if no peers
        if not all_peer_ips:
            processed_results.append({
                "tracker": tracker,
                "status": status,
                "seeders": seeders,
                "leechers": leechers,
                "response_time": response_time,
                "working_peers": 0,
                "bad_peers": 0,
                "bogon_peers": 0,
                "bad_external_peers": 0,
                "good_external_peers": 0,
                "total_peers": 0,
                "suspicious": False,
                "notes": result.get("error", "")
            })
            continue
        
        # Check for suspicious tracker
        suspicious = is_suspicious_tracker(result, common_ips, external_ipv4, external_ipv6_networks)
        
        # Analyze peers
        working_peers = 0
        bad_peers = 0
        bogon_peers = 0
        bad_external_peers = 0
        good_external_peers = 0
        
        # Check first 5 peers for BitTorrent protocol
        peers_to_check = all_peer_ips[:5]
        if peers_to_check:
            working_peers = await check_peers_concurrently(peers_to_check, info_hash, max_concurrent=3, timeout=3)
            bad_peers = len(peers_to_check) - working_peers
        
        # Count bogon and external IP peers
        for ip, port in all_peer_ips:
            if is_bad_ip(ip):
                bogon_peers += 1
            elif is_bad_external_ip_peer(ip, port, external_ipv4, external_ipv6_networks):
                bad_external_peers += 1
            elif is_good_external_ip_peer(ip, port, external_ipv4, external_ipv6_networks):
                good_external_peers += 1
        
        processed_results.append({
            "tracker": tracker,
            "status": status,
            "seeders": seeders,
            "leechers": leechers,
            "response_time": response_time,
            "working_peers": working_peers,
            "bad_peers": bad_peers,
            "bogon_peers": bogon_peers,
            "bad_external_peers": bad_external_peers,
            "good_external_peers": good_external_peers,
            "total_peers": len(all_peer_ips),
            "suspicious": suspicious,
            "notes": result.get("error", "")
        })
    
    return processed_results

# -----------------------
# Save results to file
# -----------------------
def save_results_to_file(results, info_hash_hex, output_dir="tracker_check_results"):
    """Save results to timestamped file"""
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M")
    filename = f"trackers_check_{info_hash_hex}_{timestamp}.txt"
    filepath = os.path.join(output_dir, filename)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(f"Tracker Check Results\n")
        f.write(f"Infohash: {info_hash_hex}\n")
        f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total trackers checked: {len(results)}\n\n")
        
        # Summary
        working_trackers = [r for r in results if r["status"] == "OK"]
        suspicious_trackers = [r for r in results if r["suspicious"]]
        
        f.write(f"SUMMARY:\n")
        f.write(f"Working trackers: {len(working_trackers)}\n")
        f.write(f"Suspicious trackers: {len(suspicious_trackers)}\n")
        f.write(f"Failed/Timeout trackers: {len(results) - len(working_trackers)}\n\n")
        
        # Working trackers
        f.write("WORKING TRACKERS:\n")
        f.write("-" * 120 + "\n")
        for result in working_trackers:
            if not result["suspicious"]:
                f.write(f"{result['tracker']}\n")
                f.write(f"  Seeders: {result['seeders']}, Leechers: {result['leechers']}, Response: {result['response_time']}s\n")
                f.write(f"  Peers: {result['working_peers']}/{result['total_peers']} working, {result['bogon_peers']} bogon, {result['good_external_peers']} good external\n\n")
        
        # Suspicious trackers
        if suspicious_trackers:
            f.write("\nSUSPICIOUS TRACKERS:\n")
            f.write("-" * 120 + "\n")
            for result in suspicious_trackers:
                f.write(f"{result['tracker']}\n")
                f.write(f"  Seeders: {result['seeders']}, Leechers: {result['leechers']}, Response: {result['response_time']}s\n")
                f.write(f"  Peers: {result['working_peers']}/{result['total_peers']} working, {result['bogon_peers']} bogon\n\n")
        
        # Failed trackers
        failed_trackers = [r for r in results if r["status"] != "OK"]
        if failed_trackers:
            f.write("\nFAILED/TIMEOUT TRACKERS:\n")
            f.write("-" * 120 + "\n")
            for result in failed_trackers:
                f.write(f"{result['tracker']} - {result['status']}: {result['notes']}\n")
    
    print(f"Results saved to: {filepath}")
    return filepath

# -----------------------
# Main function
# -----------------------
async def main():
    parser = argparse.ArgumentParser(description='Check BitTorrent trackers')
    parser.add_argument('--infohash', type=str, help='Infohash (hex, base32, or magnet link)')
    parser.add_argument('--magnet', type=str, default='trackers_magnet.txt', 
                       help='File with magnet links (default: trackers_magnet.txt)')
    parser.add_argument('--timeout', type=int, default=10, help='Tracker timeout in seconds')
    parser.add_argument('--trackers-file', type=str, default='trackers.txt', help='Local trackers file')
    parser.add_argument('--bad-trackers-file', type=str, default='trackers_BAD.txt', help='Bad trackers file')
    
    args = parser.parse_args()
    
    # Load magnet links or infohash
    magnet_links = []
    if args.infohash:
        # Single infohash from command line
        magnet_links = [args.infohash]
    else:
        # Load from magnet file
        magnet_links = load_magnets_from_file(args.magnet)
        if not magnet_links:
            print(f"No magnet links found in {args.magnet}")
            return
    
    print(f"Loaded {len(magnet_links)} magnet links to check")
    
    # Initialize session
    connector = aiohttp.TCPConnector(limit=20, ssl=False)
    timeout = aiohttp.ClientTimeout(total=args.timeout)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        # Load external IPs
        print("Detecting external IP addresses...")
        external_ipv4, external_ipv6_networks = await get_external_ips(session)
        print(f"External IPv4: {external_ipv4}")
        print(f"External IPv6 networks: {len(external_ipv6_networks)}")
        
        # Load blocklist
        print("Loading blocklist...")
        await load_iblocklist()
        
        # Load bad trackers
        print("Loading bad trackers...")
        bad_domains = load_bad_trackers(args.bad_trackers_file)
        print(f"Loaded {len(bad_domains)} bad domains")
        
        # Load all trackers
        print("Loading trackers...")
        all_trackers = await load_all_trackers(args.trackers_file)
        
        # Filter bad trackers
        print("Filtering bad trackers...")
        filtered_trackers = await filter_bad_trackers(all_trackers, bad_domains, session)
        
        print(f"Using {len(filtered_trackers)} trackers for checking")
        
        # Check each magnet link
        for magnet_link in magnet_links:
            try:
                print(f"\n{'='*80}")
                print(f"Checking magnet link: {magnet_link[:80]}...")
                print(f"{'='*80}")
                
                # Parse infohash
                info_hash_bytes = parse_infohash(magnet_link)
                info_hash_hex = get_infohash_hex(info_hash_bytes)
                print(f"Infohash: {info_hash_hex}")
                
                # Announce to all trackers
                print(f"Announcing to {len(filtered_trackers)} trackers...")
                all_results = []
                
                # Process trackers in batches
                batch_size = 50
                for i in range(0, len(filtered_trackers), batch_size):
                    batch = filtered_trackers[i:i+batch_size]
                    print(f"Processing batch {i//batch_size + 1}/{(len(filtered_trackers)-1)//batch_size + 1} ({len(batch)} trackers)...")
                    
                    tasks = [announce_to_tracker(session, tracker, info_hash_bytes, args.timeout) for tracker in batch]
                    batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                    
                    for j, result in enumerate(batch_results):
                        if isinstance(result, Exception):
                            tracker = batch[j] if j < len(batch) else "unknown"
                            all_results.append({
                                "tracker": tracker,
                                "status": "ERROR",
                                "error": str(result),
                                "seeders": 0,
                                "leechers": 0,
                                "response_time": 0,
                                "all_peer_ips": []
                            })
                        else:
                            tracker, status, error, seeders, leechers, peers, response_time, all_peer_ips = result
                            all_results.append({
                                "tracker": tracker,
                                "status": status,
                                "error": error,
                                "seeders": seeders,
                                "leechers": leechers,
                                "response_time": response_time,
                                "all_peer_ips": all_peer_ips
                            })
                
                # Process results
                print("Processing results...")
                processed_results = await process_tracker_results(all_results, info_hash_bytes, external_ipv4, external_ipv6_networks)
                
                # Save results to file
                output_file = save_results_to_file(processed_results, info_hash_hex)
                
                # Print summary
                working = [r for r in processed_results if r["status"] == "OK" and not r["suspicious"]]
                suspicious = [r for r in processed_results if r["suspicious"]]
                failed = [r for r in processed_results if r["status"] != "OK"]
                
                print(f"\nSUMMARY for {info_hash_hex}:")
                print(f"Working trackers: {len(working)}")
                print(f"Suspicious trackers: {len(suspicious)}")
                print(f"Failed/Timeout: {len(failed)}")
                print(f"Results saved to: {output_file}")
                
            except Exception as e:
                print(f"Error processing magnet link {magnet_link}: {e}")
                continue

if __name__ == "__main__":
    asyncio.run(main())
