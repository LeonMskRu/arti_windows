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

# -----------------------
# IBlocklist Management with caching
# -----------------------
IBLOCKLIST_CACHE_FILE = "iblocklist.txt"
IBLOCKLIST_CACHE_MAX_AGE = 24 * 3600  # 24 hours in seconds
IBLOCKLIST_URL = "https://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=cidr&archiveformat=zip"

BAD_NETWORKS = []

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
# Tracker List Management with caching (NEW)
# -----------------------
TRACKER_CACHE_DIR = "tracker_cache"
TRACKER_CACHE_MAX_AGE = 24 * 3600  # 24 hours

TRACKER_URLS = {
    "ngosang_udp": "https://github.com/ngosang/trackerslist/raw/refs/heads/master/trackers_all_udp.txt",
    "ngosang_http": "https://github.com/ngosang/trackerslist/raw/refs/heads/master/trackers_all_http.txt",
    "ngosang_https": "https://github.com/ngosang/trackerslist/raw/refs/heads/master/trackers_all_https.txt",
    "xiu2_http": "https://github.com/XIU2/TrackersListCollection/raw/refs/heads/master/http.txt",
    "xiu2_nohttp": "https://github.com/XIU2/TrackersListCollection/raw/refs/heads/master/nohttp.txt",
    "run_all": "https://trackers.run/s/wp_up_hp_hs_v4_v6.txt",
}

async def download_and_cache_trackers(session):
    """Download and cache tracker lists from multiple sources."""
    if not os.path.exists(TRACKER_CACHE_DIR):
        os.makedirs(TRACKER_CACHE_DIR)
        print(f"Created cache directory: {TRACKER_CACHE_DIR}")

    all_trackers = set()
    
    for name, url in TRACKER_URLS.items():
        cache_file = Path(TRACKER_CACHE_DIR) / f"{name}.txt"
        
        # Check cache
        if cache_file.exists():
            file_age = time.time() - cache_file.stat().st_mtime
            if file_age < TRACKER_CACHE_MAX_AGE:
                print(f"Loading trackers for '{name}' from cache (age: {file_age/3600:.1f} hours)...")
                with open(cache_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            all_trackers.add(line)
                continue  # Move to next URL

        # Download if no cache or cache is old
        print(f"Downloading tracker list '{name}' from {url}...")
        try:
            timeout = aiohttp.ClientTimeout(total=60)
            async with session.get(url, timeout=timeout) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    trackers_from_url = {line.strip() for line in text.splitlines() if line.strip()}
                    with open(cache_file, 'w', encoding='utf-8') as f:
                        f.write(text)
                    all_trackers.update(trackers_from_url)
                    print(f"  -> Downloaded and cached {len(trackers_from_url)} trackers.")
                else:
                    print(f"  -> Failed to download '{name}', status: {resp.status}. Will try using cache if it exists.")
                    # If download fails but cache exists (even if old), use it
                    if cache_file.exists():
                        with open(cache_file, 'r', encoding='utf-8') as f:
                            trackers_from_cache = {line.strip() for line in f.read().splitlines() if line.strip()}
                            all_trackers.update(trackers_from_cache)
                            print(f"  -> Using stale cache for '{name}' ({len(trackers_from_cache)} trackers).")

        except Exception as e:
            print(f"  -> Error downloading '{name}': {e}. Will try using cache if it exists.")
            # If any error happens, fallback to cache
            if cache_file.exists():
                with open(cache_file, 'r', encoding='utf-8') as f:
                    trackers_from_cache = {line.strip() for line in f.read().splitlines() if line.strip()}
                    all_trackers.update(trackers_from_cache)
                    print(f"  -> Using stale cache for '{name}' ({len(trackers_from_cache)} trackers).")

    return list(all_trackers)

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
# Get external IPs (both IPv4 and IPv6)
# -----------------------
async def get_external_ips(session):
    """Get external IPv4 and IPv6 addresses"""
    ipv4_services = [
        'http://ipv4.icanhazip.com',
        'http://api.ipify.org',
        'http://ident.me',
        'http://checkip.amazonaws.com',
        'http://ipecho.net/plain'
    ]
    
    ipv6_services = [
        'http://ipv6.icanhazip.com',
        'http://v6.ident.me',
        'http://ipv6.seeip.org',
        'http://ipv6.2ip.io'
    ]
    
    external_ipv4 = None
    external_ipv6_networks = set()
    
    # Get IPv4
    for service in ipv4_services:
        try:
            # Disable proxy for this request
            connector = aiohttp.TCPConnector(family=socket.AF_INET)
            timeout = aiohttp.ClientTimeout(total=8)
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as no_proxy_session:
                async with no_proxy_session.get(service, timeout=timeout) as resp:
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
            connector = aiohttp.TCPConnector(family=socket.AF_INET6)
            timeout = aiohttp.ClientTimeout(total=8)
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as no_proxy_session:
                async with no_proxy_session.get(service, timeout=timeout) as resp:
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
                                    # Create /64 network from the IPv6 address (first 4 hextets)
                                    ip_parts = ip_str.split(':')
                                    if len(ip_parts) >= 4:
                                        # Reconstruct first 4 hextets for /64 network
                                        network_str = ':'.join(ip_parts[:4]) + '::/64'
                                        try:
                                            network = ipaddress.IPv6Network(network_str, strict=False)
                                            if network not in external_ipv6_networks:
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
            
        s = socket.create_connection((ip, port), timeout=timeout) # Removed family, create_connection handles it
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
# Load trackers from file (with duplicate removal)
# -----------------------
def load_trackers(path):
    trackers = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                trackers.append(line)
    
    # Remove duplicates during loading
    unique_trackers = remove_duplicate_trackers(trackers)
    print(f"Loaded {len(unique_trackers)} unique trackers from {path} (removed {len(trackers) - len(unique_trackers)} duplicates)")
    return unique_trackers

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
        
        action, recv_transaction_id, connection_id = struct.unpack("!IIQ", connect_response)
        
        if action != 0 or recv_transaction_id != transaction_id:
            return tracker, "ERROR", "udp_connect_failed", 0, 0, [], round(time.time()-start,2), []
        
        # Prepare announce request
        peer_id = '-PC0001-' + ''.join(random.choices(string.ascii_letters + string.digits, k=12))
        peer_id_bytes = peer_id.encode('ascii')
        
        downloaded = 0
        left = 0
        uploaded = 0
        event = 2  # started
        ip = 0
        key = random.randint(0, 0x7FFFFFFF)
        num_want = -1  # -1 means default
        announce_port = 6881
        
        announce_request = struct.pack("!QII20s20sQQQIIIiH",
            connection_id,  # connection_id
            1,             # action (announce)
            transaction_id, # transaction_id
            info_hash,      # info_hash
            peer_id_bytes,  # peer_id
            downloaded,     # downloaded
            left,           # left
            uploaded,       # uploaded
            event,          # event
            ip,             # ip
            key,            # key
            num_want,       # num_want
            announce_port   # port
        )
        
        # Send announce request
        sock.sendto(announce_request, sockaddr)
        
        # Receive announce response
        announce_response = sock.recv(4096)
        if len(announce_response) < 20:
            return tracker, "ERROR", "udp_announce_response_too_short", 0, 0, [], round(time.time()-start,2), []
        
        # Parse announce response
        action_resp, transaction_id_resp, interval, leechers, seeders = struct.unpack("!IIIII", announce_response[:20])
        
        if action_resp != 1 or transaction_id_resp != transaction_id:
            return tracker, "ERROR", "udp_announce_failed", 0, 0, [], round(time.time()-start,2), []
        
        # Parse peers from compact format
        peers_data = announce_response[20:]
        peers = []
        
        # IPv4 peers (6 bytes per peer: 4 for IP, 2 for port)
        if len(peers_data) % 6 == 0:
            for i in range(0, len(peers_data), 6):
                ip_bytes = peers_data[i:i+4]
                port_bytes = peers_data[i+4:i+6]
                ip = socket.inet_ntoa(ip_bytes)
                port = struct.unpack(">H", port_bytes)[0]
                peers.append((ip, port))
        
        sock.close()
        return tracker, "OK", "", seeders, leechers, peers, round(time.time()-start,2), peers
        
    except socket.timeout:
        return tracker, "ERROR", "udp_timeout", 0, 0, [], round(time.time()-start,2), []
    except Exception as e:
        return tracker, "ERROR", f"udp_error: {str(e)}", 0, 0, [], round(time.time()-start,2), []

# -----------------------
# Announce request (HTTP and UDP)
# -----------------------
async def announce_tracker(session, tracker, info_hash):
    """Announce to tracker (HTTP/HTTPS/UDP)"""
    parsed = urlparse(tracker)
    
    # Handle UDP trackers
    if parsed.scheme == "udp":
        return await announce_udp_tracker(tracker, info_hash)
    
    # Handle HTTP/HTTPS trackers (existing code)
    if parsed.scheme not in ("http", "https"):
        return tracker, "ERROR", "unsupported_scheme", 0, 0, [], 0, []
    
    start = time.time()
    try:
        peer_id = '-PC0001-' + ''.join(random.choices(string.ascii_letters + string.digits, k=12))
        params = {
            "info_hash": info_hash,
            "peer_id": peer_id,
            "port": 6881,
            "uploaded": 0,
            "downloaded": 0,
            "left": 0,
            "compact": 1,
            "event": "started"
        }
        query_parts = []
        for key, value in params.items():
            if key == "info_hash":
                encoded_value = quote_from_bytes(value)
            else:
                encoded_value = quote_from_bytes(str(value).encode())
            query_parts.append(f"{key}={encoded_value}")
        
        # Ensure proper URL construction
        base_url = tracker.rstrip('?&')
        separator = '&' if '?' in base_url else '?'
        url = base_url + separator + "&".join(query_parts)

        timeout = aiohttp.ClientTimeout(total=15)
        async with session.get(url, timeout=timeout) as resp:
            data = await resp.read()
            if resp.status != 200:
                return tracker, "ERROR", f"http_status_{resp.status}", 0, 0, [], round(time.time()-start,2), []
            try:
                info = bencodepy.decode(data)
            except Exception as e:
                return tracker, "ERROR", f"bdecode_error: {str(e)}", 0, 0, [], round(time.time()-start,2), []
            seeders = int(info.get(b"complete", 0))
            leechers = int(info.get(b"incomplete", 0))
            peers = parse_peers_from_response(info)
            return tracker, "OK", "", seeders, leechers, peers, round(time.time()-start,2), peers
    except asyncio.TimeoutError:
        return tracker, "ERROR", "timeout", 0, 0, [], round(time.time()-start,2), []
    except (ConnectionResetError, aiohttp.ClientError, OSError) as e:
        return tracker, "ERROR", f"conn_error: {e}", 0, 0, [], round(time.time()-start,2), []
    except Exception as e:
        return tracker, "ERROR", str(e), 0, 0, [], round(time.time()-start,2), []

# -----------------------
# Worker
# -----------------------
async def worker(name, queue, session, info_hash, results, max_handshake_checks=10):
    while True:
        tracker = await queue.get()
        if tracker is None:
            queue.task_done()
            break
        result = await announce_tracker(session, tracker, info_hash)
        t, status, err, seeders, leechers, peers, dt, peer_ips = result

        bad_ip_count = 0
        handshake_ok = 0
        checked_peers = 0
        verified_peers = []
        bad_ips = []
        good_ips = []

        for ip, port in peer_ips:
            if is_bad_ip(ip):
                bad_ip_count += 1
                bad_ips.append((ip, port))
            else:
                good_ips.append((ip, port))

        # Check handshake on limited number of "good" IPs
        random.shuffle(good_ips) # Randomize to check different peers each time
        for ip, port in good_ips:
            if checked_peers >= max_handshake_checks:
                break
            if is_bittorrent_peer(ip, port, info_hash):
                handshake_ok += 1
                verified_peers.append((ip, port))
            checked_peers += 1

        all_good_ips = good_ips

        results.append({
            "tracker": t,
            "status": status,
            "error": err,
            "seeders": seeders,
            "leechers": leechers,
            "total_peers": len(peer_ips),
            "bad_peers": bad_ip_count,
            "handshake_ok": handshake_ok,
            "good_peers_count": len(all_good_ips),
            "good_peer_ips": all_good_ips,
            "verified_peer_ips": verified_peers,
            "all_peer_ips": peer_ips,
            "time_s": dt
        })

        good_info = f" - {len(all_good_ips)} good IPs" if all_good_ips else ""
        print(f"Checked: {t} - {status} ({seeders} seeders, {leechers} leechers{good_info})")
        queue.task_done()

# -----------------------
# Save files with CORRECTED logic for WORK and GOOD
# -----------------------
def save_additional_files(results, base_path, common_ips, external_ipv4, external_ipv6_networks, bad_flag=False):
    """
    CORRECTED LOGIC:
    
    - Without --bad (default):
        WORK: статус OK + НЕТ ЛЮБЫХ плохих IP (включая external_ip:6881 и другие плохие IP)
        GOOD: статус OK + есть хотя бы один хороший IP + НЕТ ЛЮБЫХ плохих IP
    
    - With --bad:
        WORK: статус OK + единственный возможный "плохой" IP - это external_ip:6881 (но других плохих IP НЕТ)
        GOOD: статус OK + есть хотя бы один хороший IP + единственный возможный "плохой" IP - это external_ip:6881 (но других плохих IP НЕТ)
    """
    work_trackers = []
    good_trackers = []

    for r in results:
        if r["status"] != "OK":
            continue

        all_peers = r["all_peer_ips"] or []
        
        # Check for non-external bad IPs
        has_other_bad_ips = any(is_bad_ip(ip) and not is_our_external_ip(ip, external_ipv4, external_ipv6_networks) for ip, port in all_peers)

        # Check for our external IP with the bad port 6881
        has_bad_external_ip = any(is_bad_external_ip_peer(ip, port, external_ipv4, external_ipv6_networks) for ip, port in all_peers)

        # Check for any good peer (not bogon/private/blocklisted)
        has_good_peer = any(not is_bad_ip(ip) for ip, port in all_peers)
        
        # Check for a good peer that is NOT our external IP
        has_good_non_external_peer = any(not is_bad_ip(ip) and not is_our_external_ip(ip, external_ipv4, external_ipv6_networks) for ip, port in all_peers)

        if bad_flag:
            # --bad mode: Allow our_ip:6881, but no other bad IPs
            if not has_other_bad_ips:
                work_trackers.append(r["tracker"])
                if has_good_peer:
                    good_trackers.append(r["tracker"])
        else:
            # default mode: Strict, no bad IPs of any kind
            if not has_other_bad_ips and not has_bad_external_ip:
                work_trackers.append(r["tracker"])
                if has_good_non_external_peer:
                    good_trackers.append(r["tracker"])

    # Remove duplicates from work and good trackers
    work_trackers = remove_duplicate_trackers(work_trackers)
    good_trackers = remove_duplicate_trackers(good_trackers)

    # Write files
    with open(f"{base_path}_WORK.txt", "w", encoding="utf-8") as f:
        for t in work_trackers:
            f.write(f"{t}\n\n")
    print(f"Saved {len(work_trackers)} work trackers to {base_path}_WORK.txt")

    with open(f"{base_path}_GOOD.txt", "w", encoding="utf-8") as f:
        for t in good_trackers:
            f.write(f"{t}\n\n")
    print(f"Saved {len(good_trackers)} good trackers to {base_path}_GOOD.txt")

    return work_trackers, good_trackers

# -----------------------
# Save IP detail files (including new BAD_IP.txt)
# -----------------------
def save_detailed_ip_files(results, base_path, common_ips, external_ipv4, external_ipv6_networks):
    all_ip_data = []
    for result in results:
        if result["status"] == "OK" and result["all_peer_ips"]:
            tracker_name = urlparse(result["tracker"]).netloc.replace(':', '_')
            suspicious = is_suspicious_tracker(result, common_ips, external_ipv4, external_ipv6_networks)
            has_bad_external_ip = any(is_bad_external_ip_peer(ip, port, external_ipv4, external_ipv6_networks) for ip, port in result["all_peer_ips"])
            has_good_external_ip = any(is_good_external_ip_peer(ip, port, external_ipv4, external_ipv6_networks) for ip, port in result["all_peer_ips"])
            
            all_ip_data.append(f"# {result['tracker']}")
            all_ip_data.append(f"# Seeders: {result['seeders']}, Leechers: {result['leechers']}, Total peers: {result['total_peers']}")
            all_ip_data.append(f"# Suspicious: {suspicious}, Has bad external IP (6881): {has_bad_external_ip}, Has good external IP (!=6881): {has_good_external_ip}")
            
            for ip, port in result["all_peer_ips"]:
                ip_type = "bad" if is_bad_ip(ip) else "good"
                peer_type = "seed" if result["seeders"] > 0 else "peer"
                is_bad_external = " [BAD_EXTERNAL_6881]" if is_bad_external_ip_peer(ip, port, external_ipv4, external_ipv6_networks) else ""
                is_good_external = " [GOOD_EXTERNAL]" if is_good_external_ip_peer(ip, port, external_ipv4, external_ipv6_networks) else ""
                all_ip_data.append(f"{tracker_name} {peer_type} {ip}:{port} # {ip_type}{is_bad_external}{is_good_external}")
            all_ip_data.append("")
            
    if all_ip_data:
        with open(f"{base_path}_IP.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(all_ip_data))
        print(f"Saved all IP data to {base_path}_IP.txt")

    good_ip_data = []
    for result in results:
        if result["status"] == "OK" and result["good_peer_ips"]:
            # Only include non-suspicious trackers here (optional)
            if is_suspicious_tracker(result, common_ips, external_ipv4, external_ipv6_networks):
                continue
            tracker_name = urlparse(result["tracker"]).netloc.replace(':', '_')
            has_bad_external_ip = any(is_bad_external_ip_peer(ip, port, external_ipv4, external_ipv6_networks) for ip, port in result["all_peer_ips"])
            has_good_external_ip = any(is_good_external_ip_peer(ip, port, external_ipv4, external_ipv6_networks) for ip, port in result["all_peer_ips"])
            
            good_ip_data.append(f"# {result['tracker']}")
            good_ip_data.append(f"# Seeders: {result['seeders']}, Leechers: {result['leechers']}, Good peers: {len(result['good_peer_ips'])}")
            good_ip_data.append(f"# Has bad external IP (6881): {has_bad_external_ip}, Has good external IP (!=6881): {has_good_external_ip}")
            
            for ip, port in result["good_peer_ips"]:
                peer_type = "seed" if result["seeders"] > 0 else "peer"
                is_bad_external = " [BAD_EXTERNAL_6881]" if is_bad_external_ip_peer(ip, port, external_ipv4, external_ipv6_networks) else ""
                is_good_external = " [GOOD_EXTERNAL]" if is_good_external_ip_peer(ip, port, external_ipv4, external_ipv6_networks) else ""
                good_ip_data.append(f"{tracker_name} {peer_type} {ip}:{port}{is_bad_external}{is_good_external}")
            good_ip_data.append("")
            
    if good_ip_data:
        with open(f"{base_path}_GOOD_IP.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(good_ip_data))
        print(f"Saved good IP data to {base_path}_GOOD_IP.txt")

    # NEW: Save BAD IP file
    bad_ip_data = []
    for result in results:
        if result["status"] == "OK" and result["all_peer_ips"]:
            tracker_name = urlparse(result["tracker"]).netloc.replace(':', '_')
            bad_ips_in_tracker = []
            
            for ip, port in result["all_peer_ips"]:
                reasons = []
                if is_bad_ip(ip):
                    reasons.append("bogon/private/blocklisted")
                if is_bad_external_ip_peer(ip, port, external_ipv4, external_ipv6_networks):
                    reasons.append("bad_external_6881")
                
                if reasons:
                    bad_ips_in_tracker.append((ip, port, reasons))
            
            if bad_ips_in_tracker:
                bad_ip_data.append(f"# {result['tracker']}")
                bad_ip_data.append(f"# Seeders: {result['seeders']}, Leechers: {result['leechers']}, Total peers: {result['total_peers']}, Bad peers: {len(bad_ips_in_tracker)}")
                
                for ip, port, reasons in bad_ips_in_tracker:
                    reason_str = ", ".join(reasons)
                    bad_ip_data.append(f"{tracker_name} {ip}:{port} # {reason_str}")
                bad_ip_data.append("")
    
    if bad_ip_data:
        with open(f"{base_path}_BAD_IP.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(bad_ip_data))
        print(f"Saved bad IP data to {base_path}_BAD_IP.txt")

# -----------------------
# Save statistics
# -----------------------
def save_statistics(results, base_path, external_ipv4, external_ipv6_networks, common_ips, bad_flag=False):
    stats = []
    stats.append("Tracker Statistics")
    stats.append("=" * 50)
    
    if bad_flag:
        stats.append("MODE: --bad enabled (allowing trackers with our external IP even with port 6881)")
    else:
        stats.append("MODE: Standard (excluding trackers with our external IP and port 6881)")
    stats.append("")
    
    total = len(results)
    successful = len([r for r in results if r['status'] == 'OK'])

    # Count trackers by protocol
    http_trackers = len([r for r in results if r['tracker'].startswith(('http:', 'https:'))])
    udp_trackers = len([r for r in results if r['tracker'].startswith('udp:')])
    successful_http = len([r for r in results if r['status'] == 'OK' and r['tracker'].startswith(('http:', 'https:'))])
    successful_udp = len([r for r in results if r['status'] == 'OK' and r['tracker'].startswith('udp:')])

    # Count unique trackers (after duplicate removal)
    unique_tracker_keys = set()
    for r in results:
        unique_tracker_keys.add(get_tracker_key(r['tracker']))
    
    stats.append(f"Total trackers checked: {total}")
    stats.append(f"Unique trackers (by protocol-domain-port): {len(unique_tracker_keys)}")
    stats.append(f"  - HTTP/HTTPS trackers: {http_trackers}")
    stats.append(f"  - UDP trackers: {udp_trackers}")
    stats.append(f"Successful responses: {successful}")
    stats.append(f"  - HTTP/HTTPS successful: {successful_http}")
    stats.append(f"  - UDP successful: {successful_udp}")
    stats.append("")

    work_trackers, good_trackers = [], [] # Need to recalculate for stats
    bad_external_ip_count = 0
    good_external_ip_count = 0
    
    for r in results:
        if r["status"] != "OK":
            continue
        peers = r["all_peer_ips"] or []
        has_bad_external_ip = any(is_bad_external_ip_peer(ip, port, external_ipv4, external_ipv6_networks) for ip, port in peers)
        has_other_bad_ips = any(is_bad_ip(ip) and not is_our_external_ip(ip, external_ipv4, external_ipv6_networks) for ip, port in peers)
        has_good_external_ip = any(is_good_external_ip_peer(ip, port, external_ipv4, external_ipv6_networks) for ip, port in peers)
        has_good_peer = any(not is_bad_ip(ip) for ip, port in peers)
        has_good_non_external_peer = any(not is_bad_ip(ip) and not is_our_external_ip(ip, external_ipv4, external_ipv6_networks) for ip, port in peers)

        if has_bad_external_ip:
            bad_external_ip_count += 1
        if has_good_external_ip:
            good_external_ip_count += 1
            
        if bad_flag:
            if not has_other_bad_ips:
                work_trackers.append(r["tracker"])
                if has_good_peer:
                    good_trackers.append(r["tracker"])
        else:
            if not has_other_bad_ips and not has_bad_external_ip:
                work_trackers.append(r["tracker"])
                if has_good_non_external_peer:
                    good_trackers.append(r["tracker"])
    
    stats.append("CRITERIA SUMMARY:")
    if bad_flag:
        stats.append("WORK trackers (OK status, no bogon/private IPs other than our own):")
        stats.append("GOOD trackers (WORK criteria + at least one good peer):")
    else:
        stats.append("WORK trackers (OK status, no bad IPs of any kind, including our_ip:6881):")
        stats.append("GOOD trackers (WORK criteria + at least one good non-external peer):")
    
    stats.append(f"Work trackers: {len(remove_duplicate_trackers(work_trackers))}")
    stats.append(f"Good trackers: {len(remove_duplicate_trackers(good_trackers))}")
    stats.append(f"Trackers with bad external IP (port 6881): {bad_external_ip_count}")
    stats.append(f"Trackers with good external IP (port != 6881): {good_external_ip_count}")
    stats.append("")

    total_ips = sum(len(r["all_peer_ips"]) for r in results if r["status"] == "OK")
    good_ips = sum(len(r["good_peer_ips"]) for r in results if r["status"] == "OK")
    verified_ips = sum(len(r["verified_peer_ips"]) for r in results if r["status"] == "OK")
    
    external_ip_peers_6881 = 0
    external_ip_peers_other = 0
    for r in results:
        if r["status"] == "OK":
            for ip, port in r["all_peer_ips"]:
                if is_our_external_ip(ip, external_ipv4, external_ipv6_networks):
                    if port == 6881:
                        external_ip_peers_6881 += 1
                    else:
                        external_ip_peers_other += 1

    stats.append(f"Total IPs found: {total_ips}")
    stats.append(f"Good IPs (non-bogon): {good_ips}")
    stats.append(f"Verified IPs (handshake ok): {verified_ips}")
    stats.append(f"Bad IPs (bogon/private/blocklisted): {total_ips - good_ips}")
    stats.append("")
    stats.append(f"External IPv4: {external_ipv4}")
    if external_ipv6_networks:
        stats.append(f"External IPv6 networks (/64): {len(external_ipv6_networks)}")
        for network in external_ipv6_networks:
            stats.append(f"  - {network}")
    stats.append(f"External IP peers with port 6881 (BAD): {external_ip_peers_6881}")
    stats.append(f"External IP peers with other ports (WORKING): {external_ip_peers_other}")
    stats.append(f"Blocklist networks loaded: {len(BAD_NETWORKS)}")
    stats.append("")

    suspicious_trackers = [r for r in results if r["status"] == "OK" and is_suspicious_tracker(r, common_ips, external_ipv4, external_ipv6_networks)]
    stats.append(f"Suspicious trackers (detected): {len(suspicious_trackers)}")
    for tracker in suspicious_trackers:
        stats.append(f"  - {urlparse(tracker['tracker']).netloc}")

    with open(f"{base_path}_STATS.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(stats))
    print(f"Saved statistics to {base_path}_STATS.txt")

# -----------------------
# Main async
# -----------------------
async def main_async(args, info_hash):
    # Load iblocklist first
    print("Loading blocklist...")
    await load_iblocklist()
    
    bad_domains = load_bad_trackers()
    results = []
    queue = asyncio.Queue()
    
    # Generate dynamic output filenames for this run
    timestamp = time.strftime("%Y%m%d_%H%M")
    infohash_hex = binascii.hexlify(info_hash).decode('ascii')
    base_path = f"trackers_check_{infohash_hex}_{timestamp}"
    csv_output_file = f"{base_path}.csv"

    connector = aiohttp.TCPConnector(limit=args.concurrency, limit_per_host=2)
    session_timeout = aiohttp.ClientTimeout(total=30, connect=10, sock_read=10)

    async with aiohttp.ClientSession(connector=connector, timeout=session_timeout) as session:
        # Download and cache tracker lists
        downloaded_trackers = await download_and_cache_trackers(session)
        
        # Load local trackers if file exists
        local_trackers = []
        if os.path.exists(args.trackers):
            print(f"Loading local trackers from {args.trackers}...")
            with open(args.trackers, 'r', encoding='utf-8') as f:
                local_trackers = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            print(f"  -> Loaded {len(local_trackers)} local trackers.")
        else:
            print(f"Local tracker file not found: {args.trackers}")
        
        # Combine and de-duplicate BEFORE checks
        print("Combining and removing duplicate trackers...")
        combined_trackers = downloaded_trackers + local_trackers
        trackers = remove_duplicate_trackers(combined_trackers)
        print(f"Total unique trackers to check: {len(trackers)}")
        
        print("\nDetecting external IPs...")
        external_ipv4, external_ipv6_networks = await get_external_ips(session)
        print(f"Using external IPv4: {external_ipv4}")
        if external_ipv6_networks:
            print(f"Using external IPv6 networks (/64): {len(external_ipv6_networks)}")
            for network in external_ipv6_networks:
                print(f"  - {network}")

        # Filter trackers by domain and IP blocklist (initial quick filter)
        print("\nFiltering trackers by bad domains and blocklisted IPs...")
        trackers = await filter_bad_trackers(trackers, bad_domains, session)
        
        print(f"\nStarting announce to {len(trackers)} trackers...")
        for tr in trackers:
            queue.put_nowait(tr)

        workers = [
            asyncio.create_task(worker(f"W{i}", queue, session, info_hash, results, args.max_handshakes))
            for i in range(args.concurrency)
        ]

        await queue.join()
        for _ in workers:
            queue.put_nowait(None)
        await asyncio.gather(*workers, return_exceptions=True)

    print("\nAnalyzing peer consistency...")
    common_ips = analyze_peer_consistency(results)

    # Save results
    print("\nSaving result files...")
    with open(csv_output_file, "w", newline="", encoding="utf-8") as fo:
        writer = csv.DictWriter(fo, fieldnames=[
            "tracker", "status", "error", "seeders", "leechers",
            "total_peers", "bad_peers", "handshake_ok", "good_peers_count", "time_s"
        ])
        writer.writeheader()
        for r in results:
            row = {k: v for k, v in r.items() if k not in ["good_peer_ips", "verified_peer_ips", "all_peer_ips"]}
            writer.writerow(row)

    save_additional_files(results, base_path, common_ips, external_ipv4, external_ipv6_networks, args.bad)
    save_detailed_ip_files(results, base_path, common_ips, external_ipv4, external_ipv6_networks)
    save_statistics(results, base_path, external_ipv4, external_ipv6_networks, common_ips, args.bad)

    print(f"\nMain results saved to {csv_output_file}")
    print(f"Total trackers checked: {len(results)}")
    
    unique_tracker_keys = {get_tracker_key(r['tracker']) for r in results}
    print(f"Unique trackers (by protocol-domain-port): {len(unique_tracker_keys)}")
    
    successful = len([r for r in results if r['status'] == 'OK'])
    print(f"Successful: {successful}")
    
    http_trackers = len([r for r in results if r['tracker'].startswith(('http:', 'https:'))])
    udp_trackers = len([r for r in results if r['tracker'].startswith('udp:')])
    successful_http = len([r for r in results if r['status'] == 'OK' and r['tracker'].startswith(('http:', 'https:'))])
    successful_udp = len([r for r in results if r['status'] == 'OK' and r['tracker'].startswith('udp:')])
    
    print(f"HTTP/HTTPS trackers: {http_trackers} (successful: {successful_http})")
    print(f"UDP trackers: {udp_trackers} (successful: {successful_udp})")
    print(f"External IPv4: {external_ipv4}")
    if external_ipv6_networks:
        print(f"External IPv6 networks (/64): {len(external_ipv6_networks)}")
    print(f"Blocklist networks: {len(BAD_NETWORKS)}")
    
    if args.bad:
        print("MODE: --bad enabled (trackers with our external IP even with port 6881 are included in WORK and GOOD)")

# -----------------------
# CLI
# -----------------------
def main():
    parser = argparse.ArgumentParser(description="Проверка HTTP(S)/UDP трекеров на fake/bogon сиды/пиры с iblocklist фильтрацией и удалением дубликатов")
    parser.add_argument("--trackers", default="trackers.txt", help="Дополнительный локальный файл со списком трекеров")
    parser.add_argument("--concurrency", type=int, default=4, help="Максимум одновременных запросов")
    parser.add_argument("--infohash", help="Magnet или hex/base32 infohash для одной проверки")
    parser.add_argument("--magnet", help="Файл с magnet-ссылками для проверки (по умолчанию: trackers_magnet.txt)")
    parser.add_argument("--max-handshakes", type=int, default=5, help="Максимум проверок handshake на трекер")
    parser.add_argument("--bad", action="store_true", help="Включить трекеры с нашим внешним IP (даже с портом 6881) в WORK и GOOD файлы")
    args = parser.parse_args()

    infohashes_to_check = []
    
    # Determine the source of infohashes
    if args.infohash:
        source_name = f"аргумент --infohash"
        try:
            infohashes_to_check.append(parse_infohash(args.infohash))
        except ValueError as e:
            print(f"Ошибка в --infohash: {e}")
            return
    else:
        magnet_file = args.magnet if args.magnet else "trackers_magnet.txt"
        source_name = f"файл '{magnet_file}'"
        if not os.path.exists(magnet_file):
            print(f"Файл с magnet-ссылками не найден: {magnet_file}")
            print("Укажите infohash с помощью --infohash или --magnet, или создайте файл trackers_magnet.txt")
            return
        with open(magnet_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line.startswith("magnet:?"):
                    try:
                        infohashes_to_check.append(parse_infohash(line))
                    except ValueError as e:
                        print(f"Не удалось извлечь infohash из строки '{line[:60]}...': {e}")

    if not infohashes_to_check:
        print(f"Не найдено ни одного infohash для проверки в {source_name}.")
        return

    # Main loop for each infohash
    total_hashes = len(infohashes_to_check)
    for i, info_hash_bytes in enumerate(infohashes_to_check):
        print("\n" + "="*80)
        print(f"Проверка InfoHash {i+1}/{total_hashes}: {binascii.hexlify(info_hash_bytes).decode('ascii')}")
        print("="*80 + "\n")
        
        if os.name == 'nt':
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

        try:
            asyncio.run(main_async(args, info_hash_bytes))
        except KeyboardInterrupt:
            print("\nПрервано пользователем")
            break # Exit the loop
        except Exception as e:
            print(f"Произошла критическая ошибка при проверке хэша: {e}")
            # To continue to the next hash on error, uncomment the next line
            # continue
            break

if __name__ == "__main__":
    main()
