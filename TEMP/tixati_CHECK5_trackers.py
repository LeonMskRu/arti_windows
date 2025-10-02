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
# Get external IP
# -----------------------
async def get_external_ip(session):
    """Get external IP using provided session"""
    services = [
        'http://ipv4.icanhazip.com',
        'http://api.ipify.org',
        'http://ident.me',
        'http://checkip.amazonaws.com',
        'http://ipecho.net/plain'
    ]
    for service in services:
        try:
            timeout = aiohttp.ClientTimeout(total=8)
            async with session.get(service, timeout=timeout) as resp:
                if resp.status == 200:
                    ip_text = (await resp.text()).strip()
                    ip = ipaddress.ip_address(ip_text)
                    print(f"External IP detected: {ip} from {service}")
                    return str(ip)
        except Exception as e:
            print(f"Failed to get IP from {service}: {e}")
            continue
    raise Exception("Could not determine external IP from any service")

# -----------------------
# Filter trackers with bad domains and blocklisted IPs
# -----------------------
async def filter_bad_trackers(trackers, bad_domains, session):
    """Filter trackers by bad domains and blocklisted IPs"""
    if not bad_domains and not BAD_NETWORKS:
        return trackers
    
    filtered = []
    semaphore = asyncio.Semaphore(10)  # Limit concurrent DNS lookups
    
    async def check_tracker(tracker):
        try:
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
    print(f"Filtered {len(trackers) - len(filtered)} bad trackers")
    return filtered

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
def is_suspicious_tracker(result, common_ips, external_ip):
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
        
        # IPv6 unique local
        if addr.version == 6 and ipaddress.IPv6Address('fc00::') <= addr <= ipaddress.IPv6Address('fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'):
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
def is_bad_external_ip_peer(ip, port, external_ip):
    """Check if peer is external IP with port 6881 (bad)"""
    return ip == external_ip and port == 6881

# -----------------------
# Check if peer is good external IP
# -----------------------
def is_good_external_ip_peer(ip, port, external_ip):
    """Check if peer is external IP with port != 6881 (working)"""
    return ip == external_ip and port != 6881

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
        s = socket.create_connection((ip, port), timeout=timeout)
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
# Load trackers from file
# -----------------------
def load_trackers(path):
    trackers = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                trackers.append(line)
    return trackers

# -----------------------
# Parse peers from tracker response
# -----------------------
def parse_peers_from_response(info):
    peers = []
    try:
        peers_bin = info.get(b"peers", b"")
        # Compact binary format
        if isinstance(peers_bin, bytes) and len(peers_bin) % 6 == 0 and len(peers_bin) > 0:
            for i in range(0, len(peers_bin), 6):
                ip_bytes = peers_bin[i:i+4]
                port_bytes = peers_bin[i+4:i+6]
                ip = ".".join(str(b) for b in ip_bytes)
                port = struct.unpack(">H", port_bytes)[0]
                peers.append((ip, port))
        # Dict/list format
        elif isinstance(peers_bin, list):
            for peer in peers_bin:
                if isinstance(peer, dict):
                    ip_bytes = peer.get(b'ip')
                    port = peer.get(b'port', 0)
                    if ip_bytes:
                        if isinstance(ip_bytes, bytes):
                            ip = ip_bytes.decode('utf-8', errors='ignore')
                        else:
                            ip = str(ip_bytes)
                        if ip and port:
                            peers.append((ip, port))
    except Exception as e:
        print(f"Error parsing peers: {e}")
    return peers

# -----------------------
# Announce request
# -----------------------
async def announce_tracker(session, tracker, info_hash):
    parsed = urlparse(tracker)
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
                encoded_value = quote_from_bytes(str(value).encode()) if isinstance(value, bytes) else quote_from_bytes(str(value).encode())
            query_parts.append(f"{key}={encoded_value}")
        url = tracker + ("&" if "?" in tracker else "?") + "&".join(query_parts)
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
# Save files with NEW logic for WORK and GOOD
# -----------------------
def save_additional_files(results, base_path, common_ips, external_ip):
    """
    NEW LOGIC:
    - WORK: 
        1. статус OK
        2. НЕТ external_ip:6881 (плохой)
        3. НЕТ других плохих IP (bogon/private/blocklisted)
        4. МОЖЕТ БЫТЬ external_ip с портом != 6881 (рабочий)
    - GOOD: любой трекер со статусом OK и хотя бы одним не-bogon и не-external IP
    """
    work_trackers = []
    good_trackers = []

    for r in results:
        if r["status"] != "OK":
            continue

        all_peers = r["all_peer_ips"] or []
        
        # Проверяем наличие плохих IP (external_ip:6881 или другие плохие IP)
        has_bad_external_ip = any(is_bad_external_ip_peer(ip, port, external_ip) for ip, port in all_peers)
        has_other_bad_ips = any(is_bad_ip(ip) for ip, port in all_peers)
        
        # WORK условие: нет external_ip:6881 И нет других плохих IP
        if not has_bad_external_ip and not has_other_bad_ips:
            work_trackers.append(r["tracker"])

        # GOOD условие: есть хотя бы один не-bogon и не-external IP
        good_peer_found = False
        for ip, port in all_peers:
            if (not is_bad_ip(ip)) and ip != external_ip:
                good_peer_found = True
                break
        if good_peer_found:
            good_trackers.append(r["tracker"])

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
# Save IP detail files
# -----------------------
def save_detailed_ip_files(results, base_path, common_ips, external_ip):
    all_ip_data = []
    for result in results:
        if result["status"] == "OK" and result["all_peer_ips"]:
            tracker_name = urlparse(result["tracker"]).netloc.replace(':', '_')
            suspicious = is_suspicious_tracker(result, common_ips, external_ip)
            has_bad_external_ip = any(is_bad_external_ip_peer(ip, port, external_ip) for ip, port in result["all_peer_ips"])
            has_good_external_ip = any(is_good_external_ip_peer(ip, port, external_ip) for ip, port in result["all_peer_ips"])
            
            all_ip_data.append(f"# {result['tracker']}")
            all_ip_data.append(f"# Seeders: {result['seeders']}, Leechers: {result['leechers']}, Total peers: {result['total_peers']}")
            all_ip_data.append(f"# Suspicious: {suspicious}, Has bad external IP (6881): {has_bad_external_ip}, Has good external IP (!=6881): {has_good_external_ip}")
            
            for ip, port in result["all_peer_ips"]:
                ip_type = "bad" if is_bad_ip(ip) else "good"
                peer_type = "seed" if result["seeders"] > 0 else "peer"
                is_bad_external = " [BAD_EXTERNAL_6881]" if is_bad_external_ip_peer(ip, port, external_ip) else ""
                is_good_external = " [GOOD_EXTERNAL]" if is_good_external_ip_peer(ip, port, external_ip) else ""
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
            if is_suspicious_tracker(result, common_ips, external_ip):
                continue
            tracker_name = urlparse(result["tracker"]).netloc.replace(':', '_')
            has_bad_external_ip = any(is_bad_external_ip_peer(ip, port, external_ip) for ip, port in result["all_peer_ips"])
            has_good_external_ip = any(is_good_external_ip_peer(ip, port, external_ip) for ip, port in result["all_peer_ips"])
            
            good_ip_data.append(f"# {result['tracker']}")
            good_ip_data.append(f"# Seeders: {result['seeders']}, Leechers: {result['leechers']}, Good peers: {len(result['good_peer_ips'])}")
            good_ip_data.append(f"# Has bad external IP (6881): {has_bad_external_ip}, Has good external IP (!=6881): {has_good_external_ip}")
            
            for ip, port in result["good_peer_ips"]:
                peer_type = "seed" if result["seeders"] > 0 else "peer"
                is_bad_external = " [BAD_EXTERNAL_6881]" if is_bad_external_ip_peer(ip, port, external_ip) else ""
                is_good_external = " [GOOD_EXTERNAL]" if is_good_external_ip_peer(ip, port, external_ip) else ""
                good_ip_data.append(f"{tracker_name} {peer_type} {ip}:{port}{is_bad_external}{is_good_external}")
            good_ip_data.append("")
            
    if good_ip_data:
        with open(f"{base_path}_GOOD_IP.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(good_ip_data))
        print(f"Saved good IP data to {base_path}_GOOD_IP.txt")

# -----------------------
# Save statistics
# -----------------------
def save_statistics(results, base_path, external_ip, common_ips):
    stats = []
    stats.append("Tracker Statistics")
    stats.append("=" * 50)
    total = len(results)
    successful = len([r for r in results if r['status'] == 'OK'])

    # NEW criteria
    work_new = 0
    good_new = 0
    bad_external_ip_count = 0
    good_external_ip_count = 0
    
    for r in results:
        if r["status"] != "OK":
            continue
        peers = r["all_peer_ips"] or []
        has_bad_external_ip = any(is_bad_external_ip_peer(ip, port, external_ip) for ip, port in peers)
        has_other_bad_ips = any(is_bad_ip(ip) for ip, port in peers)
        has_good_external_ip = any(is_good_external_ip_peer(ip, port, external_ip) for ip, port in peers)
        
        if has_bad_external_ip:
            bad_external_ip_count += 1
        if has_good_external_ip:
            good_external_ip_count += 1
            
        # NEW WORK CONDITION
        if not has_bad_external_ip and not has_other_bad_ips:
            work_new += 1
            
        if any((not is_bad_ip(ip)) and ip != external_ip for ip, _ in peers):
            good_new += 1

    stats.append(f"Total trackers checked: {total}")
    stats.append(f"Successful responses: {successful}")
    stats.append("")
    stats.append("NEW CRITERIA:")
    stats.append(f"Work trackers (no bad external IP 6881, no other bad IPs): {work_new}")
    stats.append(f"Good trackers (have at least one non-bogon non-external IP): {good_new}")
    stats.append(f"Trackers with bad external IP (port 6881): {bad_external_ip_count}")
    stats.append(f"Trackers with good external IP (port != 6881): {good_external_ip_count}")
    stats.append("")

    total_ips = sum(len(r["all_peer_ips"]) for r in results if r["status"] == "OK")
    good_ips = sum(len(r["good_peer_ips"]) for r in results if r["status"] == "OK")
    verified_ips = sum(len(r["verified_peer_ips"]) for r in results if r["status"] == "OK")
    
    # Count external IP peers by port
    external_ip_peers_6881 = 0
    external_ip_peers_other = 0
    for r in results:
        if r["status"] == "OK":
            for ip, port in r["all_peer_ips"]:
                if ip == external_ip:
                    if port == 6881:
                        external_ip_peers_6881 += 1
                    else:
                        external_ip_peers_other += 1

    stats.append(f"Total IPs found: {total_ips}")
    stats.append(f"Good IPs (non-bogon): {good_ips}")
    stats.append(f"Verified IPs (handshake ok): {verified_ips}")
    stats.append(f"Bad IPs (bogon/private/blocklisted): {total_ips - good_ips}")
    stats.append("")
    stats.append(f"External IP: {external_ip}")
    stats.append(f"External IP peers with port 6881 (BAD): {external_ip_peers_6881}")
    stats.append(f"External IP peers with other ports (WORKING): {external_ip_peers_other}")
    stats.append(f"Blocklist networks loaded: {len(BAD_NETWORKS)}")
    stats.append("")

    suspicious_trackers = [r for r in results if r["status"] == "OK" and is_suspicious_tracker(r, common_ips, external_ip)]
    stats.append(f"Suspicious trackers (detected): {len(suspicious_trackers)}")
    for tracker in suspicious_trackers:
        stats.append(f"  - {urlparse(tracker['tracker']).netloc}")

    with open(f"{base_path}_STATS.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(stats))
    print(f"Saved statistics to {base_path}_STATS.txt")

# -----------------------
# Main async
# -----------------------
async def main_async(args):
    # Load iblocklist first
    print("Loading blocklist...")
    await load_iblocklist()
    
    bad_domains = load_bad_trackers()
    trackers = load_trackers(args.trackers)
    
    info_hash = parse_infohash(args.infohash)
    results = []
    queue = asyncio.Queue()
    
    connector = aiohttp.TCPConnector(limit=args.concurrency, limit_per_host=2, ssl=False)
    session_timeout = aiohttp.ClientTimeout(total=30, connect=10, sock_read=10)

    async with aiohttp.ClientSession(connector=connector, timeout=session_timeout) as session:
        print("Detecting external IP...")
        external_ip = await get_external_ip(session)
        print(f"Using external IP: {external_ip}")

        # Filter trackers (domains + IP blocklist)
        print("Filtering trackers...")
        trackers = await filter_bad_trackers(trackers, bad_domains, session)
        
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

    print("Analyzing peer consistency...")
    common_ips = analyze_peer_consistency(results)

    # Save CSV
    with open(args.out, "w", newline="", encoding="utf-8") as fo:
        writer = csv.DictWriter(fo, fieldnames=[
            "tracker", "status", "error", "seeders", "leechers",
            "total_peers", "bad_peers", "handshake_ok", "good_peers_count", "time_s"
        ])
        writer.writeheader()
        for r in results:
            row = {k: v for k, v in r.items() if k not in ["good_peer_ips", "verified_peer_ips", "all_peer_ips"]}
            writer.writerow(row)

    base_path = os.path.splitext(args.out)[0]
    save_additional_files(results, base_path, common_ips, external_ip)
    save_detailed_ip_files(results, base_path, common_ips, external_ip)
    save_statistics(results, base_path, external_ip, common_ips)

    print(f"\nMain results saved to {args.out}")
    print(f"Total trackers checked: {len(results)}")
    successful = len([r for r in results if r['status'] == 'OK'])
    print(f"Successful: {successful}")
    print(f"External IP used for filtering: {external_ip}")
    print(f"Blocklist networks: {len(BAD_NETWORKS)}")

# -----------------------
# CLI
# -----------------------
def main():
    parser = argparse.ArgumentParser(description="Проверка HTTP(S) трекеров на fake/bogon сиды/пиры с iblocklist фильтрацией")
    parser.add_argument("--trackers", default="trackers.txt", help="Файл со списком трекеров")
    parser.add_argument("--concurrency", type=int, default=4, help="Максимум одновременных запросов")
    parser.add_argument("--infohash", required=True, help="Magnet или hex/base32 infohash")
    parser.add_argument("--out", default="trackers_check.csv", help="CSV файл для вывода")
    parser.add_argument("--max-handshakes", type=int, default=5, help="Максимум проверок handshake на трекер")
    args = parser.parse_args()

    if os.name == 'nt':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\nПрервано пользователем")
    except Exception as e:
        print(f"Произошла ошибка: {e}")

if __name__ == "__main__":
    main()
