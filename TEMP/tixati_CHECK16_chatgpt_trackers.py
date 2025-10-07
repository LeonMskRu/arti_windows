#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tixati_CHECK14_trackers.py - обновлённая версия
Основные изменения:
 - Загрузка внешних списков трекеров с кэшированием (sources/)
 - Объединение trackers.txt + скачанные списки
 - Удаление дубликатов ДО проверок
 - Поддержка magnet-файла с несколькими magnet-ссылками (--infohash "" и --magnet trackers_magnet.txt)
 - Сохранение результатов для каждого infohash в отдельные файлы с временной меткой
 - Улучшенная обработка http->https и отсутствие схемы (пробуем https затем http)
"""

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
# Constants & configuration
# -----------------------
IBLOCKLIST_CACHE_FILE = "iblocklist.txt"
IBLOCKLIST_CACHE_MAX_AGE = 24 * 3600  # 24 hours in seconds
IBLOCKLIST_URL = "https://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=cidr&archiveformat=zip"

TRACKER_SOURCE_URLS = [
    "https://github.com/ngosang/trackerslist/raw/refs/heads/master/trackers_all_udp.txt",
    "https://github.com/ngosang/trackerslist/raw/refs/heads/master/trackers_all_http.txt",
    "https://github.com/ngosang/trackerslist/raw/refs/heads/master/trackers_all_https.txt",
    "https://github.com/XIU2/TrackersListCollection/raw/refs/heads/master/http.txt",
    "https://github.com/XIU2/TrackersListCollection/raw/refs/heads/master/nohttp.txt",
    "https://trackers.run/s/wp_up_hp_hs_v4_v6.txt",
]

TRACKER_SOURCES_DIR = Path("sources")
TRACKER_SOURCES_DIR.mkdir(exist_ok=True)

BAD_NETWORKS = []

# -----------------------
# Utilities
# -----------------------
def safe_filename(s: str) -> str:
    s = re.sub(r'[^A-Za-z0-9._-]', '_', s)
    return s.strip('_')

def hex_infohash(infohash_bytes: bytes) -> str:
    return binascii.hexlify(infohash_bytes).decode('ascii').lower()

def now_timestamp_str():
    return datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")

# -----------------------
# IBlocklist Management with caching
# -----------------------
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

    cached = load_iblocklist_cache()
    if cached is not None:
        BAD_NETWORKS = cached
        return

    networks = await download_iblocklist()
    if networks:
        BAD_NETWORKS = networks
        save_iblocklist_cache(networks)
    else:
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
# External tracker sources download with caching (24h)
# -----------------------
async def download_tracker_source(session: aiohttp.ClientSession, url: str, max_age=24*3600):
    """
    Download a tracker source into sources/ with caching.
    Returns list of tracker lines (strings).
    """
    # choose filename from url
    parsed = urlparse(url)
    fname = safe_filename(parsed.netloc + parsed.path)
    if not fname:
        fname = hashlib.sha1(url.encode()).hexdigest()
    dest = TRACKER_SOURCES_DIR / fname
    # if exists and fresh - read and return
    if dest.exists():
        age = time.time() - dest.stat().st_mtime
        if age < max_age:
            try:
                with open(dest, encoding='utf-8') as f:
                    lines = [l.strip() for l in f if l.strip() and not l.strip().startswith('#')]
                print(f"Using cached source {dest} (age {age/3600:.1f}h)")
                return lines
            except Exception as e:
                print(f"Failed reading cached {dest}: {e}")
    # otherwise download
    try:
        timeout = aiohttp.ClientTimeout(total=30)
        async with session.get(url, timeout=timeout) as resp:
            if resp.status != 200:
                print(f"Failed to download {url}: HTTP {resp.status}")
                return []
            text = await resp.text()
            lines = []
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    lines.append(line)
            # save to file
            try:
                with open(dest, 'w', encoding='utf-8') as f:
                    f.write(text)
                print(f"Downloaded and cached {url} -> {dest} ({len(lines)} lines)")
            except Exception as e:
                print(f"Failed to cache {dest}: {e}")
            return lines
    except Exception as e:
        print(f"Error downloading {url}: {e}")
        return []

async def download_all_tracker_sources(loop=None):
    """Download all sources concurrently and return merged list"""
    async with aiohttp.ClientSession() as session:
        tasks = [download_tracker_source(session, u) for u in TRACKER_SOURCE_URLS]
        results = await asyncio.gather(*tasks)
    merged = []
    for r in results:
        merged.extend(r)
    print(f"Downloaded/loaded {len(merged)} total lines from external sources")
    return merged

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
            connector = aiohttp.TCPConnector(family=socket.AF_INET, ssl=False)
            timeout = aiohttp.ClientTimeout(total=8)
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as no_proxy_session:
                async with no_proxy_session.get(service, timeout=timeout) as resp:
                    if resp.status == 200:
                        ip_text = (await resp.text()).strip()
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
            connector = aiohttp.TCPConnector(family=socket.AF_INET6, ssl=False)
            timeout = aiohttp.ClientTimeout(total=8)
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as no_proxy_session:
                async with no_proxy_session.get(service, timeout=timeout) as resp:
                    if resp.status == 200:
                        resp_text = await resp.text()
                        ipv6_pattern = r'(?:(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4})|(?:(?:[0-9a-fA-F]{1,4}:){1,7}:)|(?:(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})|(?:(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2})|(?:(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3})|(?:(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4})|(?:(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5})|(?:[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6})|(?::(?::[0-9a-fA-F]{1,4}){1,7}|:))'
                        ip_matches = re.findall(ipv6_pattern, resp_text)
                        for ip_match in ip_matches:
                            try:
                                ip = ipaddress.ip_address(ip_match.strip())
                                if ip.version == 6:
                                    ip_str = str(ip)
                                    # If specific prefix logic is needed, adapt here; for now we add a /64 of the address
                                    ip_parts = ip_str.split(':')
                                    if len(ip_parts) >= 4:
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
# Tracker dedupe & filtering utils
# -----------------------
def get_tracker_key(tracker_url):
    """Generate unique key for tracker based on protocol, domain, and port"""
    try:
        parsed = urlparse(tracker_url)
        scheme = parsed.scheme.lower() if parsed.scheme else ""
        hostname = parsed.hostname.lower() if parsed.hostname else ""
        port = parsed.port

        # Set default ports if not specified
        if port is None:
            if scheme == 'http':
                port = 80
            elif scheme == 'https':
                port = 443
            elif scheme == 'udp':
                port = 80  # default placeholder
            else:
                # no scheme: treat as unknown, but use 0
                port = 0

        return f"{scheme}://{hostname}:{port}"
    except Exception:
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

async def filter_bad_trackers(trackers, bad_domains, session):
    """Filter trackers by bad domains and blocklisted IPs, and remove duplicates"""
    # Remove duplicates first (as requested)
    trackers = remove_duplicate_trackers(trackers)

    if not bad_domains and not BAD_NETWORKS:
        return trackers

    filtered = []
    seen_keys = set()
    semaphore = asyncio.Semaphore(20)

    async def check_tracker(tracker):
        try:
            key = get_tracker_key(tracker)
            if key in seen_keys:
                return None
            seen_keys.add(key)

            parsed = urlparse(tracker)
            hostname = parsed.hostname
            if not hostname:
                # If no hostname, keep it (will be attempted later)
                return tracker

            if hostname.lower() in bad_domains:
                print(f"Skipping bad domain: {tracker}")
                return None

            async with semaphore:
                try:
                    addrs = await asyncio.get_event_loop().getaddrinfo(
                        hostname, None, family=socket.AF_UNSPEC
                    )
                    tracker_ips = {addr[4][0] for addr in addrs}
                    for ip in tracker_ips:
                        if ip_in_blocklist(ip):
                            print(f"Skipping tracker {tracker} (IP {ip} in blocklist)")
                            return None
                except Exception as e:
                    # DNS lookup failed - keep tracker (temporary DNS)
                    print(f"DNS lookup failed for {hostname}: {e}")
            return tracker
        except Exception as e:
            print(f"Error checking tracker {tracker}: {e}")
            return tracker

    tasks = [check_tracker(t) for t in trackers]
    results = await asyncio.gather(*tasks)
    filtered = [r for r in results if r is not None]
    print(f"Filtered trackers count: {len(trackers)} -> {len(filtered)} after bad-domain/blocklist checks")
    return filtered

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
        if isinstance(peers_bin, list) or isinstance(peers6_bin, list):
            items = peers_bin if isinstance(peers_bin, list) else []
            for peer in items:
                if isinstance(peer, dict):
                    ip_bytes = peer.get(b'ip')
                    port = peer.get(b'port', 0)
                    if ip_bytes:
                        if isinstance(ip_bytes, bytes):
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

        addrinfo = await asyncio.get_event_loop().getaddrinfo(
            hostname, port, family=socket.AF_UNSPEC, type=socket.SOCK_DGRAM
        )
        if not addrinfo:
            return tracker, "ERROR", "dns_resolution_failed", 0, 0, [], round(time.time()-start,2), []

        family, socktype, proto, canonname, sockaddr = addrinfo[0]

        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        transaction_id = random.randint(0, 0x7FFFFFFF)
        protocol_id = 0x41727101980  # Magic constant
        connect_request = struct.pack("!QII", protocol_id, 0, transaction_id)

        sock.sendto(connect_request, sockaddr)
        connect_response = sock.recv(16)
        if len(connect_response) < 16:
            return tracker, "ERROR", "udp_connect_response_too_short", 0, 0, [], round(time.time()-start,2), []

        action, recv_transaction_id, connection_id = struct.unpack("!IIQ", connect_response)
        if action != 0 or recv_transaction_id != transaction_id:
            return tracker, "ERROR", "udp_connect_failed", 0, 0, [], round(time.time()-start,2), []

        peer_id = '-PC0001-' + ''.join(random.choices(string.ascii_letters + string.digits, k=12))
        peer_id_bytes = peer_id.encode('ascii')

        downloaded = 0
        left = 0
        uploaded = 0
        event = 2  # started
        ip = 0
        key = random.randint(0, 0x7FFFFFFF)
        num_want = -1
        announce_port = 6881

        # Note: pack info_hash and peer_id carefully, info_hash must be 20 bytes
        announce_request = struct.pack("!QII20s20sQQQIIIiH",
            connection_id,
            1,
            transaction_id,
            info_hash,
            peer_id_bytes,
            downloaded,
            left,
            uploaded,
            event,
            ip,
            key,
            num_want,
            announce_port
        )

        sock.sendto(announce_request, sockaddr)
        announce_response = sock.recv(4096)
        if len(announce_response) < 20:
            return tracker, "ERROR", "udp_announce_response_too_short", 0, 0, [], round(time.time()-start,2), []

        action_resp, transaction_id_resp, interval, leechers, seeders = struct.unpack("!IIIII", announce_response[:20])
        if action_resp != 1 or transaction_id_resp != transaction_id:
            return tracker, "ERROR", "udp_announce_failed", 0, 0, [], round(time.time()-start,2), []

        peers_data = announce_response[20:]
        peers = []
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
# Announce request (HTTP and UDP) with improved HTTP/HTTPS handling & redirects
# -----------------------
async def announce_tracker(session, tracker, info_hash):
    """Announce to tracker (HTTP/HTTPS/UDP). If tracker has no scheme, try https then http."""
    parsed = urlparse(tracker)

    # Handle UDP trackers quickly (explicit scheme)
    if parsed.scheme == "udp":
        return await announce_udp_tracker(tracker, info_hash)

    # If scheme is missing, try https first then http
    schemes_to_try = []
    if parsed.scheme in ("http", "https"):
        schemes_to_try = [parsed.scheme]
    elif parsed.scheme == "":
        schemes_to_try = ["https", "http"]
    else:
        return tracker, "ERROR", "unsupported_scheme", 0, 0, [], 0, []

    start = time.time()
    last_error = None

    for scheme in schemes_to_try:
        # Build base tracker url with scheme
        if parsed.scheme:
            base_url = tracker
        else:
            base_url = f"{scheme}://{tracker}"

        try:
            # prepare params
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
            url = base_url + ("&" if "?" in base_url else "?") + "&".join(query_parts)

            timeout = aiohttp.ClientTimeout(total=15)
            # follow redirects; capture final URL
            async with session.get(url, timeout=timeout, allow_redirects=True) as resp:
                final_url = str(resp.url)
                data = await resp.read()
                if resp.status != 200:
                    last_error = f"http_status_{resp.status}"
                    # If status indicates possible redirect to https handled earlier by allow_redirects
                    print(f"{base_url} -> HTTP {resp.status}, tried scheme {scheme}")
                    continue
                try:
                    info = bencodepy.decode(data)
                except Exception as e:
                    last_error = f"bdecode_error: {str(e)}"
                    continue
                seeders = int(info.get(b"complete", 0))
                leechers = int(info.get(b"incomplete", 0))
                peers = parse_peers_from_response(info)
                # return final_url so results show actual endpoint after redirects
                return final_url, "OK", "", seeders, leechers, peers, round(time.time()-start,2), peers
        except asyncio.TimeoutError:
            last_error = "timeout"
            print(f"Timeout querying {base_url}")
            continue
        except (ConnectionResetError, aiohttp.ClientError, OSError) as e:
            last_error = f"conn_error: {e}"
            print(f"Connection error querying {base_url}: {e}")
            continue
        except Exception as e:
            last_error = str(e)
            print(f"Error querying {base_url}: {e}")
            continue

    # If we reach here - all attempts failed
    return tracker, "ERROR", last_error or "unknown_error", 0, 0, [], round(time.time()-start,2), []

# -----------------------
# Handshake check
# -----------------------
def is_bittorrent_peer(ip, port, info_hash, timeout=3):
    try:
        if ':' in ip:  # IPv6
            family = socket.AF_INET6
        else:
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
# Bad IP heuristics (unchanged logic)
# -----------------------
def is_bad_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved:
            return True
        if addr.version == 4:
            if ipaddress.IPv4Address('100.64.0.0') <= addr <= ipaddress.IPv4Address('100.127.255.255'):
                return True
            if ipaddress.IPv4Address('0.0.0.0') <= addr <= ipaddress.IPv4Address('0.255.255.255'):
                return True
            if ipaddress.IPv4Address('169.254.0.0') <= addr <= ipaddress.IPv4Address('169.254.255.255'):
                return True
            if ipaddress.IPv4Address('192.0.0.0') <= addr <= ipaddress.IPv4Address('192.0.0.255'):
                return True
            if ipaddress.IPv4Address('192.0.2.0') <= addr <= ipaddress.IPv4Address('192.0.2.255'):
                return True
            if ipaddress.IPv4Address('198.18.0.0') <= addr <= ipaddress.IPv4Address('198.19.255.255'):
                return True
            if ipaddress.IPv4Address('198.51.100.0') <= addr <= ipaddress.IPv4Address('198.51.100.255'):
                return True
            if ipaddress.IPv4Address('203.0.113.0') <= addr <= ipaddress.IPv4Address('203.0.113.255'):
                return True
            if ipaddress.IPv4Address('104.28.198.0') <= addr <= ipaddress.IPv4Address('104.28.198.255'):
                return True
            if ipaddress.IPv4Address('172.71.184.0') <= addr <= ipaddress.IPv4Address('172.71.184.255'):
                return True
        if addr.version == 6:
            if addr.ipv4_mapped is not None:
                return True
            if hasattr(addr, 'is_ipv4_compatible') and addr.is_ipv4_compatible:
                return True
            if addr.is_private:
                return True
            if ipaddress.IPv6Address('2001:db8::') <= addr <= ipaddress.IPv6Address('2001:db8:ffff:ffff:ffff:ffff:ffff:ffff'):
                return True
            if ipaddress.IPv6Address('2002::') <= addr <= ipaddress.IPv6Address('2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff'):
                return True
            if ipaddress.IPv6Address('2001::') <= addr <= ipaddress.IPv6Address('2001:0:ffff:ffff:ffff:ffff:ffff:ffff'):
                return True
            if ipaddress.IPv6Address('2001:2::') <= addr <= ipaddress.IPv6Address('2001:2:0:ffff:ffff:ffff:ffff:ffff'):
                return True
            if ipaddress.IPv6Address('2001:10::') <= addr <= ipaddress.IPv6Address('2001:1f:ffff:ffff:ffff:ffff:ffff:ffff'):
                return True
            if ipaddress.IPv6Address('100::') <= addr <= ipaddress.IPv6Address('100::ffff:ffff:ffff:ffff'):
                return True
            if ipaddress.IPv6Address('2a09:bac5::') <= addr <= ipaddress.IPv6Address('2a09:bac5:ffff:ffff:ffff:ffff:ffff:ffff'):
                return True
            if ipaddress.IPv6Address('2a0a:e5c0::') <= addr <= ipaddress.IPv6Address('2a0a:e5c0:ffff:ffff:ffff:ffff:ffff:ffff'):
                return True
        if ip_in_blocklist(ip):
            return True
        return False
    except Exception:
        return True

def is_bad_external_ip_peer(ip, port, external_ipv4, external_ipv6_networks):
    if ip == external_ipv4 and port == 6881:
        return True
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version == 6:
            for network in external_ipv6_networks:
                if ip_obj in network and port == 6881:
                    return True
    except Exception:
        pass
    return False

def is_good_external_ip_peer(ip, port, external_ipv4, external_ipv6_networks):
    if ip == external_ipv4 and port != 6881:
        return True
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version == 6:
            for network in external_ipv6_networks:
                if ip_obj in network and port != 6881:
                    return True
    except Exception:
        pass
    return False

def is_our_external_ip(ip, external_ipv4, external_ipv6_networks):
    if ip == external_ipv4:
        return True
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
# Peer consistency & suspicious detection (unchanged)
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
# Saving results (per-infohash with timestamp)
# -----------------------
def save_additional_files(results, base_path, common_ips, external_ipv4, external_ipv6_networks, bad_flag=False):
    work_trackers = []
    good_trackers = []

    for r in results:
        if r["status"] != "OK":
            continue

        all_peers = r["all_peer_ips"] or []

        has_any_bad_ips = any(is_bad_ip(ip) for ip, port in all_peers)
        has_bad_external_ip = any(is_bad_external_ip_peer(ip, port, external_ipv4, external_ipv6_networks) for ip, port in all_peers)

        bad_ip_types = set()
        for ip, port in all_peers:
            if is_bad_ip(ip):
                bad_ip_types.add("other_bad")
            if is_bad_external_ip_peer(ip, port, external_ipv4, external_ipv6_networks):
                bad_ip_types.add("myip_6881")

        if bad_flag:
            has_only_myip_6881_as_bad = (bad_ip_types == {"myip_6881"}) or (bad_ip_types == set())
            has_other_bad_ips = "other_bad" in bad_ip_types

            if not has_other_bad_ips:
                work_trackers.append(r["tracker"])

            good_peer_found = False
            for ip, port in all_peers:
                if not is_bad_ip(ip):
                    good_peer_found = True
                    break
            if good_peer_found and not has_other_bad_ips:
                good_trackers.append(r["tracker"])
        else:
            has_no_bad_ips_at_all = len(bad_ip_types) == 0

            if has_no_bad_ips_at_all:
                work_trackers.append(r["tracker"])

            good_peer_found = False
            for ip, port in all_peers:
                if not is_bad_ip(ip) and not is_our_external_ip(ip, external_ipv4, external_ipv6_networks):
                    good_peer_found = True
                    break
            if good_peer_found and has_no_bad_ips_at_all:
                good_trackers.append(r["tracker"])

    work_trackers = remove_duplicate_trackers(work_trackers)
    good_trackers = remove_duplicate_trackers(good_trackers)

    with open(f"{base_path}_WORK.txt", "w", encoding="utf-8") as f:
        for t in work_trackers:
            f.write(f"{t}\n\n")
    print(f"Saved {len(work_trackers)} work trackers to {base_path}_WORK.txt")

    with open(f"{base_path}_GOOD.txt", "w", encoding="utf-8") as f:
        for t in good_trackers:
            f.write(f"{t}\n\n")
    print(f"Saved {len(good_trackers)} good trackers to {base_path}_GOOD.txt")

    return work_trackers, good_trackers

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

    http_trackers = len([r for r in results if r['tracker'].startswith(('http:', 'https:'))])
    udp_trackers = len([r for r in results if r['tracker'].startswith('udp:')])
    successful_http = len([r for r in results if r['status'] == 'OK' and r['tracker'].startswith(('http:', 'https:'))])
    successful_udp = len([r for r in results if r['status'] == 'OK' and r['tracker'].startswith('udp:')])

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

    work_new = 0
    good_new = 0
    bad_external_ip_count = 0
    good_external_ip_count = 0

    for r in results:
        if r["status"] != "OK":
            continue
        peers = r["all_peer_ips"] or []
        has_bad_external_ip = any(is_bad_external_ip_peer(ip, port, external_ipv4, external_ipv6_networks) for ip, port in peers)
        has_other_bad_ips = any(is_bad_ip(ip) for ip, port in peers)
        has_good_external_ip = any(is_good_external_ip_peer(ip, port, external_ipv4, external_ipv6_networks) for ip, port in peers)

        if has_bad_external_ip:
            bad_external_ip_count += 1
        if has_good_external_ip:
            good_external_ip_count += 1

        if bad_flag:
            if not has_other_bad_ips:
                work_new += 1
            good_peer_found = any(not is_bad_ip(ip) for ip, port in peers)
            if good_peer_found:
                good_new += 1
        else:
            if not has_bad_external_ip and not has_other_bad_ips:
                work_new += 1
            if any((not is_bad_ip(ip)) and not is_our_external_ip(ip, external_ipv4, external_ipv6_networks) for ip, _ in peers):
                good_new += 1

    stats.append("CRITERIA SUMMARY:")
    if bad_flag:
        stats.append("WORK trackers (no other bad IPs, our external IP with port 6881 allowed):")
        stats.append("GOOD trackers (have at least one non-bogon IP, our external IP allowed):")
    else:
        stats.append("WORK trackers (no bad external IP 6881, no other bad IPs):")
        stats.append("GOOD trackers (have at least one non-bogon non-external IP):")

    stats.append(f"Work trackers: {work_new}")
    stats.append(f"Good trackers: {good_new}")
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
# Load trackers from default file + external sources, dedupe BEFORE checks
# -----------------------
def load_trackers_combined(trackers_file, external_lines):
    trackers = []
    # load base trackers file if exists
    if os.path.exists(trackers_file):
        with open(trackers_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    trackers.append(line)
    # add external lines
    if external_lines:
        for l in external_lines:
            l = l.strip()
            if l and not l.startswith('#'):
                trackers.append(l)
    # Normalize and remove duplicates
    # Some lines may be plain hostnames, ensure they look like a URL (we handle missing scheme later)
    trackers = [t for t in trackers if t]
    unique = []
    seen = set()
    for t in trackers:
        key = get_tracker_key(t)
        if key not in seen:
            seen.add(key)
            unique.append(t)
    print(f"Loaded combined trackers: {len(trackers)} lines -> {len(unique)} unique")
    return unique

# -----------------------
# Infohash utils (unchanged)
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
# Top-level runner for a single infohash (performs downloads, filtering, checking, saving)
# -----------------------
async def run_check_for_infohash(infohash_bytes, args, external_tracker_lines=None):
    # timestamped base names
    hexhash = hex_infohash(infohash_bytes)
    ts = now_timestamp_str()
    base_outname = f"trackers_check_{hexhash}_{ts}"
    csv_out = f"{base_outname}.csv"

    # load blocklist
    print("Loading blocklist...")
    await load_iblocklist()

    bad_domains = load_bad_trackers()
    # combine trackers.txt + external sources
    combined_trackers = load_trackers_combined(args.trackers, external_tracker_lines or [])

    # parse infohash
    info_hash = infohash_bytes

    results = []
    queue = asyncio.Queue()

    # aiohttp session for HTTP trackers
    connector = aiohttp.TCPConnector(limit=args.concurrency, limit_per_host=2, ssl=False)
    session_timeout = aiohttp.ClientTimeout(total=30, connect=10, sock_read=10)

    async with aiohttp.ClientSession(connector=connector, timeout=session_timeout) as session:
        # detect external IPs
        print("Detecting external IPs...")
        external_ipv4, external_ipv6_networks = await get_external_ips(session)
        print(f"Using external IPv4: {external_ipv4}")
        print(f"Using external IPv6 networks (/64): {len(external_ipv6_networks)}")
        for network in external_ipv6_networks:
            print(f"  - {network}")

        # Filter trackers (domains + IP blocklist + duplicates)
        print("Filtering trackers (bad domains / blocklists / duplicates)...")
        trackers_filtered = await filter_bad_trackers(combined_trackers, bad_domains, session)

        # Put trackers into queue
        for tr in trackers_filtered:
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

    # Write CSV
    with open(csv_out, "w", newline="", encoding="utf-8") as fo:
        writer = csv.DictWriter(fo, fieldnames=[
            "tracker", "status", "error", "seeders", "leechers",
            "total_peers", "bad_peers", "handshake_ok", "good_peers_count", "time_s"
        ])
        writer.writeheader()
        for r in results:
            row = {k: v for k, v in r.items() if k not in ["good_peer_ips", "verified_peer_ips", "all_peer_ips"]}
            writer.writerow(row)
    print(f"Main results saved to {csv_out}")

    base_path = base_outname
    save_additional_files(results, base_path, common_ips, external_ipv4, external_ipv6_networks, args.bad)
    save_detailed_ip_files(results, base_path, common_ips, external_ipv4, external_ipv6_networks)
    save_statistics(results, base_path, external_ipv4, external_ipv6_networks, common_ips, args.bad)

    # short summary to console
    print(f"Total trackers checked: {len(results)}")
    unique_tracker_keys = set(get_tracker_key(r['tracker']) for r in results)
    print(f"Unique trackers (by protocol-domain-port): {len(unique_tracker_keys)}")
    successful = len([r for r in results if r['status'] == 'OK'])
    print(f"Successful: {successful}")
    print(f"Output files prefix: {base_outname}")

    return base_outname, csv_out

# -----------------------
# Main async (handles multiple magnets if requested)
# -----------------------
async def main_async(args):
    # Download external tracker sources (with caching) first
    print("Loading external tracker sources (with cache)...")
    try:
        external_lines = await download_all_tracker_sources()
    except Exception as e:
        print(f"Failed to download external tracker sources: {e}")
        external_lines = []

    # Determine infohashes to check:
    infohash_list = []

    if args.infohash == "":
        # read magnets file
        if not os.path.exists(args.magnet):
            raise SystemExit(f"Magnet file {args.magnet} not found")
        with open(args.magnet, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                try:
                    ih = parse_infohash(line)
                    infohash_list.append(ih)
                except Exception as e:
                    print(f"Skipping invalid magnet line: {line} - {e}")
    else:
        # single infohash or magnet provided on CLI
        try:
            ih = parse_infohash(args.infohash)
            infohash_list.append(ih)
        except Exception as e:
            raise SystemExit(f"Invalid --infohash: {e}")

    if not infohash_list:
        raise SystemExit("No valid infohashes to process")

    # Process each infohash sequentially (user requested sequential checking)
    for infohash_bytes in infohash_list:
        try:
            print(f"\n=== Starting check for {hex_infohash(infohash_bytes)} ===")
            prefix, csvfile = await run_check_for_infohash(infohash_bytes, args, external_tracker_lines=external_lines)
            print(f"Finished {hex_infohash(infohash_bytes)} -> outputs prefix {prefix}")
        except Exception as e:
            print(f"Error while processing {hex_infohash(infohash_bytes)}: {e}")
            continue

# -----------------------
# CLI
# -----------------------
def main():
    parser = argparse.ArgumentParser(description="Проверка HTTP(S)/UDP трекеров на fake/bogon сиды/пиры с загрузкой внешних списков, кэшированием и поддержкой нескольких magnet ссылок")
    parser.add_argument("--trackers", default="trackers.txt", help="Файл со списком трекеров (обязательно включается)")
    parser.add_argument("--concurrency", type=int, default=4, help="Максимум одновременных запросов")
    parser.add_argument("--infohash", required=True, help="Magnet или hex/base32 infohash. Если пустая строка --infohash \"\" - используем файл --magnet")
    parser.add_argument("--magnet", default="trackers_magnet.txt", help="Файл с magnet-ссылками (только если --infohash \"\")")
    parser.add_argument("--out", default="trackers_check.csv", help="(не используется когда проверяем несколько) Базовый CSV файл для вывода (опционально)")
    parser.add_argument("--max-handshakes", type=int, default=5, help="Максимум проверок handshake на трекер")
    parser.add_argument("--bad", action="store_true", help="Включить трекеры с нашим внешним IP (даже с портом 6881) в WORK и GOOD файлы")
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
