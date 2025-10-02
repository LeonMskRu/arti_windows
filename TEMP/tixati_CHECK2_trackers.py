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
# Get external IP (uses provided session for direct request)
# -----------------------
async def get_external_ip(session):
    """Получает внешний IP через несколько сервисов, используя переданный session"""
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
            # Не прерываем цикл — пробуем следующий сервис
            print(f"Failed to get IP from {service}: {e}")
            continue
    raise Exception("Could not determine external IP from any service")

# -----------------------
# Filter trackers with bad domains
# -----------------------
def filter_bad_trackers(trackers, bad_domains):
    if not bad_domains:
        return trackers
    filtered = []
    for tracker in trackers:
        try:
            domain = urlparse(tracker).hostname
            if domain and domain.lower() not in bad_domains:
                filtered.append(tracker)
            else:
                print(f"Skipping bad tracker: {tracker}")
        except Exception:
            filtered.append(tracker)
    print(f"Filtered {len(trackers) - len(filtered)} bad trackers")
    return filtered

# -----------------------
# Peer consistency (still available but not required for new rules)
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
# Suspicious check (kept but not used as restrictive filter for new rules)
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
    has_external_ip = any(ip == external_ip for ip, port in result["all_peer_ips"])
    if not has_external_ip:
        # Это информационное сообщение — не делает трекер автоматически подозрительным
        print(f"Tracker {urlparse(result['tracker']).netloc}: external IP {external_ip} not found in peers")
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
        raise ValueError("Не могу найти infohash в magnet")
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
    raise ValueError("infohash должен быть 40 hex, base32 или magnet-ссылкой")

# -----------------------
# Improved bogon/private check
# -----------------------
def is_bad_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved:
            return True
        # Carrier-grade NAT 100.64.0.0/10
        if addr.version == 4:
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
        return False
    except Exception:
        # Если парсинг не удался — считать "плохим" для безопасного поведения
        return True

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
# Announce request (with safer exception handling)
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
        # Ловим типичные ошибки соединения и возвращаем понятный статус
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

        # Проверяем handshake на ограниченном числе "хороших" IP
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
# Save files with new logic for WORK and GOOD
# -----------------------
def save_additional_files(results, base_path, common_ips, external_ip):
    """
    NEW logic:
    - WORK: any tracker with status OK and NOT (only external IP returned) and no bad IPs present
      (trackers with zero peers but OK are included as WORK if no bad IPs)
    - GOOD: any tracker with status OK and at least one peer that is not-bogon and not external_ip
    """
    work_trackers = []
    good_trackers = []

    for r in results:
        if r["status"] != "OK":
            continue

        all_peers = r["all_peer_ips"] or []
        # detect if all peers are exactly the external IP (echo-only)
        if all_peers:
            peers_ips = [ip for ip, _ in all_peers]
            all_echo = all(ip == external_ip for ip in peers_ips)
        else:
            all_echo = False  # no peers => not "echo-only"

        # detect any bad IP present
        any_bad = any(is_bad_ip(ip) for ip, _ in all_peers)

        # WORK condition: status OK AND not echo-only AND no bad IPs
        if not all_echo and not any_bad:
            work_trackers.append(r["tracker"])

        # GOOD condition: status OK AND has at least one non-bogon non-external IP
        good_peer_found = False
        for ip, port in all_peers:
            if (not is_bad_ip(ip)) and ip != external_ip:
                good_peer_found = True
                break
        if good_peer_found:
            good_trackers.append(r["tracker"])

    # write files
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
# Save IP detail files (unchanged logic except small clarifications)
# -----------------------
def save_detailed_ip_files(results, base_path, common_ips, external_ip):
    all_ip_data = []
    for result in results:
        if result["status"] == "OK" and result["all_peer_ips"]:
            tracker_name = urlparse(result["tracker"]).netloc.replace(':', '_')
            suspicious = is_suspicious_tracker(result, common_ips, external_ip)
            has_external_ip = any(ip == external_ip for ip, port in result["all_peer_ips"])
            all_ip_data.append(f"# {result['tracker']}")
            all_ip_data.append(f"# Seeders: {result['seeders']}, Leechers: {result['leechers']}, Total peers: {result['total_peers']}")
            all_ip_data.append(f"# Suspicious: {suspicious}, Has external IP: {has_external_ip}")
            for ip, port in result["all_peer_ips"]:
                ip_type = "bad" if is_bad_ip(ip) else "good"
                peer_type = "seed" if result["seeders"] > 0 else "peer"
                is_external = " [EXTERNAL]" if ip == external_ip else ""
                all_ip_data.append(f"{tracker_name} {peer_type} {ip}:{port} # {ip_type}{is_external}")
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
            has_external_ip = any(ip == external_ip for ip, port in result["all_peer_ips"])
            good_ip_data.append(f"# {result['tracker']}")
            good_ip_data.append(f"# Seeders: {result['seeders']}, Leechers: {result['leechers']}, Good peers: {len(result['good_peer_ips'])}")
            good_ip_data.append(f"# Has external IP: {has_external_ip}")
            for ip, port in result["good_peer_ips"]:
                peer_type = "seed" if result["seeders"] > 0 else "peer"
                is_external = " [EXTERNAL]" if ip == external_ip else ""
                good_ip_data.append(f"{tracker_name} {peer_type} {ip}:{port}{is_external}")
            good_ip_data.append("")
    if good_ip_data:
        with open(f"{base_path}_GOOD_IP.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(good_ip_data))
        print(f"Saved good IP data to {base_path}_GOOD_IP.txt")

# -----------------------
# Save statistics (updated to new criteria)
# -----------------------
def save_statistics(results, base_path, external_ip, common_ips):
    stats = []
    stats.append("Tracker Statistics")
    stats.append("=" * 50)
    total = len(results)
    successful = len([r for r in results if r['status'] == 'OK'])

    # OLD criteria
    work_trackers_old = len([r for r in results if r['status'] == 'OK' and (r['seeders'] > 0 or r['leechers'] > 0 or r['total_peers'] > 0)])
    good_trackers_old = len([r for r in results if r['status'] == 'OK' and r['good_peers_count'] > 0])

    # NEW criteria using functions above (recompute quickly)
    base_path_temp = os.path.splitext(base_path)[0]  # unused but kept
    work_new = 0
    good_new = 0
    for r in results:
        if r["status"] != "OK":
            continue
        peers = r["all_peer_ips"] or []
        any_bad = any(is_bad_ip(ip) for ip, _ in peers)
        all_echo = bool(peers) and all(ip == external_ip for ip, _ in peers)
        if not all_echo and not any_bad:
            work_new += 1
        if any((not is_bad_ip(ip)) and ip != external_ip for ip, _ in peers):
            good_new += 1

    stats.append(f"Total trackers checked: {total}")
    stats.append(f"Successful responses: {successful}")
    stats.append("")
    stats.append("OLD CRITERIA (before filtering):")
    stats.append(f"Work trackers (with peers/seeds): {work_trackers_old}")
    stats.append(f"Good trackers (with good IPs): {good_trackers_old}")
    stats.append("")
    stats.append("NEW CRITERIA (after filtering):")
    stats.append(f"Work trackers (non-echo, no-bad-ip): {work_new}")
    stats.append(f"Good trackers (have at least one non-bogon non-external IP): {good_new}")
    stats.append("")

    total_ips = sum(len(r["all_peer_ips"]) for r in results if r["status"] == "OK")
    good_ips = sum(len(r["good_peer_ips"]) for r in results if r["status"] == "OK")
    verified_ips = sum(len(r["verified_peer_ips"]) for r in results if r["status"] == "OK")

    stats.append(f"Total IPs found: {total_ips}")
    stats.append(f"Good IPs (non-bogon): {good_ips}")
    stats.append(f"Verified IPs (handshake ok): {verified_ips}")
    stats.append(f"Bad IPs (bogon/private): {total_ips - good_ips}")
    stats.append("")
    stats.append(f"External IP: {external_ip}")
    trackers_with_external_ip = len([r for r in results if r["status"] == "OK" and any(ip == external_ip for ip, port in r["all_peer_ips"])])
    stats.append(f"Trackers with external IP: {trackers_with_external_ip}")
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
    bad_domains = load_bad_trackers()
    trackers = load_trackers(args.trackers)
    trackers = filter_bad_trackers(trackers, bad_domains)

    info_hash = parse_infohash(args.infohash)
    results = []
    queue = asyncio.Queue()
    for tr in trackers:
        queue.put_nowait(tr)

    connector = aiohttp.TCPConnector(limit=args.concurrency, limit_per_host=2, ssl=False)
    session_timeout = aiohttp.ClientTimeout(total=30, connect=10, sock_read=10)

    async with aiohttp.ClientSession(connector=connector, timeout=session_timeout) as session:
        print("Detecting external IP...")
        external_ip = await get_external_ip(session)
        print(f"Using external IP: {external_ip}")

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

# -----------------------
# CLI
# -----------------------
def main():
    parser = argparse.ArgumentParser(description="Проверка HTTP(S) трекеров на fake/bogon сиды/пиры с новой логикой WORK/GOOD")
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
