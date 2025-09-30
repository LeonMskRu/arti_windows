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
from urllib.parse import urlparse, parse_qs, quote, quote_from_bytes
import bencodepy
import binascii
import base64
import os

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
# Enhanced Bogon check
# -----------------------
def is_bad_ip(ip):
    """
    Проверяет, является ли IP плохим (bogon/private/lan/cgnat/etc)
    """
    try:
        addr = ipaddress.ip_address(ip)
        
        # Private ranges (RFC 1918)
        if addr.is_private:
            return True
            
        # Loopback
        if addr.is_loopback:
            return True
            
        # Link-local
        if addr.is_link_local:
            return True
            
        # Multicast
        if addr.is_multicast:
            return True
            
        # Reserved
        if addr.is_reserved:
            return True
            
        # Carrier-grade NAT (CGNAT) - 100.64.0.0/10
        if addr.version == 4:
            ip_int = int(addr)
            # 100.64.0.0/10
            if (ip_int >= 0x6440000000 and ip_int <= 0x647FFFFFFF):
                return True
            # 0.0.0.0/8
            if (ip_int >= 0x0000000000 and ip_int <= 0x00FFFFFFF):
                return True
            # 169.254.0.0/16 (APIPA)
            if (ip_int >= 0xA9FE000000 and ip_int <= 0xA9FEFFFFFF):
                return True
            # 192.0.0.0/24 (IETF Protocol Assignments)
            if (ip_int >= 0xC000000000 and ip_int <= 0xC00000FFFF):
                return True
            # 192.0.2.0/24 (TEST-NET-1)
            if (ip_int >= 0xC000020000 and ip_int <= 0xC00002FFFF):
                return True
            # 198.18.0.0/15 (Network Benchmark Tests)
            if (ip_int >= 0xC612000000 and ip_int <= 0xC613FFFFFF):
                return True
            # 198.51.100.0/24 (TEST-NET-2)
            if (ip_int >= 0xC633640000 and ip_int <= 0xC63364FFFF):
                return True
            # 203.0.113.0/24 (TEST-NET-3)
            if (ip_int >= 0xCB00710000 and ip_int <= 0xCB0071FFFF):
                return True
            
        # IPv6 unique local (fc00::/7)
        if addr.version == 6 and (addr >= ipaddress.IPv6Address('fc00::') and 
                                 addr <= ipaddress.IPv6Address('fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')):
            return True
            
        return False
        
    except Exception:
        return True

# -----------------------
# Handshake check with error handling
# -----------------------
def is_bittorrent_peer(ip, port, info_hash, timeout=3):
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)
        pstr = b"BitTorrent protocol"
        pstrlen = bytes([len(pstr)])
        reserved = b"\x00" * 8
        peer_id = "-PC0001-" + ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(12))
        peer_id = peer_id.encode("ascii")
        handshake = pstrlen + pstr + reserved + info_hash + peer_id
        s.sendall(handshake)
        resp = s.recv(68)
        s.close()
        return len(resp) >= 68 and resp[1:20] == b"BitTorrent protocol"
    except Exception as e:
        # Игнорируем ошибки соединения - это нормально
        return False

# -----------------------
# Load trackers
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
# Enhanced peer parsing with better error handling
# -----------------------
def parse_peers_from_response(info):
    """
    Извлекает список пиров из ответа трекера
    Возвращает список кортежей (ip, port)
    """
    peers = []
    
    try:
        peers_bin = info.get(b"peers", b"")
        
        # Compact format (binary)
        if isinstance(peers_bin, bytes) and len(peers_bin) % 6 == 0:
            for i in range(0, len(peers_bin), 6):
                ip_bytes = peers_bin[i:i+4]
                port_bytes = peers_bin[i+4:i+6]
                ip = ".".join(str(b) for b in ip_bytes)
                port = struct.unpack(">H", port_bytes)[0]
                peers.append((ip, port))
                
        # Dictionary format
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
# Announce request with improved peer handling
# -----------------------
async def announce_tracker(session, tracker, info_hash):
    parsed = urlparse(tracker)
    if parsed.scheme not in ("http", "https"):
        return tracker, "ERROR", "unsupported_scheme", 0, 0, [], 0, []
    
    start = time.time()
    try:
        # Формируем параметры запроса
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
        
        # Правильно кодируем параметры
        query_parts = []
        for key, value in params.items():
            if key == "info_hash":
                encoded_value = quote_from_bytes(value)
            else:
                encoded_value = quote(str(value))
            query_parts.append(f"{key}={encoded_value}")
        
        url = tracker + ("&" if "?" in tracker else "?") + "&".join(query_parts)
        
        timeout = aiohttp.ClientTimeout(total=15)
        async with session.get(url, timeout=timeout) as resp:
            data = await resp.read()
            if resp.status != 200:
                return tracker, "ERROR", f"http_status_{resp.status}", 0, 0, [], round(time.time()-start,2), []
            
            # Декодируем ответ
            try:
                info = bencodepy.decode(data)
            except Exception as e:
                return tracker, "ERROR", f"bdecode_error: {str(e)}", 0, 0, [], round(time.time()-start,2), []
            
            # Извлекаем данные
            seeders = int(info.get(b"complete", 0))
            leechers = int(info.get(b"incomplete", 0))
            
            # Парсим пиров
            peers = parse_peers_from_response(info)
            
            return tracker, "OK", "", seeders, leechers, peers, round(time.time()-start,2), peers
            
    except asyncio.TimeoutError:
        return tracker, "ERROR", "timeout", 0, 0, [], round(time.time()-start,2), []
    except Exception as e:
        return tracker, "ERROR", str(e), 0, 0, [], round(time.time()-start,2), []

# -----------------------
# Worker with enhanced IP filtering
# -----------------------
async def worker(name, queue, session, info_hash, results, max_handshake_checks=10):
    while True:
        tracker = await queue.get()
        if tracker is None:
            queue.task_done()
            break
        
        # Выполняем announce
        result = await announce_tracker(session, tracker, info_hash)
        t, status, err, seeders, leechers, peers, dt, peer_ips = result
        
        # Проверяем пиров
        bad_ip_count = 0
        handshake_ok = 0
        checked_peers = 0
        good_peers = []  # Храним хорошие IP
        
        # Сначала считаем плохие IP
        bad_ips = []
        good_ips = []
        
        for ip, port in peer_ips:
            if is_bad_ip(ip):
                bad_ip_count += 1
                bad_ips.append((ip, port))
            else:
                good_ips.append((ip, port))
        
        # Проверяем handshake только для хороших IP (ограниченное количество)
        for ip, port in good_ips:
            if checked_peers >= max_handshake_checks:
                break
                
            if is_bittorrent_peer(ip, port, info_hash):
                handshake_ok += 1
                good_peers.append((ip, port))
            checked_peers += 1
        
        # Для GOOD трекеров считаем все хорошие IP, даже если не проверяли handshake
        all_good_ips = good_ips  # Все не-bad IP считаются хорошими для целей GOOD.txt
        
        results.append({
            "tracker": t,
            "status": status,
            "error": err,
            "seeders": seeders,
            "leechers": leechers,
            "total_peers": len(peer_ips),
            "bad_peers": bad_ip_count,
            "handshake_ok": handshake_ok,
            "good_peers_count": len(all_good_ips),  # Все не-bad IP
            "good_peer_ips": all_good_ips,  # Все не-bad IP (для GOOD.txt)
            "verified_peer_ips": good_peers,  # Только проверенные handshake (для отладки)
            "all_peer_ips": peer_ips,     # Все IP (для отладки)
            "time_s": dt
        })
        
        good_info = f" - {len(all_good_ips)} good IPs" if all_good_ips else ""
        print(f"Checked: {t} - {status} ({seeders} seeders, {leechers} leechers{good_info})")
        queue.task_done()

# -----------------------
# Enhanced file saving functions
# -----------------------
def save_additional_files(results, base_path):
    """Сохраняет дополнительные файлы с трекерами"""
    
    # 1. trackers_WORK.txt - все рабочие с хотя бы одним пиром или сидом
    work_trackers = [
        r["tracker"] for r in results 
        if r["status"] == "OK" and (r["seeders"] > 0 or r["leechers"] > 0 or r["total_peers"] > 0)
    ]
    with open(f"{base_path}_WORK.txt", "w", encoding="utf-8") as f:
        for tracker in work_trackers:
            f.write(f"{tracker}\n\n")  # Пустая строка между трекерами
    print(f"Saved {len(work_trackers)} work trackers to {base_path}_WORK.txt")
    
    # 2. trackers_GOOD.txt - рабочие трекеры с хотя бы одним хорошим IP
    good_trackers = [
        r["tracker"] for r in results 
        if r["status"] == "OK" and r["good_peers_count"] > 0
    ]
    with open(f"{base_path}_GOOD.txt", "w", encoding="utf-8") as f:
        for tracker in good_trackers:
            f.write(f"{tracker}\n\n")  # Пустая строка между трекерами
    print(f"Saved {len(good_trackers)} good trackers to {base_path}_GOOD.txt")
    
    return work_trackers, good_trackers

def save_detailed_ip_files(results, base_path):
    """Сохраняет файлы с IP-адресами"""
    
    # 1. trackers_IP.txt - все IP (включая плохие) для отладки
    all_ip_data = []
    for result in results:
        if result["status"] == "OK" and result["all_peer_ips"]:
            tracker_name = urlparse(result["tracker"]).netloc.replace(':', '_')
            
            all_ip_data.append(f"# {result['tracker']}")
            all_ip_data.append(f"# Seeders: {result['seeders']}, Leechers: {result['leechers']}, Total peers: {result['total_peers']}")
            
            for ip, port in result["all_peer_ips"]:
                ip_type = "bad" if is_bad_ip(ip) else "good"
                peer_type = "seed" if result["seeders"] > 0 else "peer"
                all_ip_data.append(f"{tracker_name} {peer_type} {ip}:{port} # {ip_type}")
            
            all_ip_data.append("")  # Пустая строка между трекерами
    
    if all_ip_data:
        with open(f"{base_path}_IP.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(all_ip_data))
        print(f"Saved all IP data to {base_path}_IP.txt")
    
    # 2. trackers_GOOD_IP.txt - только хорошие IP
    good_ip_data = []
    for result in results:
        if result["status"] == "OK" and result["good_peer_ips"]:
            tracker_name = urlparse(result["tracker"]).netloc.replace(':', '_')
            
            good_ip_data.append(f"# {result['tracker']}")
            good_ip_data.append(f"# Seeders: {result['seeders']}, Leechers: {result['leechers']}, Good peers: {len(result['good_peer_ips'])}")
            
            for ip, port in result["good_peer_ips"]:
                peer_type = "seed" if result["seeders"] > 0 else "peer"
                good_ip_data.append(f"{tracker_name} {peer_type} {ip}:{port}")
            
            good_ip_data.append("")  # Пустая строка между трекерами
    
    if good_ip_data:
        with open(f"{base_path}_GOOD_IP.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(good_ip_data))
        print(f"Saved good IP data to {base_path}_GOOD_IP.txt")

def save_statistics(results, base_path):
    """Сохраняет статистику"""
    stats = []
    stats.append("Tracker Statistics")
    stats.append("=" * 50)
    
    total = len(results)
    successful = len([r for r in results if r['status'] == 'OK'])
    work_trackers = len([r for r in results if r['status'] == 'OK' and (r['seeders'] > 0 or r['leechers'] > 0 or r['total_peers'] > 0)])
    good_trackers = len([r for r in results if r['status'] == 'OK' and r['good_peers_count'] > 0])
    
    stats.append(f"Total trackers checked: {total}")
    stats.append(f"Successful responses: {successful}")
    stats.append(f"Work trackers (with peers/seeds): {work_trackers}")
    stats.append(f"Good trackers (with good IPs): {good_trackers}")
    stats.append("")
    
    # Статистика по IP
    total_ips = sum(len(r["all_peer_ips"]) for r in results if r["status"] == "OK")
    good_ips = sum(len(r["good_peer_ips"]) for r in results if r["status"] == "OK")
    verified_ips = sum(len(r["verified_peer_ips"]) for r in results if r["status"] == "OK")
    
    stats.append(f"Total IPs found: {total_ips}")
    stats.append(f"Good IPs (non-bogon): {good_ips}")
    stats.append(f"Verified IPs (handshake ok): {verified_ips}")
    stats.append(f"Bad IPs (bogon/private): {total_ips - good_ips}")
    
    with open(f"{base_path}_STATS.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(stats))
    print(f"Saved statistics to {base_path}_STATS.txt")

# -----------------------
# Main async with error handling
# -----------------------
async def main_async(args):
    trackers = load_trackers(args.trackers)
    info_hash = parse_infohash(args.infohash)
    results = []
    queue = asyncio.Queue()
    
    for tr in trackers:
        queue.put_nowait(tr)
    
    # Устанавливаем ограничение на количество одновременных соединений
    connector = aiohttp.TCPConnector(limit=args.concurrency, limit_per_host=2, ssl=False)
    
    # Добавляем обработку ошибок соединения
    session_timeout = aiohttp.ClientTimeout(total=30, connect=10, sock_read=10)
    
    async with aiohttp.ClientSession(connector=connector, timeout=session_timeout) as session:
        workers = [
            asyncio.create_task(
                worker(f"W{i}", queue, session, info_hash, results, args.max_handshakes)
            ) 
            for i in range(args.concurrency)
        ]
        
        await queue.join()
        
        for _ in workers:
            queue.put_nowait(None)
        await asyncio.gather(*workers, return_exceptions=True)  # Игнорируем исключения в воркерах
    
    # Сохраняем CSV
    with open(args.out, "w", newline="", encoding="utf-8") as fo:
        writer = csv.DictWriter(fo, fieldnames=[
            "tracker", "status", "error", "seeders", "leechers", 
            "total_peers", "bad_peers", "handshake_ok", "good_peers_count", "time_s"
        ])
        writer.writeheader()
        for r in results:
            # Сохраняем только основные поля в CSV
            row = {k: v for k, v in r.items() if k not in ["good_peer_ips", "verified_peer_ips", "all_peer_ips"]}
            writer.writerow(row)
    
    # Сохраняем дополнительные файлы
    base_path = os.path.splitext(args.out)[0]
    save_additional_files(results, base_path)
    save_detailed_ip_files(results, base_path)
    save_statistics(results, base_path)
    
    print(f"\nMain results saved to {args.out}")
    print(f"Total trackers checked: {len(results)}")
    successful = len([r for r in results if r['status'] == 'OK'])
    print(f"Successful: {successful}")

# -----------------------
# CLI
# -----------------------
def main():
    parser = argparse.ArgumentParser(description="Проверка HTTP(S) трекеров на fake/bogon сиды/пиры")
    parser.add_argument("--trackers", default="trackers.txt", help="Файл со списком трекеров")
    parser.add_argument("--concurrency", type=int, default=4, help="Максимум одновременных запросов")
    parser.add_argument("--infohash", required=True, help="Magnet или hex/base32 infohash")
    parser.add_argument("--out", default="trackers_check.csv", help="CSV файл для вывода")
    parser.add_argument("--max-handshakes", type=int, default=5, help="Максимум проверок handshake на трекер")
    args = parser.parse_args()
    
    # Настраиваем asyncio для обработки ошибок на Windows
    if os.name == 'nt':  # Windows
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\nПрервано пользователем")
    except Exception as e:
        print(f"Произошла ошибка: {e}")

if __name__ == "__main__":
    main()
    