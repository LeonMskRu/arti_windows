#!/usr/bin/env python3
"""
dht_probe.py
Простой сканер DHT bootstrap-нод: отправляет Kademlia 'ping' (bencoded UDP) и ждёт ответа.
Python 3.8+. Без внешних зависимостей.

Usage:
    python dht_probe.py
Outputs:
    - печатает в консоль список отвечающих узлов (IP:port, RTT, краткий ответ)
    - сохраняет answers.csv с результатами
"""
import socket
import time
import random
import threading
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- Набор целей (по умолчанию). Можно добавить/удалить.
TARGETS = [
    ("dht.libtorrent.org", 25401),
    ("dht.transmissionbt.com", 6881),
    ("router.bittorrent.com", 6881),
    ("router.utorrent.com", 6881),
    ("router.bitcomet.com", 6881),
    ("dht.aelitis.com", 6881),
    # пример IP (на случай, если DNS блокируется — можно заменить/добавить свои)
    ("67.215.246.10", 6881),
    ("82.221.103.244", 6881),
]

PORTS_TO_TRY = [6881, 6881, 25401]  # порты для теста (если нужно доп. — расширь)
TIMEOUT = 3.0  # сек ожидания ответа
RETRIES = 2
WORKERS = 12

# --- Минимальный bencode (encode/decode) для нужд ping/response ---
def bencode(x):
    if isinstance(x, int):
        return b"i" + str(x).encode() + b"e"
    if isinstance(x, bytes):
        return str(len(x)).encode() + b":" + x
    if isinstance(x, str):
        b = x.encode()
        return str(len(b)).encode() + b":" + b
    if isinstance(x, list):
        return b"l" + b"".join(bencode(i) for i in x) + b"e"
    if isinstance(x, dict):
        # keys must be bytes or str, sort by key (as bytes)
        items = sorted(((k if isinstance(k, bytes) else k.encode(), v) for k, v in x.items()), key=lambda kv: kv[0])
        out = b"d"
        for k, v in items:
            out += bencode(k) + bencode(v)
        out += b"e"
        return out
    raise TypeError("Unsupported type for bencode: %r" % type(x))

def bdecode(data: bytes):
    # returns (obj, rest)
    def _decode(i):
        if data[i:i+1] == b"i":
            j = data.find(b"e", i)
            n = int(data[i+1:j].decode())
            return n, j+1
        if data[i:i+1] == b"l":
            i += 1
            lst = []
            while data[i:i+1] != b"e":
                val, i = _decode(i)
                lst.append(val)
            return lst, i+1
        if data[i:i+1] == b"d":
            i += 1
            d = {}
            while data[i:i+1] != b"e":
                key, i = _decode(i)
                val, i = _decode(i)
                d[key if isinstance(key, bytes) else key] = val
            return d, i+1
        # string: <len>:<data>
        colon = data.find(b":", i)
        l = int(data[i:colon].decode())
        start = colon + 1
        return data[start:start+l], start + l
    obj, pos = _decode(0)
    return obj

# --- Kademlia ping packet (bencoded) ---
def make_ping_tx():
    tx = ("%02x" % random.getrandbits(8)).encode()  # short transaction id
    # id должен быть 20 байт — используем случайный
    node_id = bytes(random.getrandbits(8) for _ in range(20))
    msg = {b"t": tx, b"y": b"q", b"q": b"ping", b"a": {b"id": node_id}}
    return bencode(msg), tx, node_id

def probe_target(host, port, timeout=TIMEOUT, retries=RETRIES):
    results = []
    try:
        # попытка разрешить DNS (если имя) — socket.getaddrinfo вернёт IPv4/IPv6
        addrs = socket.getaddrinfo(host, port, proto=socket.IPPROTO_UDP)
    except Exception as e:
        return {"host": host, "port": port, "ok": False, "error": f"DNS error: {e}"}

    # оставим только уникальные (addr, family)
    unique = []
    seen = set()
    for fam, socktype, proto, cname, sockaddr in addrs:
        key = (fam, sockaddr[0])
        if key in seen:
            continue
        seen.add(key)
        unique.append((fam, sockaddr))

    for fam, sockaddr in unique:
        target_ip = sockaddr[0]
        target_port = sockaddr[1] if len(sockaddr) > 1 else port
        addr_label = f"{target_ip}:{target_port}"
        for attempt in range(retries + 1):
            try:
                s = socket.socket(fam, socket.SOCK_DGRAM)
                s.settimeout(timeout)
                ping_pkt, txid, node_id = make_ping_tx()
                start = time.time()
                s.sendto(ping_pkt, (target_ip, target_port))
                data, src = s.recvfrom(4096)
                rtt = (time.time() - start) * 1000.0
                # пробуем декодировать
                try:
                    decoded = bdecode(data)
                except Exception as e:
                    decoded = None
                s.close()
                results.append({"addr": addr_label, "rtt_ms": round(rtt, 1), "decoded": decoded})
                break  # успешный ответ — не пробуем дальше
            except socket.timeout:
                if attempt == retries:
                    results.append({"addr": addr_label, "rtt_ms": None, "error": "timeout"})
                else:
                    continue
            except Exception as e:
                results.append({"addr": addr_label, "rtt_ms": None, "error": str(e)})
                break
    return {"host": host, "port": port, "ok": any(r.get("rtt_ms") for r in results), "results": results}

def main():
    print("DHT bootstrap probe — проверка списка нод (ping).")
    tasks = []
    all_targets = []
    # Расширяем цели: если указан хост без порта — попробуем стандартные порты
    for host, port in TARGETS:
        all_targets.append((host, port))

    answers = []
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futures = {ex.submit(probe_target, host, port): (host, port) for host, port in all_targets}
        for fut in as_completed(futures):
            host, port = futures[fut]
            try:
                res = fut.result()
            except Exception as e:
                res = {"host": host, "port": port, "ok": False, "error": str(e)}
            answers.append(res)
            # печать прогресса
            if res.get("ok"):
                print(f"[OK] {host}:{port}  — отвечает:")
                for r in res.get("results", []):
                    if r.get("rtt_ms") is not None:
                        print(f"     → {r['addr']}  RTT={r['rtt_ms']} ms")
                        # попытка показать краткий decoded info
                        dec = r.get("decoded")
                        if isinstance(dec, dict):
                            # показать, если присутствует 'y' или 'r'
                            y = dec.get(b"y", b"").decode() if dec.get(b"y") else ""
                            rfield = dec.get(b"r")
                            print(f"       resp_type={y}  r_keys={list(rfield.keys()) if isinstance(rfield, dict) else None}")
                    else:
                        print(f"     → {r.get('addr')}  ERROR: {r.get('error')}")
            else:
                print(f"[NO]  {host}:{port} — не отвечает / ошибка: {res.get('error') if res.get('error') else 'timeout'}")

    # Сохраняем CSV
    csv_file = "dht_probe_results.csv"
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["host", "port", "addr", "rtt_ms", "error", "decoded_present"])
        for res in answers:
            for r in res.get("results", []) if res.get("results") else ( [{"addr":"", "rtt_ms":None, "error":res.get("error"), "decoded":None}] ):
                w.writerow([res.get("host"), res.get("port"), r.get("addr"), r.get("rtt_ms"), r.get("error"), bool(r.get("decoded"))])
    print(f"\nГотово. Результаты сохранены в {csv_file}")

if __name__ == "__main__":
    main()
