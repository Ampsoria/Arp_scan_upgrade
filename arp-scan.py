#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
arp-scan-fast.py
Fast Windows-friendly ARP scanner (TCP-nudge heavy, multiprocessing).
- Default behavior: do parallel short TCP connect_ex (port 80) across targets,
  parse `arp -a` to collect MACs. For IPs still missing, try additional ports
  (443,22) in quick rounds. This mimics OS TCP ARP resolution (like your old tool)
  but runs massively parallel and targets only missing hosts to be fast.
- Works without Scapy/Npcap. Optional --use-scapy to attempt scapy first.
"""
from __future__ import annotations
import argparse, ipaddress, subprocess, re, socket, csv, json, sys
from datetime import datetime
from multiprocessing import Pool, cpu_count
from typing import List, Dict, Set, Tuple

# ---------------- banner ----------------
def print_banner():
    print(r"""
   ___                                 _       
 / _ \                               (_)      
/ /_\ \_ __ ___  _ __  ___  ___  _ __ _  __ _ 
|  _  | '_ ` _ \| '_ \/ __|/ _ \| '__| |/ _` |
| | | | | | | | | |_) \__ \ (_) | |  | | (_| |
\_| |_/_| |_| |_| .__/|___/\___/|_|  |_|\__,_|
                | |                           
                |_|                           
""")

# ---------------- targets parser ----------------
def parse_targets(target: str) -> List[str]:
    parts = [p.strip() for p in target.split(",") if p.strip()]
    res = []
    for p in parts:
        if "-" in p and not ("/" in p):
            a,b = p.split("-",1)
            start = ipaddress.ip_address(a.strip())
            end   = ipaddress.ip_address(b.strip())
            if int(end) < int(start):
                raise ValueError("Invalid range")
            for i in range(int(start), int(end)+1):
                res.append(str(ipaddress.IPv4Address(i)))
        else:
            try:
                net = ipaddress.ip_network(p, strict=False)
                if net.version != 4:
                    raise ValueError("Only IPv4 supported")
                res.extend(str(h) for h in net.hosts())
            except Exception:
                ip = ipaddress.ip_address(p)
                if ip.version != 4:
                    raise ValueError("Only IPv4 supported")
                res.append(str(ip))
    # unique & sorted
    return sorted(set(res), key=lambda x: tuple(int(o) for o in x.split(".")))

# ---------------- arp parsing ----------------
_re_arp = re.compile(r"^\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+([0-9A-Fa-f-]{17})\s+\w+", re.MULTILINE)
def read_arp_table() -> Dict[str,str]:
    try:
        p = subprocess.run(["arp", "-a"], capture_output=True, text=True, check=False)
        out = {}
        for m in _re_arp.finditer(p.stdout):
            ip = m.group(1)
            mac = m.group(2).replace("-", ":").lower()
            out[ip] = mac
        return out
    except Exception:
        return {}

# ---------------- helpers ----------------
def is_bad_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.version != 4 or a.is_multicast or a.is_unspecified or a.is_loopback or a.is_link_local or a == ipaddress.ip_address("255.255.255.255")
    except Exception:
        return True

def is_bad_mac(mac: str) -> bool:
    mac = (mac or "").lower()
    return mac == "ff:ff:ff:ff:ff:ff" or mac.startswith("01:00:5e") or mac.startswith("33:33") or mac == "00:00:00:00:00:00"

# ---------------- TCP nudge worker ----------------
def _tcp_connect_one(args_tuple) -> Tuple[str,bool]:
    ip, port, timeout_ms = args_tuple
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(max(0.03, timeout_ms/1000.0))
        # connect_ex won't raise; returns errno (0 success)
        rc = s.connect_ex((ip, port))
        s.close()
        return (ip, rc == 0)
    except Exception:
        return (ip, False)

# ---------------- batch nudge logic ----------------
def tcp_nudge_targets(ips: List[str], ports: List[int], timeout_ms: int, workers: int, batch_size:int, verbose: bool) -> Set[str]:
    """
    Strategy:
      - For each port in ports (ordered), run parallel connect_ex for all missing IPs in batches.
      - After each batch/port, read arp table and collect any discovered MACs.
      - Stop early if all found.
    Returns set of IPs that were touched (i.e., we attempted).
    """
    found_ips: Set[str] = set()
    targets_set = set(ips)
    pool = Pool(processes=max(1, min(workers, cpu_count()*3)))
    try:
        # For each port, do batched parallel connects
        for port in ports:
            if verbose:
                print(f"[*] Trying port {port} for {len([ip for ip in targets_set if ip not in found_ips])} missing hosts...")
            # prepare list of missing ips to attempt this port
            missing_now = [ip for ip in ips if ip not in found_ips]
            if not missing_now:
                break
            # process in batches to avoid too many args to pool.map
            for i in range(0, len(missing_now), batch_size):
                batch = missing_now[i:i+batch_size]
                args = [(ip, port, timeout_ms) for ip in batch]
                # map
                _ = pool.map(_tcp_connect_one, args)
                # after attempts, parse arp to capture any new entries
                arp = read_arp_table()
                for ip in batch:
                    if ip in arp and not is_bad_ip(ip) and not is_bad_mac(arp[ip]):
                        found_ips.add(ip)
                if verbose:
                    print(f"    -> batch {i//batch_size + 1}: discovered {len([ip for ip in batch if ip in arp])} in arp")
            # quick exit if all found
            if len(found_ips) == len(ips):
                break
    finally:
        pool.close()
        pool.join()
    return found_ips

# ---------------- main scan flow ----------------
def main():
    parser = argparse.ArgumentParser(description="Fast hybrid ARP scanner (TCP-nudge heavy).")
    parser.add_argument("-t","--target", required=True, help="IP/CIDR, range a-b, or comma list")
    parser.add_argument("--workers", type=int, default=max(8, cpu_count()*4), help="parallel workers")
    parser.add_argument("--ports", default="80,443,22", help="comma list of ports to try in order (default: 80,443,22)")
    parser.add_argument("--timeout-ms", type=int, default=200, help="connect timeout per port (ms)")
    parser.add_argument("--batch-size", type=int, default=200, help="how many connects to fire before reading arp")
    parser.add_argument("--csv", help="save csv")
    parser.add_argument("--json", help="save json")
    parser.add_argument("-q","--quiet", action="store_true")
    parser.add_argument("-v","--verbose", action="store_true")
    parser.add_argument("--use-scapy", action="store_true", help="attempt scapy first (optional; requires Npcap/Scapy)")
    args = parser.parse_args()

    try:
        targets = parse_targets(args.target)
    except Exception as e:
        print("Target parse error:", e, file=sys.stderr); sys.exit(2)
    if not targets:
        print("No targets", file=sys.stderr); sys.exit(2)

    if not args.quiet:
        print_banner()
        print(f"[*] Targets: {len(targets)} (showing first 6): {targets[:6]}{'...' if len(targets)>6 else ''}")
        print(f"[*] Workers: {args.workers}  batch-size: {args.batch_size}  timeout(ms): {args.timeout_ms}")
        print(f"[*] Ports (order): {args.ports}")

    start = datetime.now()

    # optional: attempt scapy quick round (very fast) if requested
    scapy_rows: Dict[str,str] = {}
    if args.use_scapy:
        try:
            from scapy.all import srp, Ether, ARP, conf
            conf.verb = 0
            # do a small batch size to avoid long waits
            from math import ceil
            chunk = 256 if len(targets) > 256 else len(targets)
            ans,_ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=" ".join(targets[:chunk])), timeout=1)
            for _, r in ans:
                scapy_rows[r.psrc] = r.src.lower()
            if args.verbose:
                print(f"[*] scapy quick found: {len(scapy_rows)}")
        except Exception as e:
            if args.verbose:
                print("[!] scapy attempt failed:", e)

    # read initial ARP (may already have some entries)
    arp = read_arp_table()
    # collect any valid matches from scapy/arp
    merged: Dict[str,str] = {}
    for ip, mac in scapy_rows.items():
        if not is_bad_ip(ip) and not is_bad_mac(mac):
            merged[ip] = mac
    for ip, mac in arp.items():
        if ip in targets and not is_bad_ip(ip) and not is_bad_mac(mac):
            merged.setdefault(ip, mac)

    # determine missing targets
    found_ips = set(merged.keys())
    missing = [ip for ip in targets if ip not in found_ips]
    if args.verbose:
        print(f"[*] Initially found {len(found_ips)}; need to nudge {len(missing)}")

    # Do tcp-nudge rounds: use ports in order, but stop when all found.
    ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
    if missing:
        discovered = tcp_nudge_targets(missing, ports, args.timeout_ms, args.workers, args.batch_size, args.verbose)
        # read arp again and merge
        arp2 = read_arp_table()
        for ip, mac in arp2.items():
            if ip in targets and not is_bad_ip(ip) and not is_bad_mac(mac):
                merged.setdefault(ip, mac)
        # if discovered set contains others, ensure merged updated
        for ip in discovered:
            if ip in arp2:
                merged.setdefault(ip, arp2[ip])

    # final formatting: only include targets and sort
    final = sorted([(ip, merged[ip]) for ip in merged if ip in targets], key=lambda x: tuple(int(o) for o in x[0].split(".")))

    dur = datetime.now() - start
    elapsed = dur.total_seconds()

    # print table
    def to_table(rows):
        if not rows:
            return "No hosts found."
        w_ip = max(len("IP"), max(len(r[0]) for r in rows))
        w_mac = max(len("MAC"), max(len(r[1]) for r in rows))
        line = "+" + "-"*(w_ip+2) + "+" + "-"*(w_mac+2) + "+\n"
        out = line
        out += f"| {'IP'.ljust(w_ip)} | {'MAC'.ljust(w_mac)} |\n"
        out += line
        for ip, mac in rows:
            out += f"| {ip.ljust(w_ip)} | {mac.ljust(w_mac)} |\n"
        out += line
        return out

    if not args.quiet:
        print("\n[*] Results:")
    print(to_table(final))
    if not args.quiet:
        print(f"[*] Hosts found: {len(final)}")
        print(f"[*] Duration: {elapsed:.2f} seconds")

    if args.csv:
        try:
            with open(args.csv, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["ip","mac"])
                for ip, mac in final:
                    w.writerow([ip, mac])
            if not args.quiet:
                print(f"[*] Saved CSV -> {args.csv}")
        except Exception as e:
            print("[!] CSV save error:", e, file=sys.stderr)

    if args.json:
        try:
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump([{"ip":ip,"mac":mac} for ip,mac in final], f, ensure_ascii=False, indent=2)
            if not args.quiet:
                print(f"[*] Saved JSON -> {args.json}")
        except Exception as e:
            print("[!] JSON save error:", e, file=sys.stderr)

if __name__ == "__main__":
    main()
