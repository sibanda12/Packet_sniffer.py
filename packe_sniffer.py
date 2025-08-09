#!/usr/bin/env python3
"""
packet_sniffer.py
A safe, local packet sniffer for learning and analysis.
Use only on networks/machines you own or have permission to test.

Features:
- Capture packets from an interface (or default)
- Print timestamp, src IP:port, dst IP:port, protocol, length
- Optional BPF filter (e.g., "tcp", "port 80", "host 8.8.8.8")
- Optional CSV logging (--log)
"""

import argparse
import csv
from datetime import datetime
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP

def pkt_summary(pkt):
    ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    proto = "OTHER"
    src = "-"
    dst = "-"
    length = len(pkt)
    try:
        if IP in pkt:
            ip = pkt[IP]
            src = f"{ip.src}"
            dst = f"{ip.dst}"
        elif IPv6 in pkt:
            ip = pkt[IPv6]
            src = f"{ip.src}"
            dst = f"{ip.dst}"
        if TCP in pkt:
            proto = "TCP"
            tcp = pkt[TCP]
            src += f":{tcp.sport}"
            dst += f":{tcp.dport}"
        elif UDP in pkt:
            proto = "UDP"
            udp = pkt[UDP]
            src += f":{udp.sport}"
            dst += f":{udp.dport}"
        elif ICMP in pkt:
            proto = "ICMP"
        elif pkt.haslayer("ARP"):
            proto = "ARP"
            # ARP doesn't have IP src/dst in same place; show summary
            src = pkt.summary()
            dst = ""
    except Exception:
        pass

    return {
        "timestamp": ts,
        "src": src,
        "dst": dst,
        "proto": proto,
        "length": length
    }

def on_packet(pkt, writer=None):
    info = pkt_summary(pkt)
    line = f"{info['timestamp']}  {info['proto']:5}  {info['src']:22} -> {info['dst']:22}  len={info['length']}"
    print(line)
    if writer:
        writer.writerow(info)

def start_sniff(interface=None, count=0, timeout=None, bpf=None, logfile=None):
    writer = None
    csvfile = None
    if logfile:
        csvfile = open(logfile, "w", newline="", encoding="utf-8")
        fieldnames = ["timestamp", "src", "dst", "proto", "length"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        print(f"[+] Logging to {logfile}")

    print("[*] Starting capture. Press Ctrl+C to stop.")
    try:
        sniff(iface=interface, prn=lambda p: on_packet(p, writer), filter=bpf, store=False,
              count=count if count > 0 else 0, timeout=timeout)
    except PermissionError:
        print("! Permission error: you must run the script with elevated privileges (sudo or Administrator).")
    except Exception as e:
        print("! Sniffing error:", e)
    finally:
        if csvfile:
            csvfile.close()
            print(f"[+] Logged file closed: {logfile}")
        print("[*] Capture finished.")

def parse_args():
    p = argparse.ArgumentParser(description="Local packet sniffer (use responsibly)")
    p.add_argument("--iface", help="Network interface to capture (e.g., eth0, wlan0). Default = system default", default=None)
    p.add_argument("--count", type=int, default=0, help="Number of packets to capture (0 = unlimited until Ctrl+C)")
    p.add_argument("--timeout", type=int, help="Capture timeout in seconds (optional)")
    p.add_argument("--filter", help='BPF filter string (e.g., "tcp and port 80")', default=None)
    p.add_argument("--log", help="Path to CSV file to save capture (optional)")
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    start_sniff(interface=args.iface, count=args.count, timeout=args.timeout, bpf=args.filter, logfile=args.log)
