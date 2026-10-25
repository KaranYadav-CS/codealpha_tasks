"""
Synthetic Network Traffic Generator (Safe Lab PCAP Generator)
CodeAlpha Cyber Security Internship - Task 4: Network Intrusion Detection System

Generates a reproducible, non-destructive PCAP file adhering to RFC 5737 
(IPv4 Address Blocks Reserved for Documentation: 192.0.2.0/24 and 198.51.100.0/24).
Exercises custom Suricata detection rules:
- Normal HTTP baseline traffic (Control / No alert)
- SID 1000001: Unique Harmless Telemetry Marker in HTTP GET
- SID 1000002: Suspicious Automated Scanner User-Agent
- SID 1000003: TCP SYN Reconnaissance Port Sweep
- SID 1000004: TCP XMAS Tree Scan Probe (FIN+PSH+URG)
- SID 1000005: TCP NULL Scan Probe (Zero flags)
- SID 1000006: Suspicious Canary DNS Query
- SID 1000007: Simulated Web Shell Command Injection (POST cmd=whoami)
"""

import os
import sys
import argparse
from scapy.all import (
    Ether, IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap
)

DEFAULT_OUTPUT_PCAP = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "lab_traffic.pcap"
)

# RFC 5737 Documentation IP addresses
CLIENT_IP = "192.0.2.10"       # TEST-NET-1 (Simulated Lab Workstation)
SERVER_IP = "198.51.100.50"    # TEST-NET-2 (Simulated Lab Web Server)
DNS_SERVER_IP = "198.51.100.53"
ATTACKER_IP = "192.0.2.100"    # Simulated Internal Rogue / Scanning Host

MAC_CLIENT = "00:11:22:33:44:55"
MAC_SERVER = "aa:bb:cc:dd:ee:ff"

def build_tcp_handshake(src_ip, dst_ip, sport, dport, seq_start=1000):
    """Simulates a valid RFC 793 TCP 3-way handshake."""
    syn = Ether(src=MAC_CLIENT, dst=MAC_SERVER) / \
          IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=sport, dport=dport, flags="S", seq=seq_start)

    syn_ack = Ether(src=MAC_SERVER, dst=MAC_CLIENT) / \
              IP(src=dst_ip, dst=src_ip) / \
              TCP(sport=dport, dport=sport, flags="SA", seq=5000, ack=seq_start + 1)

    ack = Ether(src=MAC_CLIENT, dst=MAC_SERVER) / \
          IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=sport, dport=dport, flags="A", seq=seq_start + 1, ack=5001)

    return [syn, syn_ack, ack]

def build_tcp_teardown(src_ip, dst_ip, sport, dport, client_seq, server_seq):
    """Simulates a graceful TCP FIN handshake teardown."""
    fin = Ether(src=MAC_CLIENT, dst=MAC_SERVER) / \
          IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=sport, dport=dport, flags="FA", seq=client_seq, ack=server_seq)

    fin_ack = Ether(src=MAC_SERVER, dst=MAC_CLIENT) / \
              IP(src=dst_ip, dst=src_ip) / \
              TCP(sport=dport, dport=sport, flags="FA", seq=server_seq, ack=client_seq + 1)

    final_ack = Ether(src=MAC_CLIENT, dst=MAC_SERVER) / \
                IP(src=src_ip, dst=dst_ip) / \
                TCP(sport=sport, dport=dport, flags="A", seq=client_seq + 1, ack=server_seq + 1)

    return [fin, fin_ack, final_ack]

def generate_packets():
    packets = []

    # --------------------------------------------------------------------------
    # Flow 0: Baseline Normal HTTP Traffic (Control - Must NOT trigger alerts)
    # --------------------------------------------------------------------------
    sport_0 = 49152
    dport_http = 80
    handshake_0 = build_tcp_handshake(CLIENT_IP, SERVER_IP, sport_0, dport_http, seq_start=1000)
    packets.extend(handshake_0)

    http_get_0 = (
        "GET /index.html HTTP/1.1\r\n"
        f"Host: {SERVER_IP}\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
        "Accept: text/html,application/xhtml+xml\r\n\r\n"
    )
    req_pkt_0 = Ether(src=MAC_CLIENT, dst=MAC_SERVER) / \
                IP(src=CLIENT_IP, dst=SERVER_IP) / \
                TCP(sport=sport_0, dport=dport_http, flags="PA", seq=1001, ack=5001) / \
                Raw(load=http_get_0)
    packets.append(req_pkt_0)

    http_resp_0 = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=UTF-8\r\n"
        "Content-Length: 48\r\n\r\n"
        "<html><body><h1>AlphaCorp Internal</h1></body></html>"
    )
    resp_pkt_0 = Ether(src=MAC_SERVER, dst=MAC_CLIENT) / \
                 IP(src=SERVER_IP, dst=CLIENT_IP) / \
                 TCP(sport=dport_http, dport=sport_0, flags="PA", seq=5001, ack=1001 + len(http_get_0)) / \
                 Raw(load=http_resp_0)
    packets.append(resp_pkt_0)

    packets.extend(build_tcp_teardown(CLIENT_IP, SERVER_IP, sport_0, dport_http,
                                      1001 + len(http_get_0), 5001 + len(http_resp_0)))

    # --------------------------------------------------------------------------
    # Flow 1: Harmless Telemetry Marker (Triggers SID 1000001)
    # --------------------------------------------------------------------------
    sport_1 = 49153
    packets.extend(build_tcp_handshake(CLIENT_IP, SERVER_IP, sport_1, dport_http, seq_start=2000))

    http_get_1 = (
        "GET /test-marker/alpha-telemetry HTTP/1.1\r\n"
        f"Host: {SERVER_IP}\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        "Connection: close\r\n\r\n"
    )
    req_pkt_1 = Ether(src=MAC_CLIENT, dst=MAC_SERVER) / \
                IP(src=CLIENT_IP, dst=SERVER_IP) / \
                TCP(sport=sport_1, dport=dport_http, flags="PA", seq=2001, ack=5001) / \
                Raw(load=http_get_1)
    packets.append(req_pkt_1)

    http_resp_1 = "HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\nTelemetry Acked"
    resp_pkt_1 = Ether(src=MAC_SERVER, dst=MAC_CLIENT) / \
                 IP(src=SERVER_IP, dst=CLIENT_IP) / \
                 TCP(sport=dport_http, dport=sport_1, flags="PA", seq=5001, ack=2001 + len(http_get_1)) / \
                 Raw(load=http_resp_1)
    packets.append(resp_pkt_1)
    packets.extend(build_tcp_teardown(CLIENT_IP, SERVER_IP, sport_1, dport_http,
                                      2001 + len(http_get_1), 5001 + len(http_resp_1)))

    # --------------------------------------------------------------------------
    # Flow 2: Suspicious Scanner User-Agent (Triggers SID 1000002)
    # --------------------------------------------------------------------------
    sport_2 = 49154
    packets.extend(build_tcp_handshake(ATTACKER_IP, SERVER_IP, sport_2, dport_http, seq_start=3000))

    http_get_2 = (
        "GET /api/v1/system-status HTTP/1.1\r\n"
        f"Host: {SERVER_IP}\r\n"
        "User-Agent: AlphaInfiltrationScanner/1.0\r\n"
        "Connection: close\r\n\r\n"
    )
    req_pkt_2 = Ether(src=MAC_CLIENT, dst=MAC_SERVER) / \
                IP(src=ATTACKER_IP, dst=SERVER_IP) / \
                TCP(sport=sport_2, dport=dport_http, flags="PA", seq=3001, ack=5001) / \
                Raw(load=http_get_2)
    packets.append(req_pkt_2)
    packets.extend(build_tcp_teardown(ATTACKER_IP, SERVER_IP, sport_2, dport_http,
                                      3001 + len(http_get_2), 5001))

    # --------------------------------------------------------------------------
    # Flow 3: Controlled TCP SYN Port Sweep (Triggers SID 1000003)
    # --------------------------------------------------------------------------
    target_ports = [21, 22, 23, 80, 443, 3389, 8080]
    for idx, port in enumerate(target_ports):
        syn_probe = Ether(src=MAC_CLIENT, dst=MAC_SERVER) / \
                    IP(src=ATTACKER_IP, dst=SERVER_IP) / \
                    TCP(sport=50000 + idx, dport=port, flags="S", seq=10000 + idx)
        packets.append(syn_probe)

    # --------------------------------------------------------------------------
    # Flow 4: Suspicious TCP XMAS Tree Scan (Triggers SID 1000004)
    # --------------------------------------------------------------------------
    xmas_probe = Ether(src=MAC_CLIENT, dst=MAC_SERVER) / \
                 IP(src=ATTACKER_IP, dst=SERVER_IP) / \
                 TCP(sport=51001, dport=80, flags="FPU", seq=20000)
    packets.append(xmas_probe)

    # --------------------------------------------------------------------------
    # Flow 5: Suspicious TCP NULL Scan (Triggers SID 1000005)
    # --------------------------------------------------------------------------
    null_probe = Ether(src=MAC_CLIENT, dst=MAC_SERVER) / \
                 IP(src=ATTACKER_IP, dst=SERVER_IP) / \
                 TCP(sport=51002, dport=80, flags="", seq=21000)
    packets.append(null_probe)

    # --------------------------------------------------------------------------
    # Flow 6: Suspicious Canary DNS Query (Triggers SID 1000006)
    # --------------------------------------------------------------------------
    dns_query = Ether(src=MAC_CLIENT, dst=MAC_SERVER) / \
                IP(src=CLIENT_IP, dst=DNS_SERVER_IP) / \
                UDP(sport=52123, dport=53) / \
                DNS(rd=1, qd=DNSQR(qname="canary-recon.codealpha.test", qtype="A"))
    packets.append(dns_query)

    # --------------------------------------------------------------------------
    # Flow 7: Simulated Web Shell Command Injection (Triggers SID 1000007)
    # --------------------------------------------------------------------------
    sport_7 = 49155
    packets.extend(build_tcp_handshake(ATTACKER_IP, SERVER_IP, sport_7, dport_http, seq_start=4000))

    post_body = "cmd=whoami&action=exec"
    http_post_7 = (
        "POST /admin/shell.php HTTP/1.1\r\n"
        f"Host: {SERVER_IP}\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(post_body)}\r\n"
        "Connection: close\r\n\r\n"
        f"{post_body}"
    )
    req_pkt_7 = Ether(src=MAC_CLIENT, dst=MAC_SERVER) / \
                IP(src=ATTACKER_IP, dst=SERVER_IP) / \
                TCP(sport=sport_7, dport=dport_http, flags="PA", seq=4001, ack=5001) / \
                Raw(load=http_post_7)
    packets.append(req_pkt_7)
    packets.extend(build_tcp_teardown(ATTACKER_IP, SERVER_IP, sport_7, dport_http,
                                      4001 + len(http_post_7), 5001))

    return packets

def generate_pcap(output_file=DEFAULT_OUTPUT_PCAP):
    os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
    pkts = generate_packets()
    wrpcap(output_file, pkts)
    print(f"[+] Successfully generated {len(pkts)} synthetic packets.")
    print(f"[+] Saved PCAP to: {output_file} ({os.path.getsize(output_file)} bytes)")
    return output_file

def main():
    parser = argparse.ArgumentParser(description="Generate safe, synthetic lab PCAP for Suricata NIDS testing.")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT_PCAP, help="Output PCAP file path")
    args = parser.parse_args()
    generate_pcap(args.output)

if __name__ == "__main__":
    main()
