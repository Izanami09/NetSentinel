"""
NetSentinel — AI-Powered Network Traffic Analyzer
Main Streamlit Dashboard
Run with: sudo streamlit run app.py
(sudo needed for packet capture + ARP spoofing on Mac/Linux)
"""
import os
import sys
import time
import tempfile
from datetime import datetime
import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

# FIXED IMPORT - both files are now in the same folder
from utils.capture_engine import CaptureEngine, ARPSpoofer, FlowAggregator, SCAPY_AVAILABLE
from utils.ai_explainer import AIExplainer, ReportGenerator, AppFingerprinter
import plotly.graph_objects as go
# ─────────────────────────────────────────────
# Page Config
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="NetSentinel — AI Network Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────
# Custom CSS
# ─────────────────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;600;700&display=swap');
    .main-header {
        font-family: 'JetBrains Mono', monospace;
        font-size: 2.2rem;
        font-weight: 700;
        background: linear-gradient(135deg, #00d2ff, #3a7bd5);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.5rem;
    }
    .sub-header {
        font-family: 'Inter', sans-serif;
        color: #888;
        font-size: 0.95rem;
        margin-bottom: 2rem;
    }
    .threat-high {
        background: linear-gradient(135deg, #ff4444, #cc0000);
        color: white;
        padding: 8px 16px;
        border-radius: 8px;
        font-weight: 700;
        font-size: 0.85rem;
    }
    .threat-medium {
        background: linear-gradient(135deg, #ffbb33, #ff8800);
        color: white;
        padding: 8px 16px;
        border-radius: 8px;
        font-weight: 700;
        font-size: 0.85rem;
    }
    .threat-low {
        background: linear-gradient(135deg, #ffdd57, #ffc107);
        color: #333;
        padding: 8px 16px;
        border-radius: 8px;
        font-weight: 700;
        font-size: 0.85rem;
    }
    .threat-safe {
        background: linear-gradient(135deg, #00C851, #007E33);
        color: white;
        padding: 8px 16px;
        border-radius: 8px;
        font-weight: 700;
        font-size: 0.85rem;
    }
    .metric-card {
        background: #1a1a2e;
        border: 1px solid #333;
        border-radius: 12px;
        padding: 20px;
        text-align: center;
    }
    .packet-row {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.8rem;
    }
    div[data-testid="stMetric"] {
        background: rgba(28, 131, 225, 0.05);
        border: 1px solid rgba(28, 131, 225, 0.1);
        border-radius: 8px;
        padding: 10px 15px;
    }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────
# Session State Initialization
# ─────────────────────────────────────────────
if "engine" not in st.session_state: st.session_state.engine = None
if "packets" not in st.session_state: st.session_state.packets = []
if "is_capturing" not in st.session_state: st.session_state.is_capturing = False
if "spoofer" not in st.session_state: st.session_state.spoofer = None
if "is_spoofing" not in st.session_state: st.session_state.is_spoofing = False
if "explainer" not in st.session_state: st.session_state.explainer = AIExplainer()
if "demo_mode" not in st.session_state: st.session_state.demo_mode = False
if "fingerprinter" not in st.session_state:
    st.session_state.fingerprinter = AppFingerprinter()
# ─────────────────────────────────────────────
# Hex Dump Formatter (for packet content viewer)
# ─────────────────────────────────────────────
def format_hex_dump(hex_str, bytes_per_line=16):
    """Format a hex string as a traditional hex dump with ASCII sidebar."""
    if not hex_str:
        return "No payload data"
    try:
        raw = bytes.fromhex(hex_str)
    except ValueError:
        return "Invalid hex data"
    lines = []
    for i in range(0, len(raw), bytes_per_line):
        chunk = raw[i:i + bytes_per_line]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08x}  {hex_part:<{bytes_per_line * 3}} |{ascii_part}|")
    return "\n".join(lines)

# ─────────────────────────────────────────────
# Demo Data Generator
# ─────────────────────────────────────────────
def generate_demo_packets(n=100):
    """Generate realistic demo packets for testing without sudo."""
    import random
    packets = []
    normal_services = [
        ("HTTPS", 443, "TCP"), ("HTTP", 80, "TCP"), ("DNS", 53, "UDP"),
        ("SSH", 22, "TCP"), ("NTP", 123, "UDP"),
    ]
    suspicious_scenarios = [
        {"service": "Port-4444", "dst_port": 4444, "protocol": "TCP",
         "threat_level": "high", "threat_score": 0.7,
         "threat_flags": ["Suspicious port detected"],
         "explanation": "⚠️ Connection to port 4444 (common reverse shell port) | Potentially malicious"},
        {"service": "Port-31337", "dst_port": 31337, "protocol": "TCP",
         "threat_level": "high", "threat_score": 0.8,
         "threat_flags": ["Suspicious port detected", "XMAS scan detected (FIN+PSH+URG flags)"],
         "explanation": "🔴 XMAS scan detected from external IP | Known attack technique"},
        {"service": "DNS", "dst_port": 53, "protocol": "UDP",
         "threat_level": "medium", "threat_score": 0.4,
         "threat_flags": ["Unusually long DNS query (potential DNS tunneling)"],
         "explanation": "🟠 Suspicious DNS query — possible DNS tunneling attempt"},
    ]
    src_ips = ["192.168.1.100", "192.168.1.101", "10.0.0.5"]
    dst_ips = [
        ("8.8.8.8", "United States", "Mountain View", "Google LLC"),
        ("1.1.1.1", "Australia", "Sydney", "Cloudflare"),
        ("104.21.32.1", "United States", "San Francisco", "Cloudflare"),
        ("185.199.108.153", "United States", "San Francisco", "GitHub"),
        ("142.250.80.46", "United States", "Mountain View", "Google LLC"),
        ("31.13.65.36", "Ireland", "Dublin", "Meta Platforms"),
        ("45.33.32.156", "United States", "Fremont", "Linode"),
        ("203.0.113.50", "Russia", "Moscow", "Unknown ISP"),
        ("198.51.100.23", "China", "Beijing", "Unknown ISP"),
    ]
    for i in range(n):
        ts = time.time() - random.uniform(0, 300)
        src_ip = random.choice(src_ips)
        dst_info = random.choice(dst_ips)
        if random.random() < 0.85:  # 85% normal traffic
            svc, port, proto = random.choice(normal_services)
            flags = random.choice(["S", "SA", "A", "PA", "FA", ""])
            pkt = {
                "timestamp": datetime.fromtimestamp(ts).isoformat(),
                "epoch": ts,
                "size": random.randint(40, 1500),
                "src_ip": src_ip,
                "dst_ip": dst_info[0],
                "src_port": random.randint(49152, 65535),
                "dst_port": port,
                "protocol": proto,
                "service": svc,
                "tcp_flags": flags if proto == "TCP" else "",
                "ttl": random.choice([64, 128, 255]),
                "payload_size": random.randint(0, 1400),
                "src_country": "Local",
                "src_city": "Private Network",
                "src_isp": "Local",
                "dst_country": dst_info[1],
                "dst_city": dst_info[2],
                "dst_isp": dst_info[3],
                "src_lat": 0, "src_lon": 0,
                "dst_lat": random.uniform(-40, 60),
                "dst_lon": random.uniform(-120, 140),
                "threat_score": 0.0,
                "threat_level": "safe",
                "threat_flags": [],
                "explanation": (
                    f"📦 Normal {svc} traffic: {src_ip} → {dst_info[0]} ({dst_info[1]}) | "
                    f"{svc} connection carrying data"
                ),
            }
        else:  # 15% suspicious
            scenario = random.choice(suspicious_scenarios)
            pkt = {
                "timestamp": datetime.fromtimestamp(ts).isoformat(),
                "epoch": ts,
                "size": random.randint(40, 2000),
                "src_ip": random.choice(["203.0.113.50", "198.51.100.23", "45.33.32.156"]),
                "dst_ip": src_ip,  # incoming attack
                "src_port": random.randint(1024, 65535),
                "dst_port": scenario["dst_port"],
                "protocol": scenario["protocol"],
                "service": scenario["service"],
                "tcp_flags": random.choice(["S", "FPU", ""]),
                "ttl": random.choice([2, 5, 64, 128]),
                "payload_size": random.randint(0, 3000),
                "src_country": random.choice(["Russia", "China", "Unknown"]),
                "src_city": random.choice(["Moscow", "Beijing", "Unknown"]),
                "src_isp": "Unknown ISP",
                "dst_country": "Local",
                "dst_city": "Private Network",
                "dst_isp": "Local",
                "src_lat": random.uniform(20, 60),
                "src_lon": random.uniform(30, 140),
                "dst_lat": 0, "dst_lon": 0,
                "threat_score": scenario["threat_score"],
                "threat_level": scenario["threat_level"],
                "threat_flags": scenario["threat_flags"],
                "explanation": scenario["explanation"],
            }
        # Add payload data for content viewer
        if pkt.get("service") in ("HTTP", "HTTPS"):
            sample = f"GET /page{random.randint(1, 99)}.html HTTP/1.1\r\nHost: {pkt.get('dst_ip', 'example.com')}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n"
            pkt["payload_hex"] = sample.encode().hex()
            pkt["payload_text"] = sample
            pkt["payload_ascii"] = sample[:100]
        elif pkt.get("service") == "DNS":
            pkt["payload_hex"] = ""
            pkt["payload_text"] = ""
            pkt["payload_ascii"] = ""
        else:
            pkt.setdefault("payload_hex", "")
            pkt.setdefault("payload_text", "")
            pkt.setdefault("payload_ascii", "")
        packets.append(pkt)
    packets.sort(key=lambda x: x["epoch"])
    return packets

# ─────────────────────────────────────────────
# Sidebar
# ─────────────────────────────────────────────
with st.sidebar:
    st.markdown('<div class="main-header">🛡️ NetSentinel</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">AI-Powered Network Analyzer</div>', unsafe_allow_html=True)
    st.divider()

    mode = st.radio("Mode", ["📡 Live Capture", "📂 Analyze PCAP/CSV", "🎮 Demo Mode"])

    if mode == "📡 Live Capture":
        st.markdown("### Capture Settings")
        if not SCAPY_AVAILABLE:
            st.error("⚠️ Scapy not installed. Run: `pip install scapy`")

        interface = st.text_input("Network Interface", value="en0")
        bpf_filter = st.text_input("BPF Filter (optional)", placeholder="tcp port 80")

        col1, col2 = st.columns(2)
        with col1:
            if st.button("▶️ Start Capture", type="primary", disabled=st.session_state.is_capturing, use_container_width=True):
                engine = CaptureEngine(interface=interface)
                st.session_state.engine = engine
                st.session_state.is_capturing = True
                st.session_state.packets = []
                engine.start(bpf_filter=bpf_filter or None)
                st.rerun()
        with col2:
            if st.button("⏹️ Stop Capture", disabled=not st.session_state.is_capturing, use_container_width=True):
                if st.session_state.engine:
                    if st.session_state.is_spoofing and st.session_state.spoofer:
                        st.session_state.spoofer.stop()
                        st.session_state.is_spoofing = False
                    st.session_state.engine.stop()
                    st.session_state.is_capturing = False
                    st.rerun()

        # ARP Spoofing (MITM)
        st.divider()
        st.markdown("### 🚀 ARP Spoofing (MITM)")
        st.caption("Scan your network and spoof all hosts — no need to specify IPs manually")

        # Gateway resolution: Auto or Manual
        gw_mode = st.radio("Gateway IP", ["🔄 Auto Detect", "✏️ Manual"],
                           horizontal=True, key="gw_mode")
        if gw_mode == "🔄 Auto Detect":
            @st.cache_data(ttl=30)
            def _detect_gateway():
                """Detect default gateway from system routing table."""
                import subprocess, re, platform
                try:
                    if platform.system() == "Darwin":
                        out = subprocess.check_output(
                            ["netstat", "-rn"], text=True, timeout=5
                        )
                        for line in out.splitlines():
                            parts = line.split()
                            if len(parts) >= 3 and parts[0] == "default":
                                gw = parts[1]
                                # Validate it looks like an IPv4 address
                                if re.match(r"^\d+\.\d+\.\d+\.\d+$", gw):
                                    return gw
                    else:  # Linux
                        out = subprocess.check_output(
                            ["ip", "route", "show", "default"], text=True, timeout=5
                        )
                        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
                        if m:
                            return m.group(1)
                except Exception:
                    pass
                return None

            detected_gw = _detect_gateway()
            if detected_gw:
                gateway_ip = detected_gw
                st.success(f"🔄 Gateway: **{gateway_ip}**")
            else:
                st.warning("⚠️ Could not detect gateway — falling back to manual")
                gateway_ip = st.text_input("Gateway IP (fallback)", value="192.168.1.1",
                                           key="gw_fallback")
        else:
            gateway_ip = st.text_input("Gateway IP", value="192.168.1.1",
                                        key="gw_manual")

        # Network scanner
        if st.button("🔍 Scan Network", use_container_width=True,
                     disabled=not st.session_state.is_capturing):
            if st.session_state.engine:
                with st.spinner("Scanning network..."):
                    scanner = ARPSpoofer(interface=st.session_state.engine.interface)
                    hosts = scanner.scan_network()
                    st.session_state["scan_results"] = hosts
                    st.rerun()

        scan_results = st.session_state.get("scan_results", [])
        if scan_results:
            st.success(f"Found {len(scan_results)} hosts")
            for h in scan_results:
                st.caption(f"  {h['ip']}  ({h['mac']})")

        col_sp1, col_sp2 = st.columns(2)
        with col_sp1:
            if st.button("🌐 Spoof All Hosts", type="primary",
                         disabled=not st.session_state.is_capturing or st.session_state.is_spoofing or not scan_results,
                         use_container_width=True):
                if st.session_state.engine and scan_results:
                    all_ips = ",".join(h["ip"] for h in scan_results)
                    spoofer = ARPSpoofer(interface=st.session_state.engine.interface)
                    st.session_state.spoofer = spoofer
                    success = spoofer.start(victim_ip=all_ips, gateway_ip=gateway_ip)
                    if success:
                        st.session_state.is_spoofing = True
                        n = len(spoofer.victim_macs)
                        st.success(f"🎯 Spoofing {n} hosts — whole network visible!")
                        st.rerun()
                    else:
                        st.error("Failed — check gateway IP or run scan again")
        with col_sp2:
            if st.button("🛑 Stop ARP Spoof", disabled=not st.session_state.is_spoofing, use_container_width=True):
                if st.session_state.spoofer:
                    st.session_state.spoofer.stop()
                    st.session_state.is_spoofing = False
                    st.success("✅ ARP tables restored")
                    st.rerun()

        # Manual fallback
        with st.expander("Manual Target Entry"):
            victim_ips = st.text_input("Victim IP(s)", value="192.168.1.100",
                                       help="Comma-separated (e.g. 192.168.1.100,192.168.1.101)")
            if st.button("🔴 Start Manual Spoof",
                         disabled=not st.session_state.is_capturing or st.session_state.is_spoofing,
                         use_container_width=True):
                if st.session_state.engine:
                    spoofer = ARPSpoofer(interface=st.session_state.engine.interface)
                    st.session_state.spoofer = spoofer
                    success = spoofer.start(victim_ip=victim_ips, gateway_ip=gateway_ip)
                    if success:
                        st.session_state.is_spoofing = True
                        st.success("🎯 ARP Spoofing ACTIVE!")
                        st.rerun()
                    else:
                        st.error("Failed — could not resolve target MAC addresses")

        if st.session_state.is_spoofing:
            n = len(st.session_state.spoofer.victim_macs) if st.session_state.spoofer else 0
            st.markdown(f'<div class="threat-high">🔴 ARP SPOOFING ACTIVE<br>MITM on {n} hosts</div>', unsafe_allow_html=True)

    elif mode == "📂 Analyze PCAP/CSV":
        st.markdown("### Upload Traffic Data")
        uploaded = st.file_uploader("Upload CSV file", type=["csv"])
        if uploaded:
            df = pd.read_csv(uploaded)
            st.success(f"Loaded {len(df)} records")
            st.session_state.packets = df.to_dict("records")

    else:  # Demo Mode
        st.markdown("### Demo Mode")
        n_packets = st.slider("Number of demo packets", 50, 500, 150)
        if st.button("🎲 Generate Demo Traffic", type="primary", use_container_width=True):
            demo_pkts = generate_demo_packets(n_packets)
            st.session_state.packets = demo_pkts
            st.session_state.demo_mode = True
            # Build a flow aggregator for demo packets so ML works
            demo_engine = CaptureEngine()
            for p in demo_pkts:
                demo_engine.flow_agg.add_packet(p)
            st.session_state.engine = demo_engine
            st.rerun()

    st.divider()

    # Report generation
    st.markdown("### 📄 Forensic Report")
    if st.button("Generate PDF Report", use_container_width=True):
        if st.session_state.packets:
            try:
                reporter = ReportGenerator()
                flow_agg = FlowAggregator()
                for p in st.session_state.packets:
                    flow_agg.add_packet(p)
                report_path = os.path.join(tempfile.gettempdir(), "netsentinel_report.pdf")
                reporter.generate(
                    st.session_state.packets,
                    flow_agg.get_summary(),
                    flow_agg.detect_anomalies(),
                    report_path
                )
                with open(report_path, "rb") as f:
                    st.download_button(
                        "📥 Download Report",
                        data=f.read(),
                        file_name="netsentinel_report.pdf",
                        mime="application/pdf",
                        use_container_width=True,
                    )
            except Exception as e:
                st.error(f"Report generation failed: {e}")
        else:
            st.warning("No packets captured yet")

# ─────────────────────────────────────────────
# Main Content
# ─────────────────────────────────────────────
_auto_refresh = "2s" if st.session_state.is_capturing else None

def _get_packets():
    """Get latest packets from engine (if capturing) or session state."""
    if st.session_state.is_capturing and st.session_state.engine:
        return list(st.session_state.engine.packets)
    return st.session_state.packets

# Update session state for non-fragment tabs
if st.session_state.is_capturing and st.session_state.engine:
    st.session_state.packets = list(st.session_state.engine.packets)

packets = st.session_state.packets

if not packets and not st.session_state.is_capturing:
    st.markdown('<div class="main-header">🛡️ NetSentinel</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">AI-Powered Real-Time Network Traffic Analyzer & Threat Detector</div>', unsafe_allow_html=True)
    st.info("Select a mode from the sidebar to begin.")
    st.stop()

df = pd.DataFrame(packets) if packets else pd.DataFrame()

st.markdown('<div class="main-header">🛡️ NetSentinel Dashboard</div>', unsafe_allow_html=True)

if st.session_state.is_capturing:
    if st.session_state.is_spoofing:
        st.markdown("🔴 **LIVE CAPTURE + ARP SPOOFING ACTIVE** — Traffic is being redirected through you!")
    else:
        st.markdown("🔴 **LIVE CAPTURE IN PROGRESS** — Auto-refreshing...")

# Live metrics (auto-refreshing fragment during capture)
@st.fragment(run_every=_auto_refresh)
def live_metrics():
    pkts = _get_packets()
    total = len(pkts)
    safe_count = sum(1 for p in pkts if p.get("threat_level") == "safe")
    low_count = sum(1 for p in pkts if p.get("threat_level") == "low")
    med_count = sum(1 for p in pkts if p.get("threat_level") == "medium")
    high_count = sum(1 for p in pkts if p.get("threat_level") == "high")
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric("📦 Total Packets", f"{total:,}")
    with col2:
        st.metric("✅ Safe", f"{safe_count:,}")
    with col3:
        st.metric("🟡 Low Risk", f"{low_count:,}")
    with col4:
        st.metric("🟠 Medium Risk", f"{med_count:,}")
    with col5:
        st.metric("🔴 High Risk", f"{high_count:,}")

live_metrics()

# ─────────────────────────────────────────────
# Tab Layout
# ─────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "📋 Packet Monitor", "📊 Analytics", "🌍 Geo Map",
    "🔍 Packet Inspector", "🚨 Anomalies", "🧬 App Fingerprint"
])

# ── TAB 1: Packet Monitor ──
with tab1:
    @st.fragment(run_every=_auto_refresh)
    def packet_monitor():
        pkts = _get_packets()
        if not pkts:
            st.info("Waiting for packets...")
            return
        df_live = pd.DataFrame(pkts)

        st.markdown("### Live Packet Feed")
        fcol1, fcol2, fcol3 = st.columns(3)
        with fcol1:
            filter_threat = st.multiselect("Threat Level",
                                           ["safe", "low", "medium", "high"],
                                           default=["safe", "low", "medium", "high"],
                                           key="pkt_filter_threat")
        with fcol2:
            if "protocol" in df_live.columns:
                protocols = sorted(df_live["protocol"].unique().tolist())
                filter_proto = st.multiselect("Protocol", protocols, default=protocols,
                                              key="pkt_filter_proto")
            else:
                filter_proto = []
        with fcol3:
            filter_search = st.text_input("Search (IP, service...)", "",
                                          key="pkt_filter_search")

        filtered = df_live
        if "threat_level" in filtered.columns and filter_threat:
            filtered = filtered[filtered["threat_level"].isin(filter_threat)]
        if filter_proto and "protocol" in filtered.columns:
            filtered = filtered[filtered["protocol"].isin(filter_proto)]
        if filter_search:
            search_cols = [c for c in ["src_ip", "dst_ip", "service", "protocol"]
                          if c in filtered.columns]
            if search_cols:
                mask = filtered[search_cols].apply(
                    lambda col: col.astype(str).str.contains(filter_search, case=False)
                ).any(axis=1)
                filtered = filtered[mask]

        display_cols = ["timestamp", "src_ip", "src_port", "dst_ip", "dst_port",
                        "protocol", "service", "size", "threat_level", "threat_score"]
        available_cols = [c for c in display_cols if c in filtered.columns]
        if not filtered.empty:
            display_df = filtered[available_cols].tail(200)
            # Add threat indicator column for visual cue
            if "threat_level" in display_df.columns:
                icons = {"safe": "✅", "low": "🟡", "medium": "🟠", "high": "🔴"}
                display_df = display_df.copy()
                display_df.insert(0, " ", display_df["threat_level"].map(icons).fillna("❓"))

            event = st.dataframe(
                display_df,
                use_container_width=True,
                height=500,
                on_select="rerun",
                selection_mode="single-row",
            )
            st.caption(f"Showing {min(200, len(filtered))} of {len(filtered)} filtered packets — click a row for details")

            # Show Quick View for selected row
            if event and event.selection and event.selection.rows:
                row_num = event.selection.rows[0]
                if row_num < len(display_df):
                    actual_idx = display_df.index[row_num]
                    pkt_data = filtered.loc[actual_idx].to_dict()

                    st.divider()
                    st.markdown("### Quick View")

                    # ── Header row: summary + threat badge ──
                    qcol1, qcol2 = st.columns([3, 1])
                    with qcol1:
                        st.markdown(
                            f"**{pkt_data.get('src_ip', '?')}:{pkt_data.get('src_port', '')}** → "
                            f"**{pkt_data.get('dst_ip', '?')}:{pkt_data.get('dst_port', '')}**"
                        )
                        st.markdown(
                            f"Protocol: `{pkt_data.get('protocol', '?')}` | "
                            f"Service: `{pkt_data.get('service', '?')}` | "
                            f"Size: `{pkt_data.get('size', 0)}B`"
                        )
                    with qcol2:
                        level = str(pkt_data.get("threat_level", "safe"))
                        score = pkt_data.get("threat_score", 0)
                        try:
                            score_str = f"{float(score):.0%}"
                        except (ValueError, TypeError):
                            score_str = str(score)
                        st.markdown(
                            f'<div class="threat-{level}">'
                            f'THREAT: {level.upper()}<br>{score_str}</div>',
                            unsafe_allow_html=True,
                        )

                    # ── AI Explanation ──
                    expl = pkt_data.get("explanation", "")
                    if expl:
                        st.info(str(expl))

                    # ── Full packet details ──
                    dcol1, dcol2 = st.columns(2)
                    with dcol1:
                        st.markdown("**Packet Details**")
                        details = {
                            "Timestamp": pkt_data.get("timestamp", ""),
                            "Frame Size": f"{pkt_data.get('size', 0)} bytes",
                            "Source MAC": pkt_data.get("src_mac", "N/A"),
                            "Dest MAC": pkt_data.get("dst_mac", "N/A"),
                            "IP Version": pkt_data.get("ip_version", "N/A"),
                            "TTL": pkt_data.get("ttl", "N/A"),
                            "TCP Flags": pkt_data.get("tcp_flags", "N/A"),
                            "TCP Seq": pkt_data.get("tcp_seq", "N/A"),
                            "TCP Ack": pkt_data.get("tcp_ack", "N/A"),
                            "Window Size": pkt_data.get("window_size", "N/A"),
                            "ICMP Type": pkt_data.get("icmp_type", "N/A"),
                            "DNS Query": pkt_data.get("dns_query", "N/A"),
                            "Payload Size": f"{pkt_data.get('payload_size', 0)} bytes",
                        }
                        for k, v in details.items():
                            if str(v) not in ("N/A", "None"):
                                st.markdown(f"`{k}:` **{v}**")

                    with dcol2:
                        st.markdown("**Geography**")
                        st.markdown(
                            f"Src: {pkt_data.get('src_city', '?')}, "
                            f"{pkt_data.get('src_country', '?')} "
                            f"({pkt_data.get('src_isp', '?')})"
                        )
                        st.markdown(
                            f"Dst: {pkt_data.get('dst_city', '?')}, "
                            f"{pkt_data.get('dst_country', '?')} "
                            f"({pkt_data.get('dst_isp', '?')})"
                        )
                        # Threat flags
                        flags = pkt_data.get("threat_flags", [])
                        if flags and isinstance(flags, list) and len(flags) > 0:
                            st.markdown("**Threat Flags**")
                            for fl in flags:
                                st.markdown(f"- {fl}")

                    # ── Protocol layers ──
                    pkt_layers = pkt_data.get("layers", [])
                    if pkt_layers and isinstance(pkt_layers, list):
                        st.markdown("**Protocol Layers**")
                        for layer in pkt_layers:
                            if isinstance(layer, dict):
                                layer_name = layer.get("name", "Unknown")
                                fields = layer.get("fields", {})
                                with st.expander(layer_name, expanded=False):
                                    for fn, fv in fields.items():
                                        st.markdown(f"&nbsp;&nbsp;`{fn}:` **{fv}**")

                    # ── Payload content ──
                    p_hex = pkt_data.get("payload_hex", "")
                    p_text = pkt_data.get("payload_text", "")
                    p_size = pkt_data.get("payload_size", 0)
                    if isinstance(p_hex, str) and p_hex and p_size:
                        with st.expander(f"Payload ({p_size} bytes)", expanded=False):
                            ptab1, ptab2 = st.tabs(["Hex Dump", "Text"])
                            with ptab1:
                                st.code(format_hex_dump(p_hex), language=None)
                            with ptab2:
                                if isinstance(p_text, str) and p_text:
                                    st.code(p_text, language=None)
                                else:
                                    st.caption("No readable text")
        else:
            st.info("No packets match the current filters.")

    packet_monitor()

# ── TAB 2: Analytics ──
with tab2:
    st.markdown("### Traffic Analytics")
    acol1, acol2 = st.columns(2)
    with acol1:
        if "protocol" in df.columns:
            proto_counts = df["protocol"].value_counts()
            fig = px.pie(
                values=proto_counts.values,
                names=proto_counts.index,
                title="Protocol Distribution",
                color_discrete_sequence=px.colors.qualitative.Set2,
                hole=0.4,
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
    with acol2:
        if "threat_level" in df.columns:
            threat_counts = df["threat_level"].value_counts()
            color_map = {"safe": "#4CAF50", "low": "#FFC107", "medium": "#FF9800", "high": "#F44336"}
            fig = px.bar(
                x=threat_counts.index,
                y=threat_counts.values,
                title="Threat Level Distribution",
                color=threat_counts.index,
                color_discrete_map=color_map,
                labels={"x": "Threat Level", "y": "Packet Count"},
            )
            fig.update_layout(height=400, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)

    if "service" in df.columns:
        svc_counts = df["service"].value_counts().head(15)
        fig = px.bar(
            x=svc_counts.values,
            y=svc_counts.index,
            orientation="h",
            title="Top 15 Services",
            labels={"x": "Packet Count", "y": "Service"},
            color=svc_counts.values,
            color_continuous_scale="Blues",
        )
        fig.update_layout(height=450, showlegend=False)
        st.plotly_chart(fig, use_container_width=True)

    tcol1, tcol2 = st.columns(2)
    with tcol1:
        if "src_ip" in df.columns:
            top_src = df["src_ip"].value_counts().head(10)
            fig = px.bar(x=top_src.index, y=top_src.values,
                         title="Top 10 Source IPs",
                         labels={"x": "IP Address", "y": "Packets"})
            fig.update_layout(height=350)
            st.plotly_chart(fig, use_container_width=True)
    with tcol2:
        if "dst_ip" in df.columns:
            top_dst = df["dst_ip"].value_counts().head(10)
            fig = px.bar(x=top_dst.index, y=top_dst.values,
                         title="Top 10 Destination IPs",
                         labels={"x": "IP Address", "y": "Packets"})
            fig.update_layout(height=350)
            st.plotly_chart(fig, use_container_width=True)

    if "size" in df.columns:
        fig = px.histogram(df, x="size", nbins=50,
                           title="Packet Size Distribution",
                           labels={"size": "Packet Size (bytes)", "count": "Frequency"},
                           color_discrete_sequence=["#3a7bd5"])
        fig.update_layout(height=350)
        st.plotly_chart(fig, use_container_width=True)

# ── TAB 3: Geo Map ──
with tab3:
    st.markdown("### Geographic Traffic Map")
    geo_data = []
    for p in packets:
        if p.get("dst_lat") and p.get("dst_lon"):
            if p.get("dst_country") not in ("Local", "Unknown") and p["dst_lat"] != 0:
                geo_data.append({
                    "lat": p["dst_lat"],
                    "lon": p["dst_lon"],
                    "ip": p.get("dst_ip", "?"),
                    "country": p.get("dst_country", "?"),
                    "city": p.get("dst_city", "?"),
                    "threat": p.get("threat_level", "safe"),
                    "service": p.get("service", "?"),
                })
        if p.get("src_lat") and p.get("src_lon"):
            if p.get("src_country") not in ("Local", "Unknown") and p["src_lat"] != 0:
                geo_data.append({
                    "lat": p["src_lat"],
                    "lon": p["src_lon"],
                    "ip": p.get("src_ip", "?"),
                    "country": p.get("src_country", "?"),
                    "city": p.get("src_city", "?"),
                    "threat": p.get("threat_level", "safe"),
                    "service": p.get("service", "?"),
                })
    if geo_data:
        geo_df = pd.DataFrame(geo_data)
        color_map = {"safe": "#4CAF50", "low": "#FFC107", "medium": "#FF9800", "high": "#F44336"}
        geo_df["color"] = geo_df["threat"].map(color_map).fillna("#4CAF50")
        fig = px.scatter_geo(
            geo_df,
            lat="lat",
            lon="lon",
            color="threat",
            color_discrete_map=color_map,
            hover_data=["ip", "country", "city", "service"],
            title="Network Traffic Origins & Destinations",
            size_max=15,
        )
        fig.update_geos(
            showcoastlines=True,
            coastlinecolor="RebeccaPurple",
            showland=True,
            landcolor="rgb(30, 30, 50)",
            showocean=True,
            oceancolor="rgb(15, 15, 35)",
            showlakes=False,
            bgcolor="rgb(10, 10, 25)",
        )
        fig.update_layout(
            height=600,
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            geo=dict(bgcolor="rgb(10, 10, 25)"),
        )
        st.plotly_chart(fig, use_container_width=True)

        country_counts = geo_df["country"].value_counts().head(10)
        fig2 = px.bar(x=country_counts.index, y=country_counts.values,
                      title="Top 10 Countries by Traffic",
                      labels={"x": "Country", "y": "Connections"},
                      color_discrete_sequence=["#3a7bd5"])
        fig2.update_layout(height=350)
        st.plotly_chart(fig2, use_container_width=True)
    else:
        st.info("No geographic data available. Start a capture or load traffic data.")

# ── TAB 4: Packet Inspector ──
with tab4:
    st.markdown("### AI-Powered Packet Inspector")
    st.markdown("Search and select any packet for full AI analysis, ML prediction, and content view.")
    if packets:
        # Filters
        insp_col1, insp_col2, insp_col3 = st.columns(3)
        with insp_col1:
            insp_search = st.text_input("Search (IP, service, port...)", "", key="insp_search")
        with insp_col2:
            insp_threat = st.multiselect(
                "Threat Level", ["safe", "low", "medium", "high"],
                default=["safe", "low", "medium", "high"], key="insp_threat",
            )
        with insp_col3:
            all_protos = sorted(set(p.get("protocol", "") for p in packets if p.get("protocol")))
            insp_proto = st.multiselect("Protocol", all_protos, default=all_protos, key="insp_proto")

        filtered_pkts = packets
        if insp_threat:
            filtered_pkts = [p for p in filtered_pkts if p.get("threat_level", "safe") in insp_threat]
        if insp_proto:
            filtered_pkts = [p for p in filtered_pkts if p.get("protocol", "") in insp_proto]
        if insp_search:
            _s = insp_search.lower()
            filtered_pkts = [
                p for p in filtered_pkts
                if _s in str(p.get("src_ip", "")).lower()
                or _s in str(p.get("dst_ip", "")).lower()
                or _s in str(p.get("service", "")).lower()
                or _s in str(p.get("protocol", "")).lower()
                or _s in str(p.get("dst_port", ""))
            ]

        recent = filtered_pkts[-500:]
        if recent:
            options = []
            for i, p in enumerate(recent):
                threat_icon = {"safe": "✅", "low": "🟡", "medium": "🟠", "high": "🔴"}.get(
                    p.get("threat_level", "safe"), "❓"
                )
                label = (
                    f"{threat_icon} {p.get('src_ip', '?')}:{p.get('src_port', '')} → "
                    f"{p.get('dst_ip', '?')}:{p.get('dst_port', '')} "
                    f"[{p.get('protocol', '?')}/{p.get('service', '?')}] "
                    f"({p.get('size', 0)}B)"
                )
                options.append(label)

            # Pre-select packet clicked in monitor tab
            default_idx = len(options) - 1
            inspected = st.session_state.get("inspected_packet")
            if inspected:
                # Match on epoch (unique float timestamp) — most reliable
                insp_epoch = str(inspected.get("epoch", ""))
                insp_ts = str(inspected.get("timestamp", ""))
                insp_src = str(inspected.get("src_ip", ""))
                for i, p in enumerate(recent):
                    if str(p.get("epoch", "")) == insp_epoch:
                        default_idx = i
                        break
                    # Fallback: match on timestamp + src_ip
                    if (str(p.get("timestamp", "")) == insp_ts
                            and str(p.get("src_ip", "")) == insp_src):
                        default_idx = i
                        break

            selected_idx = st.selectbox("Select a packet", range(len(options)),
                                        format_func=lambda i: options[i],
                                        index=default_idx)
            st.caption(f"{len(recent)} of {len(filtered_pkts)} packets match filters")
        else:
            selected_idx = None
            st.warning("No packets match filters. Try adjusting your search.")

        if selected_idx is not None and recent:
            pkt = recent[selected_idx]
            explainer = st.session_state.explainer
            # Get real flow features for ML prediction
            flow_features = None
            engine = st.session_state.engine
            if engine and hasattr(engine, "flow_agg"):
                flow_features = engine.flow_agg.get_flow_features(pkt)
            explanation = explainer.explain_packet(pkt, flow_features=flow_features)
            level = pkt.get("threat_level", "safe")
            st.markdown(f'<div class="threat-{level}">'
                        f'THREAT LEVEL: {level.upper()} — Score: {pkt.get("threat_score", 0):.0%}'
                        f'</div>', unsafe_allow_html=True)
            st.markdown("")

            # ── Sub-tabs for organized view ──
            detail_tab, dissect_tab, ai_tab, content_tab = st.tabs([
                "📦 Details & Geo", "🔬 Protocol Dissection",
                "🤖 AI Analysis", "📄 Packet Content"
            ])

            # ── Details & Geo ──
            with detail_tab:
                icol1, icol2 = st.columns(2)
                with icol1:
                    st.markdown("#### 📦 Packet Details")
                    details = {
                        "Timestamp": pkt.get("timestamp", ""),
                        "Frame Size": f"{pkt.get('size', 0)} bytes",
                        "Source MAC": pkt.get("src_mac", "N/A"),
                        "Destination MAC": pkt.get("dst_mac", "N/A"),
                        "Source IP": f"{pkt.get('src_ip', '?')}:{pkt.get('src_port', '')}",
                        "Destination IP": f"{pkt.get('dst_ip', '?')}:{pkt.get('dst_port', '')}",
                        "Protocol": pkt.get("protocol", "?"),
                        "Service": pkt.get("service", "?"),
                        "IP Version": pkt.get("ip_version", "?"),
                        "TTL / Hop Limit": pkt.get("ttl", "?"),
                        "TCP Flags": pkt.get("tcp_flags", "N/A"),
                        "TCP Sequence": pkt.get("tcp_seq", "N/A"),
                        "TCP Ack": pkt.get("tcp_ack", "N/A"),
                        "Window Size": pkt.get("window_size", "N/A"),
                        "ICMP Type": pkt.get("icmp_type", "N/A"),
                        "ICMP Code": pkt.get("icmp_code", "N/A"),
                        "DNS Query": pkt.get("dns_query", "N/A"),
                        "Payload Size": f"{pkt.get('payload_size', 0)} bytes",
                    }
                    # Filter out N/A fields for cleanliness
                    for k, v in details.items():
                        if str(v) not in ("N/A", "None"):
                            st.markdown(f"**{k}:** `{v}`")
                with icol2:
                    st.markdown("#### 🌍 Geographic Info")
                    st.markdown(explanation.get("geo_info", "No geo data"))
                    st.markdown("#### 📡 Protocol Info")
                    st.markdown(explanation.get("protocol_info", ""))

            # ── Protocol Dissection (Wireshark-like) ──
            with dissect_tab:
                st.markdown("#### 🔬 Protocol Layer Dissection")
                pkt_layers = pkt.get("layers", [])
                if pkt_layers:
                    for i, layer in enumerate(pkt_layers):
                        layer_name = layer.get("name", f"Layer {i}")
                        fields = layer.get("fields", {})
                        with st.expander(f"**Layer {i+1}: {layer_name}**", expanded=(i < 2)):
                            for field_name, field_val in fields.items():
                                st.markdown(f"&nbsp;&nbsp;&nbsp;&nbsp;**{field_name}:** `{field_val}`")
                    # Flow info if available
                    if flow_features:
                        with st.expander("**Flow Statistics** (aggregated)", expanded=False):
                            fcol1, fcol2 = st.columns(2)
                            with fcol1:
                                st.markdown(f"**Duration:** `{flow_features.get('dur', 0):.3f}s`")
                                st.markdown(f"**Fwd Packets:** `{flow_features.get('spkts', 0)}`")
                                st.markdown(f"**Bwd Packets:** `{flow_features.get('dpkts', 0)}`")
                                st.markdown(f"**Fwd Bytes:** `{flow_features.get('sbytes', 0)}`")
                                st.markdown(f"**Bwd Bytes:** `{flow_features.get('dbytes', 0)}`")
                                st.markdown(f"**Rate:** `{flow_features.get('rate', 0):.1f} pkt/s`")
                            with fcol2:
                                st.markdown(f"**Fwd Jitter:** `{flow_features.get('sjit', 0):.2f}ms`")
                                st.markdown(f"**Bwd Jitter:** `{flow_features.get('djit', 0):.2f}ms`")
                                st.markdown(f"**TCP RTT:** `{flow_features.get('tcprtt', 0):.4f}s`")
                                st.markdown(f"**SYN-ACK:** `{flow_features.get('synack', 0):.4f}s`")
                                st.markdown(f"**Fwd Load:** `{flow_features.get('sload', 0):.0f} bps`")
                                st.markdown(f"**Bwd Load:** `{flow_features.get('dload', 0):.0f} bps`")
                else:
                    st.info("No layer dissection available for this packet. Layer data is captured during live capture.")

            # ── AI Analysis ──
            with ai_tab:
                st.markdown("#### 🤖 AI Explanation")
                st.info(explanation.get("summary", "No explanation available"))
                st.markdown("#### 🛡️ Threat Assessment")
                st.markdown(explanation.get("threat_assessment", ""))
                ml = explanation.get("ml_prediction")
                if ml:
                    st.markdown("#### 🔮 ML Model Prediction")
                    if ml.get("prediction") == "Pending":
                        st.info(ml.get("note", "Collecting flow data..."))
                    elif ml.get("prediction") != "Unknown":
                        pred = ml["prediction"]
                        if pred == "Attack":
                            pred_icon = "🔴"
                        elif pred == "Suspicious":
                            pred_icon = "🟠"
                        else:
                            pred_icon = "🟢"
                        pcol1, pcol2, pcol3 = st.columns(3)
                        with pcol1:
                            st.metric("Prediction", f"{pred_icon} {pred}")
                        with pcol2:
                            st.metric("Confidence", f"{ml.get('confidence', 0):.1%}")
                        with pcol3:
                            st.metric("Attack Prob", f"{ml.get('attack_probability', 0):.1%}")
                        if ml.get("ensemble"):
                            with st.expander("Ensemble Details"):
                                ecol1, ecol2 = st.columns(2)
                                with ecol1:
                                    st.markdown(f"**XGBoost:** {ml.get('xgb_verdict', '?')}")
                                with ecol2:
                                    iso_v = ml.get('iso_verdict', '?')
                                    iso_s = ml.get('iso_score', 0)
                                    st.markdown(f"**Isolation Forest:** {iso_v} (score: {iso_s:.3f})")
                        if "top_contributing_features" in ml:
                            st.markdown("**Top Contributing Features (SHAP):**")
                            for feat in ml["top_contributing_features"]:
                                direction = "🔺" if feat["impact"] > 0 else "🔻"
                                st.markdown(
                                    f" {direction} **{feat['feature']}** — {feat['direction']} "
                                    f"(impact: {feat['impact']:.4f})"
                                )
                st.markdown("#### 💡 Recommendations")
                for rec in explanation.get("recommendations", []):
                    st.markdown(f"• {rec}")

            # ── Packet Content ──
            with content_tab:
                st.markdown("#### 📄 Packet Content")
                payload_hex = pkt.get("payload_hex", pkt.get("payload_preview", ""))
                payload_text = pkt.get("payload_text", "")
                payload_size = pkt.get("payload_size", 0)

                if payload_size > 0 and payload_hex:
                    st.markdown(f"**Payload Size:** {payload_size} bytes")
                    ctab1, ctab2, ctab3 = st.tabs(["Hex Dump", "Text / ASCII", "Raw Hex"])
                    with ctab1:
                        st.code(format_hex_dump(payload_hex), language=None)
                    with ctab2:
                        if payload_text:
                            st.code(payload_text, language=None)
                        else:
                            st.info("No readable text content in this packet")
                    with ctab3:
                        formatted_hex = " ".join(
                            payload_hex[i:i+2] for i in range(0, len(payload_hex), 2)
                        )
                        st.code(formatted_hex, language=None)
                else:
                    st.info("No payload data in this packet (headers only)")

# ── TAB 5: Anomalies ──
with tab5:
    st.markdown("### 🚨 Flow-Level Anomaly Detection")
    flow_agg = FlowAggregator()
    for p in packets:
        flow_agg.add_packet(p)
    anomalies = flow_agg.detect_anomalies()
    summary = flow_agg.get_summary()
    scol1, scol2, scol3 = st.columns(3)
    with scol1:
        st.metric("Total Flows", summary["total_flows"])
    with scol2:
        st.metric("Total Data", f"{summary['total_bytes'] / 1024:.1f} KB")
    with scol3:
        st.metric("Anomalies Detected", len(anomalies))
    if anomalies:
        st.markdown("### Detected Anomalies")
        for i, anom in enumerate(anomalies):
            severity_color = {"high": "🔴", "medium": "🟠", "low": "🟡"}.get(
                anom.get("severity", "low"), "⚪"
            )
            with st.expander(
                f"{severity_color} [{anom['severity'].upper()}] {anom['type']} — {anom.get('flow_key', '')}"
            ):
                st.markdown(f"**Detail:** {anom.get('detail', '')}")
                if "ports" in anom:
                    st.markdown(f"**Unique ports contacted:** {anom['ports']}")
                if anom["type"] == "Port Scan":
                    st.warning("**Recommendation:** This is a common reconnaissance technique. Ensure unused ports are closed and consider rate-limiting connections from this source.")
                elif anom["type"] == "SYN Flood":
                    st.error("**Recommendation:** Potential Denial of Service attack. Consider enabling SYN cookies, rate-limiting, or blocking the source IP.")
                elif anom["type"] == "High Traffic Rate":
                    st.warning("**Recommendation:** Unusually high packet rate detected. This could be a DDoS attack or simply high-bandwidth usage. Investigate the traffic content and source.")
    else:
        st.success("✅ No flow-level anomalies detected. Traffic patterns appear normal.")

    st.markdown("### Active Flows")
    flow_data = []
    for key, flow in flow_agg.flows.items():
        duration = (flow["last_time"] or time.time()) - (flow["start_time"] or time.time())
        flow_data.append({
            "Flow": key,
            "Packets": flow["packet_count"],
            "Bytes": flow["total_bytes"],
            "Duration (s)": round(duration, 1),
            "Protocol": flow["protocol"],
            "Unique Ports": len(flow["ports_contacted"]),
        })
    if flow_data:
        flow_df = pd.DataFrame(flow_data)
        flow_df = flow_df.sort_values("Packets", ascending=False)
        st.dataframe(flow_df, use_container_width=True, height=400)

# ── TAB 6: App Fingerprinting ──
# ── TAB 6: App Fingerprinting ──
with tab6:
    @st.fragment(run_every=_auto_refresh)
    def app_fingerprint():
        st.markdown("### 🧬 AI App Fingerprinting")
        st.markdown("Identifies which app generated the captured traffic using an ensemble of XGBoost and LightGBM — without decrypting anything.")

        _fp_packets = _get_packets()
        if not _fp_packets:
            st.info("Start a capture or load traffic data to identify apps.")
            return
        if not st.session_state.fingerprinter.xgb_model:
            st.warning("App fingerprinting models not found. Train the model first:\n\n`python train_app_fingerprint.py`")
            return

        fp = st.session_state.fingerprinter
        WINDOW_SEC = 2.0   # match collector training window (was 3.5)
        STEP_SEC = 0.5     # match collector step (was 1.5)
        CHUNK_SIZE = 150   # count-based fallback chunk size

        # ── IP filter ────────────────────────────────────────────────────────
        # Build list of unique IPs seen in this capture for the dropdown
        all_ips = sorted(set(
            ip
            for p in _fp_packets
            for ip in (p.get("src_ip", ""), p.get("dst_ip", ""))
            if ip and not ip.startswith(("0.", "255.", "224.", "239.", "ff0"))
        ))
        ficol1, ficol2 = st.columns([2, 3])
        with ficol1:
            filter_mode = st.radio("Track", ["All traffic", "Specific IP"],
                                   horizontal=True, key="fp_filter_mode")
        with ficol2:
            if filter_mode == "Specific IP":
                typed_ip = st.text_input("IP address", placeholder="e.g. 192.168.1.42",
                                         key="fp_ip_input")
                matched = [ip for ip in all_ips if typed_ip and typed_ip in ip]
                if matched and typed_ip not in matched:
                    st.caption(f"Suggestions: {', '.join(matched[:5])}")
                target_ip = typed_ip.strip()
            else:
                target_ip = ""

        if filter_mode == "Specific IP":
            if not target_ip:
                st.info("Enter an IP address above to track a specific device.")
                return
            _fp_packets = [
                p for p in _fp_packets
                if p.get("src_ip") == target_ip or p.get("dst_ip") == target_ip
            ]
            if not _fp_packets:
                st.warning(f"No packets found for IP **{target_ip}**. "
                           f"Available IPs: {', '.join(all_ips[:10])}")
                return
            st.success(f"Tracking **{target_ip}** — {len(_fp_packets):,} packets")

        sorted_pkts = sorted(_fp_packets, key=lambda p: p.get("epoch", 0))
        if len(sorted_pkts) <= 10:
            st.info("Need more packets for app fingerprinting. Keep capturing...")
            return

        start_t = sorted_pkts[0].get("epoch", 0)
        end_t = sorted_pkts[-1].get("epoch", 0)
        duration = end_t - start_t
        window_results = []

        if duration >= WINDOW_SEC:
            ws = start_t
            while ws + WINDOW_SEC <= end_t:
                we = ws + WINDOW_SEC
                window_pkts = [p for p in sorted_pkts if ws <= p.get("epoch", 0) < we]
                if len(window_pkts) >= 5:
                    result = fp.predict(window_pkts)
                    if result and "error" not in result:
                        result["time"] = pd.Timestamp.fromtimestamp(ws).strftime("%H:%M:%S")
                        result["n_packets"] = len(window_pkts)
                        window_results.append(result)
                ws += STEP_SEC
        else:
            for chunk_start in range(0, len(sorted_pkts), CHUNK_SIZE):
                window_pkts = sorted_pkts[chunk_start:chunk_start + CHUNK_SIZE]
                if len(window_pkts) >= 5:
                    ts = window_pkts[0].get("epoch", 0)
                    result = fp.predict(window_pkts)
                    if result and "error" not in result:
                        label = f"#{chunk_start//CHUNK_SIZE + 1}" if ts == 0 else \
                                pd.Timestamp.fromtimestamp(ts).strftime("%H:%M:%S")
                        result["time"] = label
                        result["n_packets"] = len(window_pkts)
                        window_results.append(result)

        if not window_results:
            st.info("Not enough traffic captured for app fingerprinting. Capture for at least 30 seconds.")
            return

        from collections import Counter

        # ── Rolling majority vote ─────────────────────────────────────────────
        VOTE_WINDOW = 15
        MIN_VOTE_SHARE = 0.55  # 55% of non-Unknown windows must agree

        def _rolling_vote(results, k):
            """Simple count majority over the last k windows."""
            smoothed = []
            for i in range(len(results)):
                bucket = results[max(0, i - k + 1): i + 1]
                votes = {}
                for b in bucket:
                    app = b["xgb_app"]
                    if app == "Unknown":
                        continue
                    votes[app] = votes.get(app, 0) + 1
                if votes:
                    winner = max(votes, key=votes.get)
                    score = votes[winner] / sum(votes.values())
                else:
                    winner, score = "Unknown", 0.0
                smoothed.append({"app": winner, "score": score, "n_votes": len(bucket)})
            return smoothed

        smoothed = _rolling_vote(window_results, VOTE_WINDOW)
        current = smoothed[-1]
        
        if current["score"] < MIN_VOTE_SHARE:
            current = {"app": "Uncertain", "score": current["score"], "n_votes": current["n_votes"]}

        # ── Current verdict banner ────────────────────────────────────────────
        if current["app"] in ("Unknown", "Uncertain"):
            verdict_color = "#9E9E9E"
            label = "Uncertain — not enough traffic or model not confident"
        else:
            verdict_color = "#4CAF50"
            label = f"{current['score']:.0%} vote share · {current['n_votes']} windows"
        st.markdown(
            f"<div style='background:{verdict_color}22;border:2px solid {verdict_color};"
            f"border-radius:12px;padding:16px 24px;margin-bottom:16px'>"
            f"<span style='font-size:1.1em;color:#aaa'>Current App</span><br>"
            f"<span style='font-size:2.2em;font-weight:700;color:{verdict_color}'>"
            f"{current['app'].upper()}</span>"   
            f"<span style='font-size:1em;color:#aaa;margin-left:16px'>{label}</span>"
            f"</div>",
            unsafe_allow_html=True,
        )

        # ── Summary metrics ──
        fcol1, fcol2, fcol3, fcol4 = st.columns(4)
        xgb_apps = [r["xgb_app"] for r in window_results if r["xgb_app"] != "Unknown"]
        most_common_xgb = Counter(xgb_apps).most_common(1)[0] if xgb_apps else ("—", 0)
        with fcol1:
            st.metric("XGBoost Dominant", most_common_xgb[0].upper())
        with fcol2:
            avg_xgb_conf = np.mean([r["xgb_confidence"] for r in window_results])
            st.metric("Avg XGBoost Conf", f"{avg_xgb_conf:.1%}")
        with fcol3:
            st.metric("Total Windows", len(window_results))
        with fcol4:
            unknown_pct = sum(1 for r in window_results if r["xgb_app"] == "Unknown") / len(window_results)
            st.metric("Unknown Windows", f"{unknown_pct:.0%}")

        # ── Timeline with smoothed column ─────────────────────────────────────
        st.markdown("### 📈 App Detection Timeline")
        timeline_data = []
        for i, r in enumerate(window_results):
            row = {
                "Time": r["time"],
                "Pkts": r["n_packets"],
                "XGBoost": r["xgb_app"],
                "XGB Conf": f"{r['xgb_confidence']:.1%}",
                "Smoothed": smoothed[i]["app"],
                "Vote Share": f"{smoothed[i]['score']:.0%}",
            }
            if "lgbm_app" in r:
                row["LightGBM"] = r["lgbm_app"]
                row["LGBM Conf"] = f"{r['lgbm_confidence']:.1%}"
            if "ensemble_app" in r:
                row["Ensemble"] = r["ensemble_app"]
                row["Ens Conf"] = f"{r['ensemble_confidence']:.1%}"
            timeline_data.append(row)
        st.dataframe(pd.DataFrame(timeline_data), use_container_width=True, height=400)

        # ── Confidence chart ──
        st.markdown("### 📊 Model Confidence Over Time")
        chart_data = pd.DataFrame({
            "Time": [r["time"] for r in window_results],
            "XGBoost": [r["xgb_confidence"] for r in window_results],
        })
        if "lgbm_confidence" in window_results[0]:
            chart_data["LightGBM"] = [r["lgbm_confidence"] for r in window_results]
        if "ensemble_confidence" in window_results[0]:
            chart_data["Ensemble"] = [r["ensemble_confidence"] for r in window_results]

        fig = go.Figure()
        fig.add_trace(go.Scatter(x=chart_data["Time"], y=chart_data["XGBoost"],
            mode="lines+markers", name="XGBoost", line=dict(color="#2196F3", width=2)))
        
        if "LightGBM" in chart_data:
            fig.add_trace(go.Scatter(x=chart_data["Time"], y=chart_data["LightGBM"],
                mode="lines+markers", name="LightGBM", line=dict(color="#4CAF50", width=2)))
                
        if "Ensemble" in chart_data:
            fig.add_trace(go.Scatter(x=chart_data["Time"], y=chart_data["Ensemble"],
                mode="lines+markers", name="Ensemble", line=dict(color="#FF9800", width=2, dash="dot")))
                
        fig.update_layout(height=400, yaxis_title="Confidence", xaxis_title="Time",
                          yaxis=dict(range=[0, 1.05]), template="plotly_white")
        st.plotly_chart(fig, use_container_width=True)

        # ── Per-window detail ──
        st.markdown("### 🔍 Detailed Window Analysis")
        selected_win = st.selectbox("Select a window", range(len(window_results)),
            format_func=lambda i: f"Window {i+1} @ {window_results[i]['time']} — "
                                  f"XGB: {window_results[i]['xgb_app']} ({window_results[i]['xgb_confidence']:.0%})"
                                  + (f" | LGBM: {window_results[i]['lgbm_app']} ({window_results[i]['lgbm_confidence']:.0%})"
                                     if 'lgbm_app' in window_results[i] else ""))

        if selected_win is not None:
            wr = window_results[selected_win]
            dcol1, dcol2 = st.columns(2)
            
            with dcol1:
                st.markdown("#### 🚀 XGBoost Prediction")
                st.markdown(f"**App: {wr['xgb_app'].upper()}** — {wr['xgb_confidence']:.1%} confidence")
                if "xgb_all_probs" in wr:
                    for app, prob in sorted(wr["xgb_all_probs"].items(), key=lambda x: x[1], reverse=True):
                        bar = int(prob * 100)
                        st.markdown(f"`{app:20s}` {'█' * max(bar//3, 0)}{'░' * max(33 - bar//3, 0)} {prob:.1%}")
                        
            if "lgbm_app" in wr:
                with dcol2:
                    st.markdown("#### ⚡ LightGBM Prediction")
                    st.markdown(f"**App: {wr['lgbm_app'].upper()}** — {wr['lgbm_confidence']:.1%} confidence")
                    if "lgbm_all_probs" in wr:
                        for app, prob in sorted(wr["lgbm_all_probs"].items(), key=lambda x: x[1], reverse=True):
                            bar = int(prob * 100)
                            st.markdown(f"`{app:20s}` {'█' * max(bar//3, 0)}{'░' * max(33 - bar//3, 0)} {prob:.1%}")
                            
            if "ensemble_app" in wr:
                st.markdown("---")
                if wr["xgb_app"] == wr.get("lgbm_app", ""):
                    st.success(f"✅ **Both models agree: {wr['ensemble_app'].upper()}** (Ensemble confidence: {wr['ensemble_confidence']:.1%})")
                else:
                    st.warning(f"⚠️ **Models disagree** — XGBoost: **{wr['xgb_app']}**, LightGBM: **{wr.get('lgbm_app', '?')}**. Ensemble: **{wr['ensemble_app'].upper()}** ({wr['ensemble_confidence']:.1%})")

    app_fingerprint()
# Auto-refresh is handled by @st.fragment(run_every=...) above.
# No more time.sleep() — fragments update independently without freezing the UI.