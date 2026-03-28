"""
NetSentinel - AI Explanation Engine
Generates intelligent, human-readable explanations for network traffic.
Combines rule-based templates with ML model predictions and SHAP values.
"""

import os
import joblib
import numpy as np
import pandas as pd

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models")


class AIExplainer:
    """Generates AI-powered explanations for network packets.
    Uses XGBoost + Isolation Forest ensemble on real flow-level features."""

    def __init__(self):
        self.model = None
        self.isolation_forest = None
        self.scaler = None
        self.feature_names = None
        self.shap_explainer = None
        self._load_models()

    def _load_models(self):
        """Load trained models if available."""
        try:
            model_path = os.path.join(MODEL_DIR, "xgboost.pkl")
            if os.path.exists(model_path):
                self.model = joblib.load(model_path)
                self.scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.pkl"))
                self.feature_names = joblib.load(os.path.join(MODEL_DIR, "feature_names.pkl"))
                print("  ✅ XGBoost model loaded successfully")

                # Load Isolation Forest for ensemble
                iso_path = os.path.join(MODEL_DIR, "isolation_forest.pkl")
                if os.path.exists(iso_path):
                    self.isolation_forest = joblib.load(iso_path)
                    print("  ✅ Isolation Forest loaded (ensemble mode)")

                shap_path = os.path.join(MODEL_DIR, "shap_explainer.pkl")
                if os.path.exists(shap_path) and SHAP_AVAILABLE:
                    self.shap_explainer = joblib.load(shap_path)
                    print("  ✅ SHAP explainer loaded")
            else:
                print("  ⚠️ No trained model found. Using rule-based analysis only.")
                print("     Run 'python train_model.py' to train the ML model.")
        except Exception as e:
            print(f"  ⚠️ Model loading failed: {e}")

    def explain_packet(self, pkt_info: dict, flow_features: dict = None) -> dict:
        """Generate comprehensive explanation for a packet.

        Args:
            pkt_info: Parsed packet info dict.
            flow_features: Real aggregated flow features from FlowAggregator.
                           If None, ML prediction is skipped (avoids false positives).
        """
        explanation = {
            "summary": pkt_info.get("explanation", ""),
            "threat_assessment": self._assess_threat(pkt_info),
            "protocol_info": self._explain_protocol(pkt_info),
            "geo_info": self._explain_geography(pkt_info),
            "recommendations": self._get_recommendations(pkt_info),
        }

        # ML prediction only when we have real flow data
        if self.model and flow_features:
            ml_result = self._ml_predict(flow_features)
            explanation["ml_prediction"] = ml_result
        elif self.model and not flow_features:
            explanation["ml_prediction"] = {
                "prediction": "Pending",
                "note": "Collecting flow data for accurate prediction...",
            }

        return explanation

    def _assess_threat(self, info: dict) -> str:
        """Generate threat assessment text."""
        score = info.get("threat_score", 0)
        level = info.get("threat_level", "safe")
        flags = info.get("threat_flags", [])

        if level == "safe":
            return (
                "✅ SAFE — This packet appears to be normal network traffic. "
                "No suspicious patterns or indicators were detected."
            )
        elif level == "low":
            return (
                f"🟡 LOW RISK (Score: {score:.0%}) — Minor suspicious indicators detected: "
                f"{'; '.join(flags)}. This could be normal behavior but worth monitoring."
            )
        elif level == "medium":
            return (
                f"🟠 MEDIUM RISK (Score: {score:.0%}) — Suspicious activity detected: "
                f"{'; '.join(flags)}. This traffic pattern warrants closer inspection. "
                f"Consider checking the source IP and correlating with other traffic."
            )
        else:
            return (
                f"🔴 HIGH RISK (Score: {score:.0%}) — Potentially malicious traffic detected: "
                f"{'; '.join(flags)}. Immediate investigation recommended. "
                f"This pattern is consistent with known attack signatures."
            )

    def _explain_protocol(self, info: dict) -> str:
        """Explain the protocol being used."""
        proto = info.get("protocol", "Unknown")
        service = info.get("service", "Unknown")

        protocol_info = {
            "TCP": (
                "TCP (Transmission Control Protocol) — A connection-oriented protocol that ensures "
                "reliable, ordered delivery of data. Used for most internet traffic including web "
                "browsing, email, and file transfers."
            ),
            "UDP": (
                "UDP (User Datagram Protocol) — A connectionless protocol that sends data without "
                "establishing a connection first. Faster but less reliable than TCP. Used for DNS, "
                "streaming, gaming, and VoIP."
            ),
            "ICMP": (
                "ICMP (Internet Control Message Protocol) — Used for network diagnostics and error "
                "reporting. Common uses include ping (testing connectivity) and traceroute (mapping "
                "network paths)."
            ),
            "ARP": (
                "ARP (Address Resolution Protocol) — Maps IP addresses to physical MAC addresses "
                "on a local network. Essential for LAN communication."
            ),
        }

        service_info = {
            "HTTP": "Unencrypted web traffic (port 80). Data is transmitted in plaintext.",
            "HTTPS": "Encrypted web traffic (port 443). Secured with TLS/SSL encryption.",
            "DNS": "Domain Name System — translates domain names (like google.com) to IP addresses.",
            "SSH": "Secure Shell — encrypted remote access to servers and systems.",
            "FTP": "File Transfer Protocol — used for transferring files. Note: FTP is unencrypted.",
            "SMTP": "Simple Mail Transfer Protocol — used for sending email.",
            "RDP": "Remote Desktop Protocol — Microsoft's remote desktop access. Often targeted by attackers.",
            "SMB": "Server Message Block — Windows file/printer sharing. Historically vulnerable to attacks.",
        }

        result = protocol_info.get(proto, f"{proto} protocol.")
        if service in service_info:
            result += f"\n\nService: {service} — {service_info[service]}"

        return result

    def _explain_geography(self, info: dict) -> str:
        """Explain geographic information."""
        src_ip = info.get("src_ip", "?")
        dst_ip = info.get("dst_ip", "?")
        src_country = info.get("src_country", "Unknown")
        dst_country = info.get("dst_country", "Unknown")
        src_city = info.get("src_city", "Unknown")
        dst_city = info.get("dst_city", "Unknown")
        src_isp = info.get("src_isp", "Unknown")
        dst_isp = info.get("dst_isp", "Unknown")

        return (
            f"📍 Source: {src_ip} — {src_city}, {src_country} (ISP: {src_isp})\n"
            f"📍 Destination: {dst_ip} — {dst_city}, {dst_country} (ISP: {dst_isp})"
        )

    def _get_recommendations(self, info: dict) -> list:
        """Generate actionable recommendations."""
        recs = []
        level = info.get("threat_level", "safe")
        service = info.get("service", "")
        flags = info.get("threat_flags", [])

        if level in ("medium", "high"):
            recs.append("Investigate the source IP address for known malicious activity")
            recs.append("Check firewall logs for similar traffic patterns")
            recs.append("Consider temporarily blocking the source IP if pattern persists")

        if "Port Scan" in str(flags) or "SYN-only" in str(flags):
            recs.append("This may be a reconnaissance attempt — ensure unused ports are closed")
            recs.append("Review firewall rules to limit exposed services")

        if service == "HTTP":
            recs.append("Consider migrating to HTTPS for encrypted communication")

        if service in ("RDP", "VNC", "SSH"):
            recs.append(f"Ensure {service} access is restricted to trusted IPs only")
            recs.append("Use strong authentication and consider MFA")

        if service == "FTP":
            recs.append("FTP transmits credentials in plaintext — consider SFTP instead")

        if not recs:
            recs.append("No immediate action required — traffic appears normal")

        return recs

    # Minimum packets in a flow before we trust the ML prediction
    MIN_FLOW_PACKETS = 3

    def _ml_predict(self, flow_features: dict) -> dict:
        """Run ML ensemble prediction using real flow-level features.

        Uses XGBoost as the primary classifier, with Isolation Forest
        as a second opinion to reduce false positives. Requires minimum
        flow maturity before making a confident prediction.

        Args:
            flow_features: Real aggregated features from FlowAggregator.get_flow_features()
        """
        try:
            # Check flow maturity — single-packet flows are unreliable
            total_pkts = flow_features.get("spkts", 0) + flow_features.get("dpkts", 0)
            is_immature = total_pkts < self.MIN_FLOW_PACKETS

            # Build feature vector from real flow data (no hardcoded defaults)
            feature_vector = []
            for f in self.feature_names:
                feature_vector.append(flow_features.get(f, 0))

            X = pd.DataFrame([feature_vector], columns=self.feature_names)
            X_scaled = pd.DataFrame(
                self.scaler.transform(X),
                columns=self.feature_names
            )

            # Primary: XGBoost classification
            xgb_pred = self.model.predict(X_scaled)[0]
            xgb_proba = self.model.predict_proba(X_scaled)[0]
            xgb_attack_prob = float(xgb_proba[1]) if len(xgb_proba) > 1 else 0

            # Secondary: Isolation Forest anomaly score (if available)
            iso_is_anomaly = False
            iso_score = 0.0
            if self.isolation_forest:
                try:
                    iso_pred = self.isolation_forest.predict(X_scaled)[0]
                    iso_score = float(self.isolation_forest.decision_function(X_scaled)[0])
                    iso_is_anomaly = (iso_pred == -1)
                except Exception:
                    pass

            # For immature flows, bias heavily toward Normal to avoid
            # false positives on connection-start packets
            if is_immature:
                if xgb_attack_prob > 0.95 and iso_is_anomaly:
                    final_pred = "Suspicious"
                    confidence = xgb_attack_prob * 0.5
                else:
                    final_pred = "Normal"
                    confidence = 1.0 - xgb_attack_prob
            elif self.isolation_forest:
                # Ensemble: require BOTH models to agree for "Attack"
                if xgb_pred == 1 and iso_is_anomaly and xgb_attack_prob > 0.8:
                    final_pred = "Attack"
                    confidence = xgb_attack_prob
                elif xgb_pred == 1 and not iso_is_anomaly:
                    # XGBoost says attack but Isolation Forest disagrees
                    if xgb_attack_prob > 0.92:
                        final_pred = "Suspicious"
                        confidence = xgb_attack_prob * 0.5
                    else:
                        final_pred = "Normal"
                        confidence = 1.0 - xgb_attack_prob
                elif xgb_pred == 0 and iso_is_anomaly and iso_score < -0.3:
                    # Strong anomaly from Isolation Forest only
                    final_pred = "Suspicious"
                    confidence = 0.4
                else:
                    final_pred = "Normal"
                    confidence = float(max(xgb_proba))
            else:
                # No Isolation Forest — require high confidence from XGBoost alone
                if xgb_pred == 1 and xgb_attack_prob > 0.9:
                    final_pred = "Attack"
                elif xgb_pred == 1:
                    final_pred = "Suspicious"
                else:
                    final_pred = "Normal"
                confidence = float(max(xgb_proba))

            result = {
                "prediction": final_pred,
                "confidence": confidence,
                "attack_probability": xgb_attack_prob,
                "ensemble": True if self.isolation_forest else False,
                "xgb_verdict": "Attack" if xgb_pred == 1 else "Normal",
            }

            if self.isolation_forest:
                result["iso_verdict"] = "Anomaly" if iso_is_anomaly else "Normal"
                result["iso_score"] = iso_score

            # SHAP explanation if available
            if self.shap_explainer:
                try:
                    shap_values = self.shap_explainer.shap_values(X_scaled)
                    top_features = np.argsort(np.abs(shap_values[0]))[-5:]
                    result["top_contributing_features"] = [
                        {
                            "feature": self.feature_names[i],
                            "impact": float(shap_values[0][i]),
                            "direction": "increases risk" if shap_values[0][i] > 0 else "decreases risk",
                        }
                        for i in reversed(top_features)
                    ]
                except Exception:
                    pass

            return result

        except Exception as e:
            return {"prediction": "Unknown", "error": str(e)}


class ReportGenerator:
    """Generates forensic PDF reports."""

    def __init__(self):
        from fpdf import FPDF
        self.FPDF = FPDF

    def generate(self, packets: list, flow_summary: dict, anomalies: list,
                 output_path: str = "netsentinel_report.pdf"):
        """Generate a forensic analysis PDF report."""
        pdf = self.FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)

        # Title Page
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 24)
        pdf.cell(0, 40, "", ln=True)
        pdf.cell(0, 15, "NetSentinel", ln=True, align="C")
        pdf.set_font("Helvetica", "", 14)
        pdf.cell(0, 10, "AI-Powered Network Traffic Analysis Report", ln=True, align="C")
        pdf.cell(0, 10, "", ln=True)

        from datetime import datetime
        pdf.set_font("Helvetica", "", 11)
        pdf.cell(0, 8, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
        pdf.cell(0, 8, f"Total Packets Analyzed: {len(packets)}", ln=True, align="C")

        # Executive Summary
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 12, "Executive Summary", ln=True)
        pdf.set_font("Helvetica", "", 11)

        threat_counts = {"safe": 0, "low": 0, "medium": 0, "high": 0}
        for p in packets:
            level = p.get("threat_level", "safe")
            threat_counts[level] = threat_counts.get(level, 0) + 1

        pdf.multi_cell(0, 7,
            f"During the analysis period, NetSentinel captured and analyzed "
            f"{len(packets)} network packets across {flow_summary.get('total_flows', 0)} "
            f"unique flows.\n\n"
            f"Threat Distribution:\n"
            f"  - Safe:   {threat_counts['safe']} packets\n"
            f"  - Low:    {threat_counts['low']} packets\n"
            f"  - Medium: {threat_counts['medium']} packets\n"
            f"  - High:   {threat_counts['high']} packets\n\n"
            f"Flow-level anomalies detected: {len(anomalies)}"
        )

        # Anomalies Section
        if anomalies:
            pdf.cell(0, 10, "", ln=True)
            pdf.set_font("Helvetica", "B", 14)
            pdf.cell(0, 10, "Detected Anomalies", ln=True)
            pdf.set_font("Helvetica", "", 10)

            for i, anom in enumerate(anomalies[:20]):
                pdf.set_font("Helvetica", "B", 10)
                pdf.cell(0, 7, f"{i+1}. [{anom.get('severity', '').upper()}] {anom.get('type', '')}", ln=True)
                pdf.set_font("Helvetica", "", 10)
                pdf.multi_cell(0, 6, f"   {anom.get('detail', '')}")
                pdf.cell(0, 3, "", ln=True)

        # Top Suspicious Packets
        suspicious = [p for p in packets if p.get("threat_level") in ("medium", "high")]
        if suspicious:
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 14)
            pdf.cell(0, 10, "Top Suspicious Packets", ln=True)
            pdf.set_font("Helvetica", "", 9)

            for i, pkt in enumerate(suspicious[:30]):
                pdf.set_font("Helvetica", "B", 9)
                level_icon = "🔴" if pkt.get("threat_level") == "high" else "🟠"
                pdf.cell(0, 6,
                    f"{i+1}. {pkt.get('src_ip', '?')}:{pkt.get('src_port', '')} -> "
                    f"{pkt.get('dst_ip', '?')}:{pkt.get('dst_port', '')} "
                    f"[{pkt.get('threat_level', '').upper()}]",
                    ln=True)
                pdf.set_font("Helvetica", "", 9)
                flags_text = ", ".join(pkt.get("threat_flags", []))
                if flags_text:
                    pdf.multi_cell(0, 5, f"   Flags: {flags_text}")
                pdf.cell(0, 2, "", ln=True)

        # Protocol Distribution
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Protocol Distribution", ln=True)
        pdf.set_font("Helvetica", "", 11)

        protocols = flow_summary.get("protocols", {})
        for proto, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
            pct = (count / max(len(packets), 1)) * 100
            pdf.cell(0, 7, f"  {proto}: {count} packets ({pct:.1f}%)", ln=True)

        pdf.output(output_path)
        return output_path
    