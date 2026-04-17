"""PCAP feature extraction service wrapping the existing pcap2csv pipeline."""

from __future__ import annotations

import asyncio
import logging
import sys
import tempfile
from pathlib import Path

import dpkt
import pandas as pd

logger = logging.getLogger(__name__)

_PCAP2CSV_DIR = str(Path(__file__).resolve().parent.parent.parent / "utils" / "pcap2csv")
if _PCAP2CSV_DIR not in sys.path:
    sys.path.insert(0, _PCAP2CSV_DIR)


MODEL_FEATURES: list[str] = [
    "flow_duration", "header_length", "protocol_type", "duration", "rate",
    "srate", "drate", "fin_flag_number", "syn_flag_number", "rst_flag_number",
    "psh_flag_number", "ack_flag_number", "ece_flag_number", "cwr_flag_number",
    "ack_count", "syn_count", "fin_count", "urg_count", "rst_count",
    "http", "https", "dns", "telnet", "smtp", "ssh", "irc",
    "tcp", "udp", "dhcp", "arp", "icmp", "ipv", "llc",
    "tot_sum", "min", "max", "avg", "std", "tot_size",
    "iat", "number", "magnitue", "radius", "covariance", "variance", "weight",
]


def _sync_extract(pcap_path: str) -> pd.DataFrame:
    """Run the legacy Feature_extraction pipeline synchronously.

    Returns a DataFrame with columns lowercased and underscored,
    filtered to the 46 model features.
    """
    from Feature_extraction import Feature_extraction  # noqa: N813

    fe = Feature_extraction()

    # The pipeline writes a CSV to disk; use a temp file.
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
        csv_stem = tmp.name.removesuffix(".csv")  # pcap_evaluation appends .csv

    fe.pcap_evaluation(pcap_path, csv_stem)
    csv_path = csv_stem + ".csv"

    df = pd.read_csv(csv_path)
    Path(csv_path).unlink(missing_ok=True)

    # Normalise column names to match training data conventions
    df.columns = [c.lower().replace(" ", "_") for c in df.columns]

    # Select exactly the 46 features the scaler expects (add zeros for any missing)
    for col in MODEL_FEATURES:
        if col not in df.columns:
            df[col] = 0
    df = df[MODEL_FEATURES]

    df = df.fillna(0)
    return df


class FeatureService:
    """Async wrapper around the pcap2csv feature extraction pipeline."""

    async def extract_features(self, pcap_path: str) -> pd.DataFrame:
        """Extract and normalise features from a PCAP file.

        Runs the CPU-heavy extraction in a thread pool so the FastAPI
        event loop stays responsive.
        """
        loop = asyncio.get_running_loop()
        df = await loop.run_in_executor(None, _sync_extract, pcap_path)
        logger.info("Extracted %d flows with %d features from %s", len(df), len(df.columns), pcap_path)
        return df

    async def extract_connectivity_info(self, pcap_path: str) -> pd.DataFrame:
        """Lightweight per-packet pass to get IP/port identity data.

        Returns one row per packet with: src_ip, dst_ip, src_port,
        dst_port, protocol_name, timestamp.  This is used to attribute
        ML predictions back to specific IPs for the summary.
        """
        loop = asyncio.get_running_loop()
        rows = await loop.run_in_executor(None, _sync_extract_connectivity, pcap_path)
        return pd.DataFrame(rows, columns=[
            "src_ip", "dst_ip", "src_port", "dst_port", "protocol_name", "timestamp",
        ])


def _sync_extract_connectivity(pcap_path: str) -> list[list]:
    """Parse PCAP with dpkt to extract per-packet connection identity."""
    import socket

    rows: list[list] = []
    with open(pcap_path, "rb") as f:
        try:
            pcap = dpkt.pcap.Reader(f)
        except ValueError:
            pcap = dpkt.pcapng.Reader(f)

        for timestamp, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if isinstance(eth.data, dpkt.ip.IP):
                        ip = eth.data
                        src_ip = socket.inet_ntoa(ip.src)
                        dst_ip = socket.inet_ntoa(ip.dst)
                        protocol_name = {6: "TCP", 17: "UDP"}.get(ip.p, "OTHER")
                        src_port = dst_port = None
        
                        if protocol_name == "TCP":
                            tcp = ip.data
                            src_port = tcp.sport
                            dst_port = tcp.dport
                        elif protocol_name == "UDP":
                            udp = ip.data
                            src_port = udp.sport
                            dst_port = udp.dport
        
                        rows.append([src_ip, dst_ip, src_port, dst_port, protocol_name, timestamp])

                except Exception as e:
                    logger.warning("Failed to parse packet in %s: %s", pcap_path, e)

    return rows
