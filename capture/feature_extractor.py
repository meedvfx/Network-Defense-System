"""
Extracteur de features CIC-compatibles depuis les flux réseau.
Calcule ~80 features statistiques similaires à CIC-IDS2017/2018.
"""

import logging
from typing import Dict, List, Any

import numpy as np

from capture.flow_builder import NetworkFlow

logger = logging.getLogger(__name__)


class FeatureExtractor:
    """
    Extrait les features CIC-compatibles depuis un flux réseau.
    Calcule des statistiques sur les paquets forward/backward.
    """

    def __init__(self):
        self.feature_names = self._get_feature_names()

    def _get_feature_names(self) -> List[str]:
        """Retourne la liste ordonnée des noms de features."""
        return [
            "Destination Port", "Flow Duration",
            "Total Fwd Packets", "Total Backward Packets",
            "Total Length of Fwd Packets", "Total Length of Bwd Packets",
            "Fwd Packet Length Max", "Fwd Packet Length Min",
            "Fwd Packet Length Mean", "Fwd Packet Length Std",
            "Bwd Packet Length Max", "Bwd Packet Length Min",
            "Bwd Packet Length Mean", "Bwd Packet Length Std",
            "Flow Bytes/s", "Flow Packets/s",
            "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
            "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std",
            "Fwd IAT Max", "Fwd IAT Min",
            "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std",
            "Bwd IAT Max", "Bwd IAT Min",
            "Fwd PSH Flags", "Bwd PSH Flags",
            "Fwd URG Flags", "Bwd URG Flags",
            "Fwd Header Length", "Bwd Header Length",
            "Fwd Packets/s", "Bwd Packets/s",
            "Min Packet Length", "Max Packet Length",
            "Packet Length Mean", "Packet Length Std",
            "Packet Length Variance",
            "FIN Flag Count", "SYN Flag Count", "RST Flag Count",
            "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
            "CWE Flag Count", "ECE Flag Count",
            "Down/Up Ratio", "Average Packet Size",
            "Avg Fwd Segment Size", "Avg Bwd Segment Size",
            "Fwd Header Length.1",
            "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk",
            "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk",
            "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
            "Subflow Fwd Packets", "Subflow Fwd Bytes",
            "Subflow Bwd Packets", "Subflow Bwd Bytes",
            "Init_Win_bytes_forward", "Init_Win_bytes_backward",
            "act_data_pkt_fwd", "min_seg_size_forward",
            "Active Mean", "Active Std", "Active Max", "Active Min",
            "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
        ]

    def _safe_stats(self, values: list) -> Dict[str, float]:
        """Calcule les statistiques sûres (gère les listes vides)."""
        if not values:
            return {"mean": 0.0, "std": 0.0, "max": 0.0, "min": 0.0, "total": 0.0}

        arr = np.array(values, dtype=np.float64)
        return {
            "mean": float(np.mean(arr)),
            "std": float(np.std(arr)),
            "max": float(np.max(arr)),
            "min": float(np.min(arr)),
            "total": float(np.sum(arr)),
        }

    def _compute_iat(self, packets: list) -> Dict[str, float]:
        """Calcule les Inter-Arrival Times (IAT)."""
        if len(packets) < 2:
            return {"mean": 0.0, "std": 0.0, "max": 0.0, "min": 0.0, "total": 0.0}

        timestamps = sorted([p["timestamp"] for p in packets])
        iats = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps) - 1)]
        return self._safe_stats(iats)

    def _count_flags(self, packets: list, flag_bit: int) -> int:
        """Compte les paquets avec un flag TCP spécifique."""
        return sum(1 for p in packets if p.get("tcp_flags", 0) & flag_bit)

    def extract(self, flow: NetworkFlow) -> np.ndarray:
        """
        Extrait un vecteur de features CIC-compatible depuis un flux.

        Args:
            flow: Flux réseau construit par FlowBuilder.

        Returns:
            Array numpy de features (1D).
        """
        fwd = flow.fwd_packets
        bwd = flow.bwd_packets
        all_packets = fwd + bwd
        duration = flow.duration

        # Tailles des paquets
        fwd_sizes = [p.get("ip_len", 0) for p in fwd]
        bwd_sizes = [p.get("ip_len", 0) for p in bwd]
        all_sizes = fwd_sizes + bwd_sizes

        fwd_stats = self._safe_stats(fwd_sizes)
        bwd_stats = self._safe_stats(bwd_sizes)
        all_stats = self._safe_stats(all_sizes)

        # IAT (Inter-Arrival Time)
        flow_iat = self._compute_iat(all_packets)
        fwd_iat = self._compute_iat(fwd)
        bwd_iat = self._compute_iat(bwd)

        # Bytes/s et Packets/s
        flow_bytes_per_s = sum(all_sizes) / duration if duration > 0 else 0.0
        flow_packets_per_s = len(all_packets) / duration if duration > 0 else 0.0
        fwd_packets_per_s = len(fwd) / duration if duration > 0 else 0.0
        bwd_packets_per_s = len(bwd) / duration if duration > 0 else 0.0

        # Flags TCP (bits: FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20, ECE=0x40, CWR=0x80)
        fwd_psh = self._count_flags(fwd, 0x08)
        bwd_psh = self._count_flags(bwd, 0x08)
        fwd_urg = self._count_flags(fwd, 0x20)
        bwd_urg = self._count_flags(bwd, 0x20)

        fin_count = self._count_flags(all_packets, 0x01)
        syn_count = self._count_flags(all_packets, 0x02)
        rst_count = self._count_flags(all_packets, 0x04)
        psh_count = self._count_flags(all_packets, 0x08)
        ack_count = self._count_flags(all_packets, 0x10)
        urg_count = self._count_flags(all_packets, 0x20)
        cwe_count = self._count_flags(all_packets, 0x80)
        ece_count = self._count_flags(all_packets, 0x40)

        # Header lengths
        fwd_header_len = sum(40 for _ in fwd)  # Approximation TCP header
        bwd_header_len = sum(40 for _ in bwd)

        # Down/Up ratio
        down_up_ratio = len(bwd) / len(fwd) if len(fwd) > 0 else 0.0

        # Average sizes
        avg_packet_size = np.mean(all_sizes) if all_sizes else 0.0
        avg_fwd_seg = np.mean(fwd_sizes) if fwd_sizes else 0.0
        avg_bwd_seg = np.mean(bwd_sizes) if bwd_sizes else 0.0

        # Init window sizes
        init_win_fwd = fwd[0].get("tcp_window", 0) if fwd else 0
        init_win_bwd = bwd[0].get("tcp_window", 0) if bwd else 0

        # Active data packets (paquets avec payload)
        act_data_fwd = sum(1 for p in fwd if p.get("payload_size", 0) > 0)
        min_seg_fwd = min([p.get("ip_len", 0) for p in fwd]) if fwd else 0

        # Construire le vecteur de features
        features = [
            flow.dst_port,                    # Destination Port
            duration * 1e6,                   # Flow Duration (microseconds)
            len(fwd),                         # Total Fwd Packets
            len(bwd),                         # Total Backward Packets
            fwd_stats["total"],               # Total Length of Fwd Packets
            bwd_stats["total"],               # Total Length of Bwd Packets
            fwd_stats["max"],                 # Fwd Packet Length Max
            fwd_stats["min"],                 # Fwd Packet Length Min
            fwd_stats["mean"],                # Fwd Packet Length Mean
            fwd_stats["std"],                 # Fwd Packet Length Std
            bwd_stats["max"],                 # Bwd Packet Length Max
            bwd_stats["min"],                 # Bwd Packet Length Min
            bwd_stats["mean"],                # Bwd Packet Length Mean
            bwd_stats["std"],                 # Bwd Packet Length Std
            flow_bytes_per_s,                 # Flow Bytes/s
            flow_packets_per_s,               # Flow Packets/s
            flow_iat["mean"],                 # Flow IAT Mean
            flow_iat["std"],                  # Flow IAT Std
            flow_iat["max"],                  # Flow IAT Max
            flow_iat["min"],                  # Flow IAT Min
            fwd_iat["total"],                 # Fwd IAT Total
            fwd_iat["mean"],                  # Fwd IAT Mean
            fwd_iat["std"],                   # Fwd IAT Std
            fwd_iat["max"],                   # Fwd IAT Max
            fwd_iat["min"],                   # Fwd IAT Min
            bwd_iat["total"],                 # Bwd IAT Total
            bwd_iat["mean"],                  # Bwd IAT Mean
            bwd_iat["std"],                   # Bwd IAT Std
            bwd_iat["max"],                   # Bwd IAT Max
            bwd_iat["min"],                   # Bwd IAT Min
            fwd_psh,                          # Fwd PSH Flags
            bwd_psh,                          # Bwd PSH Flags
            fwd_urg,                          # Fwd URG Flags
            bwd_urg,                          # Bwd URG Flags
            fwd_header_len,                   # Fwd Header Length
            bwd_header_len,                   # Bwd Header Length
            fwd_packets_per_s,                # Fwd Packets/s
            bwd_packets_per_s,                # Bwd Packets/s
            all_stats["min"],                 # Min Packet Length
            all_stats["max"],                 # Max Packet Length
            all_stats["mean"],                # Packet Length Mean
            all_stats["std"],                 # Packet Length Std
            all_stats["std"] ** 2,            # Packet Length Variance
            fin_count,                        # FIN Flag Count
            syn_count,                        # SYN Flag Count
            rst_count,                        # RST Flag Count
            psh_count,                        # PSH Flag Count
            ack_count,                        # ACK Flag Count
            urg_count,                        # URG Flag Count
            cwe_count,                        # CWE Flag Count
            ece_count,                        # ECE Flag Count
            down_up_ratio,                    # Down/Up Ratio
            avg_packet_size,                  # Average Packet Size
            avg_fwd_seg,                      # Avg Fwd Segment Size
            avg_bwd_seg,                      # Avg Bwd Segment Size
            fwd_header_len,                   # Fwd Header Length.1
            0.0,                              # Fwd Avg Bytes/Bulk
            0.0,                              # Fwd Avg Packets/Bulk
            0.0,                              # Fwd Avg Bulk Rate
            0.0,                              # Bwd Avg Bytes/Bulk
            0.0,                              # Bwd Avg Packets/Bulk
            0.0,                              # Bwd Avg Bulk Rate
            len(fwd),                         # Subflow Fwd Packets
            int(fwd_stats["total"]),          # Subflow Fwd Bytes
            len(bwd),                         # Subflow Bwd Packets
            int(bwd_stats["total"]),          # Subflow Bwd Bytes
            init_win_fwd,                     # Init_Win_bytes_forward
            init_win_bwd,                     # Init_Win_bytes_backward
            act_data_fwd,                     # act_data_pkt_fwd
            min_seg_fwd,                      # min_seg_size_forward
            0.0, 0.0, 0.0, 0.0,              # Active Mean/Std/Max/Min
            0.0, 0.0, 0.0, 0.0,              # Idle Mean/Std/Max/Min
        ]

        return np.array(features, dtype=np.float32)

    def extract_batch(self, flows: List[NetworkFlow]) -> np.ndarray:
        """Extrait les features pour un batch de flux."""
        features_list = [self.extract(flow) for flow in flows]
        return np.array(features_list, dtype=np.float32)

    def get_flow_metadata(self, flow: NetworkFlow) -> dict:
        """Retourne les métadonnées du flux (pour stockage)."""
        return {
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol,
            "duration": flow.duration,
            "total_fwd_packets": flow.total_fwd_packets,
            "total_bwd_packets": flow.total_bwd_packets,
        }
