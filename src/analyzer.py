"""
PCAP Analyzer - Core packet analysis engine
Handles PCAP file parsing and initial packet extraction
"""

import os
import logging
import time
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass, asdict
from collections import defaultdict, Counter

# Try to import optional dependencies gracefully
try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    PYSHARK_AVAILABLE = False
    logging.warning("pyshark not available. Some features will be limited.")

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import Ether
    from scapy.layers.http import HTTPRequest, HTTPResponse
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.error("scapy is required but not available. Please install scapy.")

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    logging.warning("pandas not available. DataFrame export will be limited.")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class PacketInfo:
    """Structure to hold packet information"""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    packet_size: int
    payload: str
    flags: str
    ttl: Optional[int]
    window_size: Optional[int]
    seq_num: Optional[int]
    ack_num: Optional[int]
    
class PcapAnalyzer:
    """
    Main PCAP analysis engine that processes packet capture files
    and extracts detailed network information
    """
    
    def __init__(self, pcap_file: str):
        """
        Initialize the PCAP analyzer
        
        Args:
            pcap_file: Path to the PCAP file to analyze
        """
        if not SCAPY_AVAILABLE:
            raise ImportError("scapy is required for PCAP analysis. Please install it with: pip install scapy")
        
        self.pcap_file = pcap_file
        self.packets = []
        self.packet_count = 0
        self.analysis_stats = {
            'total_packets': 0,
            'total_bytes': 0,
            'unique_ips': set(),
            'protocols': Counter(),
            'ports': Counter(),
            'start_time': None,
            'end_time': None,
            'duration': 0
        }
        self.flows = defaultdict(list)
        self.conversations = defaultdict(lambda: {
            'packets': 0,
            'bytes': 0,
            'first_seen': None,
            'last_seen': None
        })
        
    def validate_pcap_file(self) -> bool:
        """
        Validate that the PCAP file exists and is readable
        
        Returns:
            bool: True if file is valid, False otherwise
        """
        if not os.path.exists(self.pcap_file):
            logger.error(f"PCAP file not found: {self.pcap_file}")
            return False
            
        if not os.access(self.pcap_file, os.R_OK):
            logger.error(f"PCAP file not readable: {self.pcap_file}")
            return False
            
        try:
            # Quick validation by attempting to read first packet
            packets = rdpcap(self.pcap_file, count=1)
            if len(packets) == 0:
                logger.error(f"PCAP file appears to be empty: {self.pcap_file}")
                return False
        except Exception as e:
            logger.error(f"Error reading PCAP file: {e}")
            return False
            
        return True
    
    def extract_packet_info(self, packet) -> Optional[PacketInfo]:
        """
        Extract detailed information from a single packet
        
        Args:
            packet: Scapy packet object
            
        Returns:
            PacketInfo: Structured packet information or None if extraction fails
        """
        try:
            # Basic packet info
            timestamp = float(packet.time)
            packet_size = len(packet)
            
            # Initialize variables
            src_ip = dst_ip = "Unknown"
            src_port = dst_port = None
            protocol = "Unknown"
            payload = ""
            flags = ""
            ttl = window_size = seq_num = ack_num = None
            
            # Extract IP layer information
            if IP in packet:
                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                protocol = ip_layer.proto
                ttl = ip_layer.ttl
                
                # Convert protocol number to name
                protocol_names = {1: "ICMP", 6: "TCP", 17: "UDP"}
                protocol = protocol_names.get(protocol, f"Unknown({protocol})")
            
            # Extract transport layer information
            if TCP in packet:
                tcp_layer = packet[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                protocol = "TCP"
                window_size = tcp_layer.window
                seq_num = tcp_layer.seq
                ack_num = tcp_layer.ack
                
                # TCP flags
                flag_names = []
                if tcp_layer.flags.F: flag_names.append("FIN")
                if tcp_layer.flags.S: flag_names.append("SYN")
                if tcp_layer.flags.R: flag_names.append("RST")
                if tcp_layer.flags.P: flag_names.append("PSH")
                if tcp_layer.flags.A: flag_names.append("ACK")
                if tcp_layer.flags.U: flag_names.append("URG")
                flags = ",".join(flag_names)
                
            elif UDP in packet:
                udp_layer = packet[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                protocol = "UDP"
                
            elif ICMP in packet:
                protocol = "ICMP"
                
            # Extract payload
            if Raw in packet:
                raw_layer = packet[Raw]
                try:
                    payload = raw_layer.load.decode('utf-8', errors='ignore')[:1000]  # Limit payload size
                except:
                    payload = str(raw_layer.load)[:1000]
            
            # Special handling for HTTP
            if HTTPRequest in packet:
                http_req = packet[HTTPRequest]
                payload = f"HTTP Request: {http_req.Method.decode()} {http_req.Path.decode()}"
                protocol = "HTTP"
                
            elif HTTPResponse in packet:
                http_resp = packet[HTTPResponse]
                payload = f"HTTP Response: {http_resp.Status_Code.decode()}"
                protocol = "HTTP"
            
            # Special handling for DNS
            if DNS in packet:
                dns_layer = packet[DNS]
                protocol = "DNS"
                if DNSQR in packet:
                    query = packet[DNSQR]
                    payload = f"DNS Query: {query.qname.decode()}"
                elif DNSRR in packet:
                    response = packet[DNSRR]
                    payload = f"DNS Response: {response.rrname.decode()}"
            
            return PacketInfo(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                packet_size=packet_size,
                payload=payload,
                flags=flags,
                ttl=ttl,
                window_size=window_size,
                seq_num=seq_num,
                ack_num=ack_num
            )
            
        except Exception as e:
            logger.warning(f"Error extracting packet info: {e}")
            return None
    
    def analyze_flows(self):
        """
        Analyze network flows and conversations from extracted packets
        """
        for packet_info in self.packets:
            # Create flow key (5-tuple)
            flow_key = (
                packet_info.src_ip,
                packet_info.dst_ip,
                packet_info.src_port or 0,
                packet_info.dst_port or 0,
                packet_info.protocol
            )
            
            # Normalize flow key (ensure consistent ordering)
            normalized_key = tuple(sorted([
                f"{packet_info.src_ip}:{packet_info.src_port or 0}",
                f"{packet_info.dst_ip}:{packet_info.dst_port or 0}"
            ]) + [packet_info.protocol])
            
            self.flows[normalized_key].append(packet_info)
            
            # Track conversations
            conv_key = tuple(sorted([packet_info.src_ip, packet_info.dst_ip]))
            conv = self.conversations[conv_key]
            conv['packets'] += 1
            conv['bytes'] += packet_info.packet_size
            
            if conv['first_seen'] is None or packet_info.timestamp < conv['first_seen']:
                conv['first_seen'] = packet_info.timestamp
            if conv['last_seen'] is None or packet_info.timestamp > conv['last_seen']:
                conv['last_seen'] = packet_info.timestamp
    
    def update_statistics(self, packet_info: PacketInfo):
        """
        Update analysis statistics with packet information
        
        Args:
            packet_info: Packet information to include in statistics
        """
        self.analysis_stats['total_packets'] += 1
        self.analysis_stats['total_bytes'] += packet_info.packet_size
        self.analysis_stats['unique_ips'].add(packet_info.src_ip)
        self.analysis_stats['unique_ips'].add(packet_info.dst_ip)
        self.analysis_stats['protocols'][packet_info.protocol] += 1
        
        if packet_info.src_port:
            self.analysis_stats['ports'][packet_info.src_port] += 1
        if packet_info.dst_port:
            self.analysis_stats['ports'][packet_info.dst_port] += 1
        
        # Update time range
        if self.analysis_stats['start_time'] is None:
            self.analysis_stats['start_time'] = packet_info.timestamp
        if self.analysis_stats['end_time'] is None:
            self.analysis_stats['end_time'] = packet_info.timestamp
            
        if packet_info.timestamp < self.analysis_stats['start_time']:
            self.analysis_stats['start_time'] = packet_info.timestamp
        if packet_info.timestamp > self.analysis_stats['end_time']:
            self.analysis_stats['end_time'] = packet_info.timestamp
    
    def analyze_pcap(self, max_packets: Optional[int] = None) -> Dict[str, Any]:
        """
        Main analysis function that processes the entire PCAP file
        
        Args:
            max_packets: Maximum number of packets to process (None for all)
            
        Returns:
            Dict containing analysis results
        """
        if not self.validate_pcap_file():
            return {"error": "Invalid PCAP file"}
        
        logger.info(f"Starting analysis of {self.pcap_file}")
        start_time = time.time()
        
        try:
            # Read packets using scapy
            logger.info("Reading PCAP file...")
            packets = rdpcap(self.pcap_file)
            
            if max_packets:
                packets = packets[:max_packets]
            
            logger.info(f"Processing {len(packets)} packets...")
            
            # Process each packet
            for i, packet in enumerate(packets):
                if i % 1000 == 0:
                    logger.info(f"Processed {i} packets...")
                
                packet_info = self.extract_packet_info(packet)
                if packet_info:
                    self.packets.append(packet_info)
                    self.update_statistics(packet_info)
            
            # Analyze flows and conversations
            logger.info("Analyzing network flows...")
            self.analyze_flows()
            
            # Calculate duration
            if self.analysis_stats['start_time'] and self.analysis_stats['end_time']:
                self.analysis_stats['duration'] = (
                    self.analysis_stats['end_time'] - self.analysis_stats['start_time']
                )
            
            # Convert sets to lists for JSON serialization
            self.analysis_stats['unique_ips'] = list(self.analysis_stats['unique_ips'])
            
            analysis_time = time.time() - start_time
            logger.info(f"Analysis completed in {analysis_time:.2f} seconds")
            
            return {
                "success": True,
                "packets": len(self.packets),
                "analysis_time": analysis_time,
                "statistics": self.analysis_stats,
                "flows_count": len(self.flows),
                "conversations_count": len(self.conversations)
            }
            
        except Exception as e:
            logger.error(f"Error during PCAP analysis: {e}")
            return {"error": str(e)}
    
    def get_top_talkers(self, limit: int = 10) -> List[Dict]:
        """
        Get the top talking IP addresses by packet count
        
        Args:
            limit: Number of top talkers to return
            
        Returns:
            List of dictionaries with IP and packet count
        """
        ip_counts = Counter()
        for packet_info in self.packets:
            ip_counts[packet_info.src_ip] += 1
            ip_counts[packet_info.dst_ip] += 1
        
        return [{"ip": ip, "packets": count} 
                for ip, count in ip_counts.most_common(limit)]
    
    def get_protocol_distribution(self) -> Dict[str, int]:
        """
        Get distribution of protocols in the capture
        
        Returns:
            Dictionary mapping protocol names to packet counts
        """
        return dict(self.analysis_stats['protocols'])
    
    def get_port_analysis(self, limit: int = 20) -> Dict[str, List]:
        """
        Get analysis of most common ports
        
        Args:
            limit: Number of top ports to return
            
        Returns:
            Dictionary with common ports and their classifications
        """
        common_ports = {
            20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 67: "DHCP Server", 68: "DHCP Client",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
            993: "IMAPS", 995: "POP3S", 3389: "RDP", 1433: "MSSQL",
            3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB"
        }
        
        top_ports = self.analysis_stats['ports'].most_common(limit)
        
        result = {
            "top_ports": [],
            "known_services": [],
            "unknown_ports": []
        }
        
        for port, count in top_ports:
            port_info = {"port": port, "count": count}
            if port in common_ports:
                port_info["service"] = common_ports[port]
                result["known_services"].append(port_info)
            else:
                result["unknown_ports"].append(port_info)
            result["top_ports"].append(port_info)
        
        return result
    
    def export_to_dataframe(self):
        """
        Export packet data to pandas DataFrame for further analysis
        
        Returns:
            DataFrame containing all packet information or dict if pandas unavailable
        """
        if not self.packets:
            if PANDAS_AVAILABLE:
                return pd.DataFrame()
            else:
                return []
        
        # Convert packet info to dictionaries
        packet_dicts = [asdict(packet) for packet in self.packets]
        
        if PANDAS_AVAILABLE:
            # Create DataFrame
            df = pd.DataFrame(packet_dicts)
            
            # Convert timestamp to datetime
            df['datetime'] = pd.to_datetime(df['timestamp'], unit='s')
            
            return df
        else:
            # Return raw data if pandas not available
            return packet_dicts
    
    def get_suspicious_indicators(self) -> Dict[str, List]:
        """
        Identify potentially suspicious network indicators
        
        Returns:
            Dictionary of suspicious indicators found
        """
        indicators = {
            "unusual_ports": [],
            "large_packets": [],
            "high_frequency_ips": [],
            "suspicious_protocols": [],
            "payload_anomalies": []
        }
        
        # Check for unusual ports (outside common ranges)
        unusual_port_threshold = 10000
        for packet_info in self.packets:
            if packet_info.src_port and packet_info.src_port > unusual_port_threshold:
                indicators["unusual_ports"].append({
                    "ip": packet_info.src_ip,
                    "port": packet_info.src_port,
                    "protocol": packet_info.protocol
                })
            if packet_info.dst_port and packet_info.dst_port > unusual_port_threshold:
                indicators["unusual_ports"].append({
                    "ip": packet_info.dst_ip,
                    "port": packet_info.dst_port,
                    "protocol": packet_info.protocol
                })
        
        # Check for unusually large packets
        avg_packet_size = sum(p.packet_size for p in self.packets) / len(self.packets)
        large_packet_threshold = avg_packet_size * 3
        
        for packet_info in self.packets:
            if packet_info.packet_size > large_packet_threshold:
                indicators["large_packets"].append({
                    "src_ip": packet_info.src_ip,
                    "dst_ip": packet_info.dst_ip,
                    "size": packet_info.packet_size,
                    "timestamp": packet_info.timestamp
                })
        
        # Remove duplicates and limit results
        for key in indicators:
            if isinstance(indicators[key], list):
                # Remove duplicates and limit to top 50
                seen = set()
                unique_items = []
                for item in indicators[key]:
                    item_key = str(sorted(item.items()))
                    if item_key not in seen:
                        seen.add(item_key)
                        unique_items.append(item)
                        if len(unique_items) >= 50:
                            break
                indicators[key] = unique_items
        
        return indicators


if __name__ == "__main__":
    # Example usage
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python analyzer.py <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    analyzer = PcapAnalyzer(pcap_file)
    
    # Run analysis
    results = analyzer.analyze_pcap()
    
    if "error" in results:
        print(f"Error: {results['error']}")
        sys.exit(1)
    
    # Print summary
    print(f"\n=== PCAP Analysis Results ===")
    print(f"Total packets: {results['packets']}")
    print(f"Analysis time: {results['analysis_time']:.2f} seconds")
    print(f"Unique IPs: {len(analyzer.analysis_stats['unique_ips'])}")
    print(f"Protocols: {list(analyzer.analysis_stats['protocols'].keys())}")
    print(f"Flows: {results['flows_count']}")
    print(f"Conversations: {results['conversations_count']}")
    
    # Top talkers
    print(f"\n=== Top Talkers ===")
    for talker in analyzer.get_top_talkers(5):
        print(f"{talker['ip']}: {talker['packets']} packets")
