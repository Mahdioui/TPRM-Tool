"""
Connection Extractor - Advanced network flow and connection analysis
Extracts detailed connection statistics, flow patterns, and behavioral analysis
"""

import logging
from typing import Dict, List, Any, Optional, Tuple, Set
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from dataclasses import dataclass, asdict
import statistics
import ipaddress
try:
    from .analyzer import PacketInfo
except ImportError:
    from analyzer import PacketInfo

logger = logging.getLogger(__name__)

@dataclass
class ConnectionFlow:
    """Structure to hold connection flow information"""
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    start_time: float
    end_time: float
    packet_count: int
    total_bytes: int
    flags_seen: Set[str]
    avg_packet_size: float
    duration: float
    packets_per_second: float
    unique_payload_patterns: int
    
@dataclass
class ConnectionStats:
    """Detailed statistics for a network connection"""
    bytes_sent: int
    bytes_received: int
    packets_sent: int
    packets_received: int
    avg_packet_size_sent: float
    avg_packet_size_received: float
    connection_duration: float
    first_packet_time: float
    last_packet_time: float
    tcp_flags: Set[str]
    payload_entropy: float
    retransmissions: int
    out_of_order: int
    
class ConnectionExtractor:
    """
    Advanced connection analysis engine that processes packet data
    to extract detailed flow statistics and behavioral patterns
    """
    
    def __init__(self, packets: List[PacketInfo]):
        """
        Initialize the connection extractor
        
        Args:
            packets: List of PacketInfo objects from the analyzer
        """
        self.packets = packets
        self.flows = {}
        self.connections = {}
        self.conversations = defaultdict(lambda: {
            'forward': defaultdict(int),
            'reverse': defaultdict(int),
            'total_packets': 0,
            'total_bytes': 0,
            'protocols': set(),
            'ports': set(),
            'first_seen': None,
            'last_seen': None
        })
        self.host_profiles = defaultdict(lambda: {
            'services_offered': set(),
            'services_used': set(),
            'peer_count': set(),
            'protocols': set(),
            'total_traffic': 0,
            'behavioral_patterns': []
        })
    
    def create_flow_key(self, packet: PacketInfo) -> str:
        """
        Create a unique flow identifier from packet information
        
        Args:
            packet: PacketInfo object
            
        Returns:
            str: Unique flow identifier
        """
        # Create bidirectional flow key
        endpoints = [
            f"{packet.src_ip}:{packet.src_port or 0}",
            f"{packet.dst_ip}:{packet.dst_port or 0}"
        ]
        endpoints.sort()
        return f"{endpoints[0]}<->{endpoints[1]}:{packet.protocol}"
    
    def calculate_payload_entropy(self, payload: str) -> float:
        """
        Calculate Shannon entropy of payload data
        
        Args:
            payload: Payload string
            
        Returns:
            float: Entropy value (0-8, higher = more random)
        """
        if not payload:
            return 0.0
        
        # Count character frequencies
        char_counts = Counter(payload)
        payload_len = len(payload)
        
        # Calculate entropy
        entropy = 0.0
        for count in char_counts.values():
            probability = count / payload_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def detect_retransmissions(self, packets: List[PacketInfo]) -> int:
        """
        Detect TCP retransmissions in a flow
        
        Args:
            packets: List of packets in the flow
            
        Returns:
            int: Number of retransmissions detected
        """
        retransmissions = 0
        seen_sequences = set()
        
        for packet in packets:
            if packet.protocol == "TCP" and packet.seq_num:
                # Simple retransmission detection based on sequence numbers
                seq_key = (packet.src_ip, packet.dst_ip, packet.seq_num)
                if seq_key in seen_sequences:
                    retransmissions += 1
                else:
                    seen_sequences.add(seq_key)
        
        return retransmissions
    
    def analyze_packet_timing(self, packets: List[PacketInfo]) -> Dict[str, float]:
        """
        Analyze timing patterns in packet flow
        
        Args:
            packets: List of packets to analyze
            
        Returns:
            Dict with timing statistics
        """
        if len(packets) < 2:
            return {
                'avg_interval': 0.0,
                'min_interval': 0.0,
                'max_interval': 0.0,
                'std_interval': 0.0,
                'jitter': 0.0
            }
        
        intervals = []
        for i in range(1, len(packets)):
            interval = packets[i].timestamp - packets[i-1].timestamp
            intervals.append(interval)
        
        if not intervals:
            return {
                'avg_interval': 0.0,
                'min_interval': 0.0,
                'max_interval': 0.0,
                'std_interval': 0.0,
                'jitter': 0.0
            }
        
        avg_interval = statistics.mean(intervals)
        min_interval = min(intervals)
        max_interval = max(intervals)
        std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
        
        # Calculate jitter (variation in packet delay)
        jitter = std_interval / avg_interval if avg_interval > 0 else 0.0
        
        return {
            'avg_interval': avg_interval,
            'min_interval': min_interval,
            'max_interval': max_interval,
            'std_interval': std_interval,
            'jitter': jitter
        }
    
    def classify_connection_type(self, flow: ConnectionFlow) -> str:
        """
        Classify the type of network connection based on patterns
        
        Args:
            flow: ConnectionFlow object
            
        Returns:
            str: Connection type classification
        """
        # Well-known port mappings
        web_ports = {80, 443, 8080, 8443}
        email_ports = {25, 587, 993, 995, 143, 110}
        dns_ports = {53}
        ssh_ports = {22}
        ftp_ports = {20, 21}
        database_ports = {1433, 3306, 5432, 27017, 6379}
        
        dst_port = flow.dst_port or 0
        src_port = flow.src_port or 0
        
        # Check protocol first
        if flow.protocol == "DNS":
            return "DNS"
        elif flow.protocol == "ICMP":
            return "ICMP"
        
        # Check ports
        if dst_port in web_ports or src_port in web_ports:
            return "Web Traffic"
        elif dst_port in email_ports or src_port in email_ports:
            return "Email"
        elif dst_port in dns_ports or src_port in dns_ports:
            return "DNS"
        elif dst_port in ssh_ports or src_port in ssh_ports:
            return "SSH"
        elif dst_port in ftp_ports or src_port in ftp_ports:
            return "FTP"
        elif dst_port in database_ports or src_port in database_ports:
            return "Database"
        
        # Check for high ports (ephemeral)
        if dst_port > 32768 or src_port > 32768:
            return "Ephemeral/P2P"
        
        # Check packet patterns
        if flow.packet_count == 1:
            return "Single Packet"
        elif flow.duration < 1.0 and flow.packet_count < 10:
            return "Short Burst"
        elif flow.duration > 300:  # 5 minutes
            return "Long Session"
        
        return "Unknown"
    
    def extract_flows(self) -> Dict[str, ConnectionFlow]:
        """
        Extract and analyze network flows from packet data
        
        Returns:
            Dict mapping flow keys to ConnectionFlow objects
        """
        flow_data = defaultdict(lambda: {
            'packets': [],
            'start_time': float('inf'),
            'end_time': 0,
            'total_bytes': 0,
            'flags': set(),
            'payloads': set()
        })
        
        # Group packets by flow
        for packet in self.packets:
            flow_key = self.create_flow_key(packet)
            flow_data[flow_key]['packets'].append(packet)
            flow_data[flow_key]['start_time'] = min(
                flow_data[flow_key]['start_time'], packet.timestamp
            )
            flow_data[flow_key]['end_time'] = max(
                flow_data[flow_key]['end_time'], packet.timestamp
            )
            flow_data[flow_key]['total_bytes'] += packet.packet_size
            
            if packet.flags:
                flow_data[flow_key]['flags'].update(packet.flags.split(','))
            
            if packet.payload:
                # Store unique payload patterns (first 100 chars)
                flow_data[flow_key]['payloads'].add(packet.payload[:100])
        
        # Create ConnectionFlow objects
        flows = {}
        for flow_key, data in flow_data.items():
            if not data['packets']:
                continue
                
            first_packet = data['packets'][0]
            duration = data['end_time'] - data['start_time']
            packet_count = len(data['packets'])
            
            flow = ConnectionFlow(
                src_ip=first_packet.src_ip,
                dst_ip=first_packet.dst_ip,
                src_port=first_packet.src_port,
                dst_port=first_packet.dst_port,
                protocol=first_packet.protocol,
                start_time=data['start_time'],
                end_time=data['end_time'],
                packet_count=packet_count,
                total_bytes=data['total_bytes'],
                flags_seen=data['flags'],
                avg_packet_size=data['total_bytes'] / packet_count,
                duration=duration,
                packets_per_second=packet_count / duration if duration > 0 else packet_count,
                unique_payload_patterns=len(data['payloads'])
            )
            
            flows[flow_key] = flow
        
        self.flows = flows
        return flows
    
    def analyze_connections(self) -> Dict[str, ConnectionStats]:
        """
        Perform detailed connection analysis
        
        Returns:
            Dict mapping connection keys to ConnectionStats objects
        """
        connections = {}
        
        for flow_key, flow in self.flows.items():
            # Get packets for this flow
            flow_packets = [p for p in self.packets 
                          if self.create_flow_key(p) == flow_key]
            
            if not flow_packets:
                continue
            
            # Separate forward and reverse packets
            forward_packets = []
            reverse_packets = []
            
            for packet in flow_packets:
                if (packet.src_ip == flow.src_ip and 
                    packet.dst_ip == flow.dst_ip):
                    forward_packets.append(packet)
                else:
                    reverse_packets.append(packet)
            
            # Calculate statistics
            bytes_sent = sum(p.packet_size for p in forward_packets)
            bytes_received = sum(p.packet_size for p in reverse_packets)
            packets_sent = len(forward_packets)
            packets_received = len(reverse_packets)
            
            avg_size_sent = bytes_sent / packets_sent if packets_sent > 0 else 0
            avg_size_received = bytes_received / packets_received if packets_received > 0 else 0
            
            # Calculate payload entropy
            all_payloads = ''.join(p.payload for p in flow_packets if p.payload)
            payload_entropy = self.calculate_payload_entropy(all_payloads)
            
            # Detect retransmissions
            retransmissions = self.detect_retransmissions(flow_packets)
            
            # Simple out-of-order detection (packets with decreasing timestamps)
            out_of_order = 0
            for i in range(1, len(flow_packets)):
                if flow_packets[i].timestamp < flow_packets[i-1].timestamp:
                    out_of_order += 1
            
            stats = ConnectionStats(
                bytes_sent=bytes_sent,
                bytes_received=bytes_received,
                packets_sent=packets_sent,
                packets_received=packets_received,
                avg_packet_size_sent=avg_size_sent,
                avg_packet_size_received=avg_size_received,
                connection_duration=flow.duration,
                first_packet_time=flow.start_time,
                last_packet_time=flow.end_time,
                tcp_flags=flow.flags_seen,
                payload_entropy=payload_entropy,
                retransmissions=retransmissions,
                out_of_order=out_of_order
            )
            
            connections[flow_key] = stats
        
        self.connections = connections
        return connections
    
    def analyze_conversations(self):
        """
        Analyze conversations between IP pairs
        """
        for packet in self.packets:
            # Create conversation key (sorted IPs)
            conv_key = tuple(sorted([packet.src_ip, packet.dst_ip]))
            conv = self.conversations[conv_key]
            
            # Track directional traffic
            if packet.src_ip < packet.dst_ip:
                conv['forward']['packets'] += 1
                conv['forward']['bytes'] += packet.packet_size
            else:
                conv['reverse']['packets'] += 1
                conv['reverse']['bytes'] += packet.packet_size
            
            # Update overall stats
            conv['total_packets'] += 1
            conv['total_bytes'] += packet.packet_size
            conv['protocols'].add(packet.protocol)
            
            if packet.src_port:
                conv['ports'].add(packet.src_port)
            if packet.dst_port:
                conv['ports'].add(packet.dst_port)
            
            # Update time range
            if conv['first_seen'] is None or packet.timestamp < conv['first_seen']:
                conv['first_seen'] = packet.timestamp
            if conv['last_seen'] is None or packet.timestamp > conv['last_seen']:
                conv['last_seen'] = packet.timestamp
    
    def build_host_profiles(self):
        """
        Build behavioral profiles for each host
        """
        for packet in self.packets:
            src_profile = self.host_profiles[packet.src_ip]
            dst_profile = self.host_profiles[packet.dst_ip]
            
            # Track services and protocols
            if packet.dst_port and packet.dst_port < 1024:
                dst_profile['services_offered'].add(packet.dst_port)
                src_profile['services_used'].add(packet.dst_port)
            
            src_profile['protocols'].add(packet.protocol)
            dst_profile['protocols'].add(packet.protocol)
            
            src_profile['peer_count'].add(packet.dst_ip)
            dst_profile['peer_count'].add(packet.src_ip)
            
            src_profile['total_traffic'] += packet.packet_size
            dst_profile['total_traffic'] += packet.packet_size
    
    def get_flow_summary(self) -> Dict[str, Any]:
        """
        Get summary statistics for all flows
        
        Returns:
            Dict with flow summary statistics
        """
        if not self.flows:
            return {}
        
        flow_stats = {
            'total_flows': len(self.flows),
            'protocol_distribution': Counter(),
            'duration_stats': [],
            'packet_count_stats': [],
            'byte_count_stats': [],
            'top_flows_by_bytes': [],
            'top_flows_by_packets': [],
            'connection_types': Counter()
        }
        
        for flow_key, flow in self.flows.items():
            flow_stats['protocol_distribution'][flow.protocol] += 1
            flow_stats['duration_stats'].append(flow.duration)
            flow_stats['packet_count_stats'].append(flow.packet_count)
            flow_stats['byte_count_stats'].append(flow.total_bytes)
            
            # Classify connection
            conn_type = self.classify_connection_type(flow)
            flow_stats['connection_types'][conn_type] += 1
        
        # Calculate statistical summaries
        if flow_stats['duration_stats']:
            flow_stats['avg_duration'] = statistics.mean(flow_stats['duration_stats'])
            flow_stats['max_duration'] = max(flow_stats['duration_stats'])
            flow_stats['min_duration'] = min(flow_stats['duration_stats'])
        
        if flow_stats['packet_count_stats']:
            flow_stats['avg_packets_per_flow'] = statistics.mean(flow_stats['packet_count_stats'])
            flow_stats['max_packets_per_flow'] = max(flow_stats['packet_count_stats'])
        
        if flow_stats['byte_count_stats']:
            flow_stats['avg_bytes_per_flow'] = statistics.mean(flow_stats['byte_count_stats'])
            flow_stats['total_bytes_all_flows'] = sum(flow_stats['byte_count_stats'])
        
        # Get top flows
        sorted_flows = sorted(self.flows.items(), 
                            key=lambda x: x[1].total_bytes, reverse=True)
        flow_stats['top_flows_by_bytes'] = [
            {
                'flow_key': key,
                'src_ip': flow.src_ip,
                'dst_ip': flow.dst_ip,
                'protocol': flow.protocol,
                'bytes': flow.total_bytes,
                'packets': flow.packet_count,
                'duration': flow.duration
            }
            for key, flow in sorted_flows[:10]
        ]
        
        sorted_flows_packets = sorted(self.flows.items(), 
                                    key=lambda x: x[1].packet_count, reverse=True)
        flow_stats['top_flows_by_packets'] = [
            {
                'flow_key': key,
                'src_ip': flow.src_ip,
                'dst_ip': flow.dst_ip,
                'protocol': flow.protocol,
                'bytes': flow.total_bytes,
                'packets': flow.packet_count,
                'duration': flow.duration
            }
            for key, flow in sorted_flows_packets[:10]
        ]
        
        return flow_stats
    
    def get_connection_summary(self) -> Dict[str, Any]:
        """
        Get summary of connection analysis
        
        Returns:
            Dict with connection summary
        """
        if not self.connections:
            return {}
        
        summary = {
            'total_connections': len(self.connections),
            'avg_duration': 0,
            'avg_bytes_per_connection': 0,
            'retransmission_rate': 0,
            'connections_with_retrans': 0,
            'high_entropy_connections': 0,
            'suspicious_connections': []
        }
        
        total_duration = 0
        total_bytes = 0
        total_retrans = 0
        
        for conn_key, stats in self.connections.items():
            total_duration += stats.connection_duration
            total_bytes += stats.bytes_sent + stats.bytes_received
            total_retrans += stats.retransmissions
            
            if stats.retransmissions > 0:
                summary['connections_with_retrans'] += 1
            
            if stats.payload_entropy > 7.0:  # High entropy threshold
                summary['high_entropy_connections'] += 1
            
            # Flag suspicious connections
            if (stats.retransmissions > 10 or 
                stats.payload_entropy > 7.5 or
                stats.out_of_order > 5):
                summary['suspicious_connections'].append({
                    'connection': conn_key,
                    'retransmissions': stats.retransmissions,
                    'entropy': stats.payload_entropy,
                    'out_of_order': stats.out_of_order
                })
        
        if len(self.connections) > 0:
            summary['avg_duration'] = total_duration / len(self.connections)
            summary['avg_bytes_per_connection'] = total_bytes / len(self.connections)
            summary['retransmission_rate'] = total_retrans / len(self.connections)
        
        return summary
    
    def run_full_analysis(self) -> Dict[str, Any]:
        """
        Run complete connection analysis
        
        Returns:
            Dict with all analysis results
        """
        logger.info("Extracting network flows...")
        self.extract_flows()
        
        logger.info("Analyzing connection statistics...")
        self.analyze_connections()
        
        logger.info("Analyzing conversations...")
        self.analyze_conversations()
        
        logger.info("Building host profiles...")
        self.build_host_profiles()
        
        # Prepare results
        results = {
            'flow_summary': self.get_flow_summary(),
            'connection_summary': self.get_connection_summary(),
            'conversation_count': len(self.conversations),
            'host_count': len(self.host_profiles),
            'flows': {k: asdict(v) for k, v in self.flows.items()},
            'connections': {k: asdict(v) for k, v in self.connections.items()}
        }
        
        return results


# Import math for entropy calculation
import math

if __name__ == "__main__":
    # Example usage with mock data
    print("Connection Extractor - Example usage requires packet data from analyzer.py")
