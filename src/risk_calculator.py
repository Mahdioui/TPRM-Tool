"""
Risk Calculator - Advanced risk scoring engine with ISO/NIST/OWASP mapping
Calculates comprehensive risk scores based on multiple threat indicators
"""

import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import statistics
from datetime import datetime

try:
    from .analyzer import PacketInfo
    from .extractor import ConnectionFlow, ConnectionStats
    from .regex_utils import ThreatMatch, ThreatSeverity
    from .nlp_utils import PayloadAnalysis
except ImportError:
    from analyzer import PacketInfo
    from extractor import ConnectionFlow, ConnectionStats
    from regex_utils import ThreatMatch, ThreatSeverity
    from nlp_utils import PayloadAnalysis

logger = logging.getLogger(__name__)

class RiskLevel(Enum):
    """Risk level classifications"""
    MINIMAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

class ComplianceFramework(Enum):
    """Supported compliance frameworks"""
    ISO_27001 = "ISO/IEC 27001"
    NIST_CSF = "NIST Cybersecurity Framework"
    OWASP_TOP10 = "OWASP Top 10"

@dataclass
class RiskFactor:
    """Individual risk factor"""
    name: str
    category: str
    score: float  # 0-100
    weight: float  # 0-1
    description: str
    evidence: List[str]
    mitigation: str
    framework_mapping: Dict[str, str]

@dataclass
class RiskAssessment:
    """Comprehensive risk assessment result"""
    overall_score: float  # 0-100
    risk_level: RiskLevel
    risk_factors: List[RiskFactor]
    category_scores: Dict[str, float]
    compliance_mapping: Dict[str, List[str]]
    recommendations: List[str]
    timestamp: datetime
    confidence: float  # 0-1

class RiskCalculator:
    """
    Advanced risk calculation engine that combines multiple threat indicators
    to produce comprehensive risk scores with regulatory compliance mapping
    """
    
    def __init__(self):
        """Initialize the risk calculator with scoring matrices"""
        self.risk_weights = self._initialize_risk_weights()
        self.compliance_mappings = self._initialize_compliance_mappings()
        self.threat_patterns = self._initialize_threat_patterns()
        self.baseline_scores = self._initialize_baseline_scores()
        
    def _initialize_risk_weights(self) -> Dict[str, float]:
        """
        Initialize risk factor weights based on security impact
        
        Returns:
            Dict mapping risk categories to weights
        """
        return {
            # Network-based risks
            'protocol_security': 0.15,
            'connection_anomalies': 0.12,
            'traffic_patterns': 0.10,
            'port_usage': 0.08,
            
            # Content-based risks
            'payload_threats': 0.20,
            'injection_attacks': 0.18,
            'malware_indicators': 0.15,
            'data_exfiltration': 0.12,
            
            # Behavioral risks
            'reconnaissance': 0.10,
            'privilege_escalation': 0.15,
            'lateral_movement': 0.12,
            'persistence': 0.10,
            
            # Data security risks
            'sensitive_data_exposure': 0.25,
            'encryption_weaknesses': 0.20,
            'authentication_bypass': 0.18,
            'access_control_violations': 0.15
        }
    
    def _initialize_compliance_mappings(self) -> Dict[str, Dict[str, List[str]]]:
        """
        Initialize compliance framework mappings
        
        Returns:
            Dict mapping frameworks to control mappings
        """
        return {
            'ISO_27001': {
                'A.9.1.1': ['authentication_bypass', 'access_control_violations'],
                'A.9.1.2': ['privilege_escalation', 'lateral_movement'],
                'A.9.2.1': ['port_usage', 'connection_anomalies'],
                'A.9.2.3': ['privilege_escalation', 'persistence'],
                'A.9.4.3': ['sensitive_data_exposure', 'authentication_bypass'],
                'A.10.1.1': ['encryption_weaknesses', 'sensitive_data_exposure'],
                'A.12.2.1': ['malware_indicators', 'payload_threats'],
                'A.12.6.1': ['reconnaissance', 'traffic_patterns'],
                'A.13.1.1': ['protocol_security', 'connection_anomalies'],
                'A.13.1.2': ['traffic_patterns', 'port_usage'],
                'A.13.2.1': ['data_exfiltration', 'protocol_security'],
                'A.14.2.5': ['injection_attacks', 'payload_threats'],
                'A.18.1.3': ['sensitive_data_exposure', 'data_exfiltration']
            },
            'NIST_CSF': {
                'ID.AM-1': ['reconnaissance', 'traffic_patterns'],
                'ID.AM-3': ['port_usage', 'connection_anomalies'],
                'PR.AC-1': ['authentication_bypass', 'access_control_violations'],
                'PR.AC-3': ['privilege_escalation', 'lateral_movement'],
                'PR.AC-4': ['access_control_violations', 'privilege_escalation'],
                'PR.AC-6': ['authentication_bypass', 'sensitive_data_exposure'],
                'PR.DS-1': ['sensitive_data_exposure', 'encryption_weaknesses'],
                'PR.DS-2': ['injection_attacks', 'payload_threats'],
                'PR.PT-1': ['malware_indicators', 'payload_threats'],
                'DE.AE-1': ['reconnaissance', 'traffic_patterns'],
                'DE.CM-1': ['connection_anomalies', 'traffic_patterns'],
                'DE.CM-4': ['malware_indicators', 'payload_threats'],
                'DE.DP-4': ['injection_attacks', 'malware_indicators'],
                'RS.RP-1': ['persistence', 'lateral_movement']
            },
            'OWASP_TOP10': {
                'A01:2021-Broken Access Control': ['access_control_violations', 'privilege_escalation'],
                'A02:2021-Cryptographic Failures': ['encryption_weaknesses', 'sensitive_data_exposure'],
                'A03:2021-Injection': ['injection_attacks', 'payload_threats'],
                'A04:2021-Insecure Design': ['protocol_security', 'connection_anomalies'],
                'A05:2021-Security Misconfiguration': ['port_usage', 'traffic_patterns'],
                'A06:2021-Vulnerable Components': ['malware_indicators', 'payload_threats'],
                'A07:2021-Identification and Authentication Failures': ['authentication_bypass'],
                'A08:2021-Software and Data Integrity Failures': ['malware_indicators', 'persistence'],
                'A09:2021-Security Logging and Monitoring Failures': ['reconnaissance', 'lateral_movement'],
                'A10:2021-Server-Side Request Forgery': ['injection_attacks', 'data_exfiltration']
            }
        }
    
    def _initialize_threat_patterns(self) -> Dict[str, Dict]:
        """
        Initialize threat pattern recognition rules
        
        Returns:
            Dict mapping threat patterns to scoring rules
        """
        return {
            'suspicious_ports': {
                'high_risk': [1433, 3389, 22, 21, 23],  # Database, RDP, SSH, FTP, Telnet
                'medium_risk': [135, 139, 445, 593, 1024],  # Windows services
                'score_multiplier': 1.5
            },
            'insecure_protocols': {
                'critical': ['FTP', 'Telnet', 'HTTP'],
                'high': ['SNMP', 'TFTP', 'Rlogin'],
                'score_multiplier': 2.0
            },
            'attack_patterns': {
                'reconnaissance': ['scan', 'enum', 'probe'],
                'exploitation': ['exploit', 'shell', 'payload'],
                'persistence': ['install', 'service', 'startup'],
                'exfiltration': ['copy', 'download', 'transfer']
            },
            'anomaly_thresholds': {
                'high_entropy': 7.0,
                'low_language_score': 0.3,
                'high_anomaly_score': 0.7,
                'retransmission_rate': 0.1,
                'packet_size_deviation': 3.0
            }
        }
    
    def _initialize_baseline_scores(self) -> Dict[str, float]:
        """
        Initialize baseline risk scores for different categories
        
        Returns:
            Dict mapping categories to baseline scores
        """
        return {
            'protocol_security': 10.0,
            'connection_anomalies': 15.0,
            'traffic_patterns': 10.0,
            'port_usage': 20.0,
            'payload_threats': 25.0,
            'injection_attacks': 30.0,
            'malware_indicators': 35.0,
            'data_exfiltration': 30.0,
            'reconnaissance': 20.0,
            'privilege_escalation': 40.0,
            'lateral_movement': 35.0,
            'persistence': 30.0,
            'sensitive_data_exposure': 50.0,
            'encryption_weaknesses': 45.0,
            'authentication_bypass': 45.0,
            'access_control_violations': 40.0
        }
    
    def calculate_protocol_risk(self, flows: Dict[str, ConnectionFlow]) -> RiskFactor:
        """
        Calculate risk based on protocol usage
        
        Args:
            flows: Network flows data
            
        Returns:
            RiskFactor for protocol security
        """
        if not flows:
            return RiskFactor(
                name="Protocol Security",
                category="protocol_security",
                score=0.0,
                weight=self.risk_weights['protocol_security'],
                description="No flows to analyze",
                evidence=[],
                mitigation="Ensure proper network monitoring",
                framework_mapping={}
            )
        
        risk_score = 0.0
        evidence = []
        
        # Count protocol usage
        protocol_counts = {}
        for flow in flows.values():
            # Handle both dict and object types
            if hasattr(flow, 'protocol'):
                protocol = flow.protocol
            elif isinstance(flow, dict):
                protocol = flow.get('protocol', 'Unknown')
            else:
                protocol = 'Unknown'
            protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
        
        # Check for insecure protocols
        insecure_protocols = self.threat_patterns['insecure_protocols']
        for protocol, count in protocol_counts.items():
            if protocol in insecure_protocols['critical']:
                risk_score += 40 * (count / len(flows))
                evidence.append(f"Critical insecure protocol: {protocol} ({count} flows)")
            elif protocol in insecure_protocols['high']:
                risk_score += 25 * (count / len(flows))
                evidence.append(f"High-risk protocol: {protocol} ({count} flows)")
        
        # Check for protocol diversity (too many protocols can be suspicious)
        protocol_diversity = len(protocol_counts)
        if protocol_diversity > 10:
            risk_score += min(20, protocol_diversity - 10)
            evidence.append(f"High protocol diversity: {protocol_diversity} different protocols")
        
        return RiskFactor(
            name="Protocol Security",
            category="protocol_security",
            score=min(100.0, risk_score),
            weight=self.risk_weights['protocol_security'],
            description="Risk assessment based on network protocol usage",
            evidence=evidence,
            mitigation="Disable unnecessary protocols, implement secure alternatives",
            framework_mapping={
                'ISO_27001': 'A.13.1.1',
                'NIST_CSF': 'PR.DS-2',
                'OWASP_TOP10': 'A04:2021-Insecure Design'
            }
        )
    
    def calculate_connection_anomaly_risk(self, connections: Dict[str, ConnectionStats]) -> RiskFactor:
        """
        Calculate risk based on connection anomalies
        
        Args:
            connections: Connection statistics
            
        Returns:
            RiskFactor for connection anomalies
        """
        if not connections:
            return RiskFactor(
                name="Connection Anomalies",
                category="connection_anomalies",
                score=0.0,
                weight=self.risk_weights['connection_anomalies'],
                description="No connections to analyze",
                evidence=[],
                mitigation="Implement connection monitoring",
                framework_mapping={}
            )
        
        risk_score = 0.0
        evidence = []
        
        # Collect metrics
        retrans_rates = []
        entropies = []
        durations = []
        
        for conn_key, stats in connections.items():
            # Handle both dict and object types
            if hasattr(stats, 'packets_sent'):
                total_packets = stats.packets_sent + stats.packets_received
                retrans_count = stats.retransmissions
                payload_entropy = stats.payload_entropy
                duration = stats.connection_duration
            elif isinstance(stats, dict):
                total_packets = stats.get('packets_sent', 0) + stats.get('packets_received', 0)
                retrans_count = stats.get('retransmissions', 0)
                payload_entropy = stats.get('payload_entropy', 0)
                duration = stats.get('connection_duration', 0)
            else:
                continue
                
            if total_packets > 0:
                retrans_rate = retrans_count / total_packets
                retrans_rates.append(retrans_rate)
                
                # High retransmission rate
                if retrans_rate > self.threat_patterns['anomaly_thresholds']['retransmission_rate']:
                    risk_score += 15
                    evidence.append(f"High retransmission rate: {retrans_rate:.2%} for {conn_key[:50]}")
            
            # High entropy in payload
            if payload_entropy > self.threat_patterns['anomaly_thresholds']['high_entropy']:
                risk_score += 20
                evidence.append(f"High payload entropy: {payload_entropy:.2f} for {conn_key[:50]}")
                entropies.append(payload_entropy)
            
            # Very long or very short connections
            if duration > 3600:  # > 1 hour
                risk_score += 10
                evidence.append(f"Long duration connection: {duration:.0f}s")
            elif duration < 0.1 and total_packets > 10:  # Very short but many packets
                risk_score += 15
                evidence.append(f"High-speed connection: {total_packets} packets in {duration:.2f}s")
            
            durations.append(duration)
        
        # Statistical anomalies
        if len(retrans_rates) > 1:
            avg_retrans = statistics.mean(retrans_rates)
            if avg_retrans > 0.05:  # 5% retransmission rate
                risk_score += 25
                evidence.append(f"High average retransmission rate: {avg_retrans:.2%}")
        
        return RiskFactor(
            name="Connection Anomalies",
            category="connection_anomalies",
            score=min(100.0, risk_score),
            weight=self.risk_weights['connection_anomalies'],
            description="Risk assessment based on connection behavior anomalies",
            evidence=evidence[:10],  # Limit evidence
            mitigation="Monitor connection patterns, investigate anomalous behavior",
            framework_mapping={
                'ISO_27001': 'A.12.6.1',
                'NIST_CSF': 'DE.CM-1',
                'OWASP_TOP10': 'A09:2021-Security Logging and Monitoring Failures'
            }
        )
    
    def calculate_payload_threat_risk(self, threat_matches: List[ThreatMatch], 
                                    nlp_analyses: List[PayloadAnalysis]) -> RiskFactor:
        """
        Calculate risk based on payload threats
        
        Args:
            threat_matches: Regex-based threat detections
            nlp_analyses: NLP-based payload analyses
            
        Returns:
            RiskFactor for payload threats
        """
        risk_score = 0.0
        evidence = []
        
        # Process regex threat matches
        if threat_matches:
            severity_scores = {
                ThreatSeverity.LOW: 10,
                ThreatSeverity.MEDIUM: 25,
                ThreatSeverity.HIGH: 50,
                ThreatSeverity.CRITICAL: 80
            }
            
            category_counts = {}
            for match in threat_matches:
                score_add = severity_scores.get(match.severity, 10)
                risk_score += score_add
                
                category_counts[match.category] = category_counts.get(match.category, 0) + 1
                evidence.append(f"{match.severity.name}: {match.description}")
            
            # Bonus for multiple threat categories
            if len(category_counts) > 3:
                risk_score += 20
                evidence.append(f"Multiple threat categories detected: {list(category_counts.keys())}")
        
        # Process NLP analyses
        if nlp_analyses:
            high_anomaly_count = sum(1 for analysis in nlp_analyses 
                                   if analysis.anomaly_score > 0.7)
            if high_anomaly_count > 0:
                risk_score += min(40, high_anomaly_count * 10)
                evidence.append(f"High anomaly payloads detected: {high_anomaly_count}")
            
            # Check for encoding
            base64_count = sum(1 for analysis in nlp_analyses 
                             if analysis.base64_likelihood > 0.7)
            if base64_count > 0:
                risk_score += min(20, base64_count * 5)
                evidence.append(f"Base64 encoded content detected: {base64_count}")
        
        return RiskFactor(
            name="Payload Threats",
            category="payload_threats",
            score=min(100.0, risk_score),
            weight=self.risk_weights['payload_threats'],
            description="Risk assessment based on payload content analysis",
            evidence=evidence[:15],
            mitigation="Implement payload inspection, content filtering, and signature-based detection",
            framework_mapping={
                'ISO_27001': 'A.12.2.1',
                'NIST_CSF': 'DE.CM-4',
                'OWASP_TOP10': 'A03:2021-Injection'
            }
        )
    
    def calculate_port_usage_risk(self, flows: Dict[str, ConnectionFlow]) -> RiskFactor:
        """
        Calculate risk based on port usage patterns
        
        Args:
            flows: Network flows data
            
        Returns:
            RiskFactor for port usage
        """
        if not flows:
            return RiskFactor(
                name="Port Usage",
                category="port_usage",
                score=0.0,
                weight=self.risk_weights['port_usage'],
                description="No flows to analyze",
                evidence=[],
                mitigation="Implement port monitoring",
                framework_mapping={}
            )
        
        risk_score = 0.0
        evidence = []
        
        # Collect port usage
        src_ports = []
        dst_ports = []
        
        for flow in flows.values():
            # Handle both dict and object types
            if hasattr(flow, 'src_port'):
                if flow.src_port:
                    src_ports.append(flow.src_port)
                if flow.dst_port:
                    dst_ports.append(flow.dst_port)
            elif isinstance(flow, dict):
                if flow.get('src_port'):
                    src_ports.append(flow.get('src_port'))
                if flow.get('dst_port'):
                    dst_ports.append(flow.get('dst_port'))
        
        all_ports = src_ports + dst_ports
        port_counts = {}
        for port in all_ports:
            port_counts[port] = port_counts.get(port, 0) + 1
        
        # Check for high-risk ports
        suspicious_ports = self.threat_patterns['suspicious_ports']
        for port, count in port_counts.items():
            if port in suspicious_ports['high_risk']:
                risk_score += 30 * (count / len(flows))
                evidence.append(f"High-risk port {port} used in {count} flows")
            elif port in suspicious_ports['medium_risk']:
                risk_score += 15 * (count / len(flows))
                evidence.append(f"Medium-risk port {port} used in {count} flows")
        
        # Check for port scanning indicators
        unique_dst_ports = len(set(dst_ports))
        if unique_dst_ports > 50:
            risk_score += min(30, unique_dst_ports - 50)
            evidence.append(f"High port diversity: {unique_dst_ports} unique destination ports")
        
        # Check for unusual high ports
        high_ports = [p for p in all_ports if p > 32768]
        if len(high_ports) > len(all_ports) * 0.8:  # More than 80% high ports
            risk_score += 15
            evidence.append(f"High proportion of ephemeral ports: {len(high_ports)}/{len(all_ports)}")
        
        return RiskFactor(
            name="Port Usage",
            category="port_usage",
            score=min(100.0, risk_score),
            weight=self.risk_weights['port_usage'],
            description="Risk assessment based on network port usage patterns",
            evidence=evidence,
            mitigation="Implement port-based access controls, monitor for port scanning",
            framework_mapping={
                'ISO_27001': 'A.13.1.2',
                'NIST_CSF': 'ID.AM-3',
                'OWASP_TOP10': 'A05:2021-Security Misconfiguration'
            }
        )
    
    def calculate_data_exposure_risk(self, threat_matches: List[ThreatMatch]) -> RiskFactor:
        """
        Calculate risk for sensitive data exposure
        
        Args:
            threat_matches: Threat detection results
            
        Returns:
            RiskFactor for data exposure
        """
        risk_score = 0.0
        evidence = []
        
        # Check for sensitive data patterns
        sensitive_categories = ['sensitive_data', 'credentials']
        
        for match in threat_matches:
            if match.category in sensitive_categories:
                if match.severity == ThreatSeverity.CRITICAL:
                    risk_score += 60
                    evidence.append(f"CRITICAL: {match.description}")
                elif match.severity == ThreatSeverity.HIGH:
                    risk_score += 40
                    evidence.append(f"HIGH: {match.description}")
                elif match.severity == ThreatSeverity.MEDIUM:
                    risk_score += 20
                    evidence.append(f"MEDIUM: {match.description}")
        
        return RiskFactor(
            name="Sensitive Data Exposure",
            category="sensitive_data_exposure",
            score=min(100.0, risk_score),
            weight=self.risk_weights['sensitive_data_exposure'],
            description="Risk assessment for sensitive data exposure",
            evidence=evidence,
            mitigation="Implement data classification, encryption, and access controls",
            framework_mapping={
                'ISO_27001': 'A.18.1.3',
                'NIST_CSF': 'PR.DS-1',
                'OWASP_TOP10': 'A02:2021-Cryptographic Failures'
            }
        )
    
    def generate_compliance_mapping(self, risk_factors: List[RiskFactor]) -> Dict[str, List[str]]:
        """
        Generate compliance framework mapping from risk factors
        
        Args:
            risk_factors: List of identified risk factors
            
        Returns:
            Dict mapping frameworks to relevant controls
        """
        mapping = {
            'ISO_27001': [],
            'NIST_CSF': [],
            'OWASP_TOP10': []
        }
        
        for factor in risk_factors:
            for framework, control in factor.framework_mapping.items():
                if control not in mapping[framework]:
                    mapping[framework].append(control)
        
        return mapping
    
    def generate_recommendations(self, risk_factors: List[RiskFactor]) -> List[str]:
        """
        Generate prioritized security recommendations
        
        Args:
            risk_factors: List of risk factors
            
        Returns:
            List of prioritized recommendations
        """
        recommendations = []
        
        # Sort by weighted score
        sorted_factors = sorted(risk_factors, 
                              key=lambda x: x.score * x.weight, reverse=True)
        
        for factor in sorted_factors[:10]:  # Top 10 risks
            if factor.score > 50:  # High risk threshold
                recommendations.append(
                    f"HIGH PRIORITY - {factor.name}: {factor.mitigation}"
                )
            elif factor.score > 25:  # Medium risk threshold
                recommendations.append(
                    f"MEDIUM PRIORITY - {factor.name}: {factor.mitigation}"
                )
        
        # Add general recommendations
        recommendations.extend([
            "Implement comprehensive network monitoring and logging",
            "Regular security assessments and penetration testing",
            "Employee security awareness training",
            "Incident response plan testing and updates",
            "Regular software updates and patch management"
        ])
        
        return recommendations[:15]  # Limit recommendations
    
    def calculate_comprehensive_risk(self, 
                                   flows: Dict[str, ConnectionFlow],
                                   connections: Dict[str, ConnectionStats],
                                   threat_matches: List[ThreatMatch],
                                   nlp_analyses: List[PayloadAnalysis]) -> RiskAssessment:
        """
        Calculate comprehensive risk assessment
        
        Args:
            flows: Network flows
            connections: Connection statistics
            threat_matches: Threat detection results
            nlp_analyses: NLP payload analyses
            
        Returns:
            RiskAssessment with complete risk analysis
        """
        risk_factors = []
        
        risk_factors.append(self.calculate_protocol_risk(flows))
        risk_factors.append(self.calculate_connection_anomaly_risk(connections))
        risk_factors.append(self.calculate_payload_threat_risk(threat_matches, nlp_analyses))
        risk_factors.append(self.calculate_port_usage_risk(flows))
        risk_factors.append(self.calculate_data_exposure_risk(threat_matches))
        
        total_weighted_score = 0.0
        total_weight = 0.0
        
        category_scores = {}
        for factor in risk_factors:
            weighted_score = factor.score * factor.weight
            total_weighted_score += weighted_score
            total_weight += factor.weight
            category_scores[factor.category] = factor.score
        
        overall_score = total_weighted_score / total_weight if total_weight > 0 else 0.0
        
        # Determine risk level
        if overall_score >= 80:
            risk_level = RiskLevel.CRITICAL
        elif overall_score >= 60:
            risk_level = RiskLevel.HIGH
        elif overall_score >= 40:
            risk_level = RiskLevel.MEDIUM
        elif overall_score >= 20:
            risk_level = RiskLevel.LOW
        else:
            risk_level = RiskLevel.MINIMAL
        
        # Calculate confidence based on data availability
        confidence = min(1.0, 
                        (len(flows) + len(connections) + len(threat_matches) + len(nlp_analyses)) / 100.0)
        
        # Generate compliance mapping and recommendations
        compliance_mapping = self.generate_compliance_mapping(risk_factors)
        recommendations = self.generate_recommendations(risk_factors)
        
        return RiskAssessment(
            overall_score=overall_score,
            risk_level=risk_level,
            risk_factors=risk_factors,
            category_scores=category_scores,
            compliance_mapping=compliance_mapping,
            recommendations=recommendations,
            timestamp=datetime.now(),
            confidence=confidence
        )


if __name__ == "__main__":
    # Example usage
    print("Risk Calculator - Example usage requires data from other modules")
    calculator = RiskCalculator()
    print(f"Initialized with {len(calculator.risk_weights)} risk categories")
    print(f"Supporting {len(calculator.compliance_mappings)} compliance frameworks")
