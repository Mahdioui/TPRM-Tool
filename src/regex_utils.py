"""
Regex Utilities - Centralized threat detection using regular expressions
Provides comprehensive regex-based detection for various cybersecurity threats
"""

import re
import logging
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class ThreatSeverity(Enum):
    """Threat severity levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class ThreatMatch:
    """Structure to hold threat detection results"""
    rule_name: str
    category: str
    severity: ThreatSeverity
    pattern: str
    matched_text: str
    description: str
    mitigation: str
    owasp_category: Optional[str] = None
    nist_category: Optional[str] = None
    iso_category: Optional[str] = None

class RegexThreatDetector:
    """
    Comprehensive threat detection engine using regular expressions
    Covers various attack vectors and suspicious patterns
    """
    
    def __init__(self):
        """Initialize the threat detector with predefined rules"""
        self.rules = self._initialize_rules()
        self.compiled_patterns = {}
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile all regex patterns for better performance"""
        for category, rules in self.rules.items():
            self.compiled_patterns[category] = {}
            for rule_name, rule_data in rules.items():
                try:
                    flags = re.IGNORECASE | re.MULTILINE
                    if rule_data.get('dotall', False):
                        flags |= re.DOTALL
                    
                    self.compiled_patterns[category][rule_name] = re.compile(
                        rule_data['pattern'], flags
                    )
                except re.error as e:
                    logger.error(f"Error compiling pattern for {rule_name}: {e}")
    
    def _initialize_rules(self) -> Dict[str, Dict[str, Dict]]:
        """
        Initialize comprehensive threat detection rules
        
        Returns:
            Dict containing organized threat detection rules
        """
        return {
            # SQL Injection Detection
            'sql_injection': {
                'sql_union_attack': {
                    'pattern': r'\bunion\s+select\b|union\s+all\s+select',
                    'severity': ThreatSeverity.HIGH,
                    'description': 'SQL UNION-based injection attempt detected',
                    'mitigation': 'Use parameterized queries and input validation',
                    'owasp': 'A03:2021 - Injection',
                    'nist': 'PR.DS-2',
                    'iso': 'A.14.2.5'
                },
                'sql_comment_injection': {
                    'pattern': r'(/\*.*?\*/|--|\#)',
                    'severity': ThreatSeverity.MEDIUM,
                    'description': 'SQL comment-based injection attempt',
                    'mitigation': 'Sanitize input and use prepared statements',
                    'owasp': 'A03:2021 - Injection',
                    'nist': 'PR.DS-2',
                    'iso': 'A.14.2.5'
                },
                'sql_boolean_blind': {
                    'pattern': r'\b(and|or)\s+\d+\s*=\s*\d+|\b(and|or)\s+[\'"`]\w*[\'"`]\s*=\s*[\'"`]\w*[\'"`]',
                    'severity': ThreatSeverity.HIGH,
                    'description': 'Boolean-based blind SQL injection',
                    'mitigation': 'Implement strict input validation',
                    'owasp': 'A03:2021 - Injection',
                    'nist': 'PR.DS-2',
                    'iso': 'A.14.2.5'
                },
                'sql_time_blind': {
                    'pattern': r'\bwaitfor\s+delay\b|\bsleep\s*\(|\bbenchmark\s*\(',
                    'severity': ThreatSeverity.HIGH,
                    'description': 'Time-based blind SQL injection',
                    'mitigation': 'Use parameterized queries and timeout controls',
                    'owasp': 'A03:2021 - Injection',
                    'nist': 'PR.DS-2',
                    'iso': 'A.14.2.5'
                }
            },
            
            # Cross-Site Scripting (XSS) Detection
            'xss': {
                'script_injection': {
                    'pattern': r'<script[^>]*>.*?</script>|javascript:|vbscript:|onload\s*=|onerror\s*=',
                    'severity': ThreatSeverity.HIGH,
                    'description': 'Script injection attempt detected',
                    'mitigation': 'Implement Content Security Policy and input encoding',
                    'owasp': 'A03:2021 - Injection',
                    'nist': 'PR.DS-2',
                    'iso': 'A.14.2.5'
                },
                'html_injection': {
                    'pattern': r'<(iframe|object|embed|form|img)[^>]*>',
                    'severity': ThreatSeverity.MEDIUM,
                    'description': 'HTML injection attempt',
                    'mitigation': 'Sanitize HTML input and use allow-lists',
                    'owasp': 'A03:2021 - Injection',
                    'nist': 'PR.DS-2',
                    'iso': 'A.14.2.5'
                },
                'event_handler_injection': {
                    'pattern': r'on\w+\s*=\s*[\'"][^\'">]*[\'"]',
                    'severity': ThreatSeverity.MEDIUM,
                    'description': 'JavaScript event handler injection',
                    'mitigation': 'Remove or encode JavaScript event handlers',
                    'owasp': 'A03:2021 - Injection',
                    'nist': 'PR.DS-2',
                    'iso': 'A.14.2.5'
                }
            },
            
            # Command Injection Detection
            'command_injection': {
                'shell_commands': {
                    'pattern': r'\b(cmd\.exe|powershell|bash|sh|/bin/|system\(|exec\(|eval\()',
                    'severity': ThreatSeverity.CRITICAL,
                    'description': 'Shell command execution attempt',
                    'mitigation': 'Use parameterized commands and input validation',
                    'owasp': 'A03:2021 - Injection',
                    'nist': 'PR.AC-4',
                    'iso': 'A.12.2.1'
                },
                'command_separators': {
                    'pattern': r'[;&|`$\(\){}]',
                    'severity': ThreatSeverity.MEDIUM,
                    'description': 'Command separator characters detected',
                    'mitigation': 'Sanitize input and use safe APIs',
                    'owasp': 'A03:2021 - Injection',
                    'nist': 'PR.AC-4',
                    'iso': 'A.12.2.1'
                },
                'windows_commands': {
                    'pattern': r'\b(net\s+user|net\s+group|reg\s+add|schtasks|wmic)',
                    'severity': ThreatSeverity.HIGH,
                    'description': 'Windows administrative command detected',
                    'mitigation': 'Restrict command execution and monitor admin activities',
                    'owasp': 'A03:2021 - Injection',
                    'nist': 'PR.AC-4',
                    'iso': 'A.9.2.3'
                }
            },
            
            # Suspicious Domains and URLs
            'suspicious_domains': {
                'suspicious_tlds': {
                    'pattern': r'\b\w+\.(tk|ml|ga|cf|xyz|club|download|click|stream|science|cricket)\b',
                    'severity': ThreatSeverity.MEDIUM,
                    'description': 'Suspicious top-level domain detected',
                    'mitigation': 'Monitor and restrict access to suspicious domains',
                    'owasp': 'A06:2021 - Vulnerable Components',
                    'nist': 'DE.CM-1',
                    'iso': 'A.13.2.1'
                },
                'ip_based_urls': {
                    'pattern': r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
                    'severity': ThreatSeverity.MEDIUM,
                    'description': 'IP-based URL detected (potential domain fronting)',
                    'mitigation': 'Monitor direct IP connections and implement DNS filtering',
                    'owasp': 'A06:2021 - Vulnerable Components',
                    'nist': 'DE.CM-1',
                    'iso': 'A.13.1.1'
                },
                'url_shorteners': {
                    'pattern': r'\b(bit\.ly|tinyurl|goo\.gl|t\.co|short\.link|tiny\.cc)\b',
                    'severity': ThreatSeverity.LOW,
                    'description': 'URL shortener service detected',
                    'mitigation': 'Expand shortened URLs and verify destinations',
                    'owasp': 'A05:2021 - Security Misconfiguration',
                    'nist': 'DE.CM-1',
                    'iso': 'A.13.2.1'
                },
                'typosquatting': {
                    'pattern': r'\b(gooogle|microsft|paypal1|amazom|facebbok|twiter)\.',
                    'severity': ThreatSeverity.HIGH,
                    'description': 'Potential typosquatting domain detected',
                    'mitigation': 'Implement domain reputation checking',
                    'owasp': 'A05:2021 - Security Misconfiguration',
                    'nist': 'DE.CM-1',
                    'iso': 'A.13.2.1'
                }
            },
            
            # DNS Suspicious Patterns
            'dns_threats': {
                'dns_tunneling': {
                    'pattern': r'\b[a-f0-9]{32,}\.',
                    'severity': ThreatSeverity.HIGH,
                    'description': 'Potential DNS tunneling detected (long hex strings)',
                    'mitigation': 'Monitor DNS query patterns and implement DGA detection',
                    'owasp': 'A06:2021 - Vulnerable Components',
                    'nist': 'DE.CM-1',
                    'iso': 'A.13.1.1'
                },
                'dga_domains': {
                    'pattern': r'\b[bcdfghjklmnpqrstvwxyz]{8,}\.(com|net|org|info)\b',
                    'severity': ThreatSeverity.MEDIUM,
                    'description': 'Potential domain generation algorithm (DGA) domain',
                    'mitigation': 'Implement DGA detection and DNS monitoring',
                    'owasp': 'A06:2021 - Vulnerable Components',
                    'nist': 'DE.CM-1',
                    'iso': 'A.13.1.1'
                },
                'suspicious_subdomains': {
                    'pattern': r'\b(admin|test|dev|staging|backup|mail|ftp|secure|login)\d*\.',
                    'severity': ThreatSeverity.LOW,
                    'description': 'Suspicious subdomain pattern detected',
                    'mitigation': 'Monitor subdomain usage and implement controls',
                    'owasp': 'A05:2021 - Security Misconfiguration',
                    'nist': 'DE.CM-1',
                    'iso': 'A.13.1.2'
                }
            },
            
            # HTTP Threat Patterns
            'http_threats': {
                'path_traversal': {
                    'pattern': r'\.\.[\\/]|%2e%2e[\\/]|%252e%252e[\\/]',
                    'severity': ThreatSeverity.HIGH,
                    'description': 'Path traversal attack attempt',
                    'mitigation': 'Implement path validation and access controls',
                    'owasp': 'A01:2021 - Broken Access Control',
                    'nist': 'PR.AC-4',
                    'iso': 'A.9.1.2'
                },
                'http_verb_tampering': {
                    'pattern': r'\b(TRACE|TRACK|DEBUG|OPTIONS|CONNECT)\b',
                    'severity': ThreatSeverity.MEDIUM,
                    'description': 'Potentially dangerous HTTP method detected',
                    'mitigation': 'Disable unnecessary HTTP methods',
                    'owasp': 'A05:2021 - Security Misconfiguration',
                    'nist': 'PR.AC-4',
                    'iso': 'A.13.1.1'
                },
                'suspicious_user_agents': {
                    'pattern': r'(sqlmap|nmap|nikto|burp|w3af|acunetix|nessus|openvas)',
                    'severity': ThreatSeverity.HIGH,
                    'description': 'Security scanner user agent detected',
                    'mitigation': 'Block scanner user agents and monitor for reconnaissance',
                    'owasp': 'A05:2021 - Security Misconfiguration',
                    'nist': 'DE.CM-1',
                    'iso': 'A.12.6.1'
                },
                'file_inclusion': {
                    'pattern': r'(include\s*\(|require\s*\(|include_once\s*\(|require_once\s*\()',
                    'severity': ThreatSeverity.HIGH,
                    'description': 'File inclusion function detected',
                    'mitigation': 'Validate file paths and use allow-lists',
                    'owasp': 'A03:2021 - Injection',
                    'nist': 'PR.DS-2',
                    'iso': 'A.14.2.5'
                }
            },
            
            # Credential and Sensitive Data Patterns
            'sensitive_data': {
                'passwords_in_clear': {
                    'pattern': r'(password|passwd|pwd)\s*[:=]\s*[\'"]?[^\s\'"]{4,}',
                    'severity': ThreatSeverity.HIGH,
                    'description': 'Cleartext password detected',
                    'mitigation': 'Encrypt passwords and use secure storage',
                    'owasp': 'A02:2021 - Cryptographic Failures',
                    'nist': 'PR.DS-1',
                    'iso': 'A.10.1.1'
                },
                'api_keys': {
                    'pattern': r'(api[_-]?key|apikey|access[_-]?token)\s*[:=]\s*[\'"]?[a-zA-Z0-9]{16,}',
                    'severity': ThreatSeverity.HIGH,
                    'description': 'API key or access token detected',
                    'mitigation': 'Secure API keys and implement rotation',
                    'owasp': 'A02:2021 - Cryptographic Failures',
                    'nist': 'PR.AC-1',
                    'iso': 'A.9.4.3'
                },
                'credit_cards': {
                    'pattern': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
                    'severity': ThreatSeverity.CRITICAL,
                    'description': 'Credit card number pattern detected',
                    'mitigation': 'Implement PCI DSS compliance and data masking',
                    'owasp': 'A02:2021 - Cryptographic Failures',
                    'nist': 'PR.DS-1',
                    'iso': 'A.18.1.3'
                },
                'social_security': {
                    'pattern': r'\b\d{3}-\d{2}-\d{4}\b',
                    'severity': ThreatSeverity.CRITICAL,
                    'description': 'Social Security Number pattern detected',
                    'mitigation': 'Implement data classification and protection',
                    'owasp': 'A02:2021 - Cryptographic Failures',
                    'nist': 'PR.DS-1',
                    'iso': 'A.18.1.3'
                }
            },
            
            # Malware and Exploit Patterns
            'malware_indicators': {
                'executable_downloads': {
                    'pattern': r'\.(exe|scr|bat|cmd|com|pif|vbs|js|jar|zip|rar)\b',
                    'severity': ThreatSeverity.MEDIUM,
                    'description': 'Executable file extension detected',
                    'mitigation': 'Scan downloads and restrict executable types',
                    'owasp': 'A06:2021 - Vulnerable Components',
                    'nist': 'DE.CM-4',
                    'iso': 'A.12.2.1'
                },
                'base64_payloads': {
                    'pattern': r'[A-Za-z0-9+/]{50,}={0,2}',
                    'severity': ThreatSeverity.MEDIUM,
                    'description': 'Potential Base64 encoded payload',
                    'mitigation': 'Decode and analyze suspicious Base64 content',
                    'owasp': 'A03:2021 - Injection',
                    'nist': 'DE.CM-1',
                    'iso': 'A.12.6.1'
                },
                'shell_code_patterns': {
                    'pattern': r'\\x[0-9a-fA-F]{2}|%u[0-9a-fA-F]{4}|\\u[0-9a-fA-F]{4}',
                    'severity': ThreatSeverity.HIGH,
                    'description': 'Potential shellcode pattern detected',
                    'mitigation': 'Block and analyze potential shellcode',
                    'owasp': 'A03:2021 - Injection',
                    'nist': 'DE.CM-4',
                    'iso': 'A.12.2.1'
                }
            },
            
            # Network Reconnaissance
            'reconnaissance': {
                'port_scanning': {
                    'pattern': r'(nmap|masscan|zmap|unicornscan)',
                    'severity': ThreatSeverity.MEDIUM,
                    'description': 'Port scanning tool detected',
                    'mitigation': 'Monitor and block reconnaissance activities',
                    'owasp': 'A05:2021 - Security Misconfiguration',
                    'nist': 'DE.CM-1',
                    'iso': 'A.12.6.1'
                },
                'vulnerability_scanning': {
                    'pattern': r'(nessus|openvas|nexpose|qualys|rapid7)',
                    'severity': ThreatSeverity.MEDIUM,
                    'description': 'Vulnerability scanner detected',
                    'mitigation': 'Monitor scanning activities and harden systems',
                    'owasp': 'A05:2021 - Security Misconfiguration',
                    'nist': 'DE.CM-1',
                    'iso': 'A.12.6.1'
                },
                'web_crawling': {
                    'pattern': r'(wget|curl|crawler|spider|bot|scraper)',
                    'severity': ThreatSeverity.LOW,
                    'description': 'Web crawling activity detected',
                    'mitigation': 'Implement rate limiting and bot detection',
                    'owasp': 'A05:2021 - Security Misconfiguration',
                    'nist': 'DE.CM-1',
                    'iso': 'A.13.1.1'
                }
            }
        }
    
    def scan_text(self, text: str, categories: Optional[List[str]] = None) -> List[ThreatMatch]:
        """
        Scan text for threat patterns
        
        Args:
            text: Text to scan
            categories: List of categories to scan (None for all)
            
        Returns:
            List of ThreatMatch objects for detected threats
        """
        if not text:
            return []
        
        matches = []
        scan_categories = categories or list(self.rules.keys())
        
        for category in scan_categories:
            if category not in self.compiled_patterns:
                continue
                
            for rule_name, pattern in self.compiled_patterns[category].items():
                try:
                    regex_matches = pattern.finditer(text)
                    for match in regex_matches:
                        rule_data = self.rules[category][rule_name]
                        
                        threat_match = ThreatMatch(
                            rule_name=rule_name,
                            category=category,
                            severity=rule_data['severity'],
                            pattern=rule_data['pattern'],
                            matched_text=match.group(0),
                            description=rule_data['description'],
                            mitigation=rule_data['mitigation'],
                            owasp_category=rule_data.get('owasp'),
                            nist_category=rule_data.get('nist'),
                            iso_category=rule_data.get('iso')
                        )
                        
                        matches.append(threat_match)
                        
                except Exception as e:
                    logger.error(f"Error scanning with rule {rule_name}: {e}")
        
        return matches
    
    def scan_payload(self, payload: str) -> List[ThreatMatch]:
        """
        Scan network payload for threats
        
        Args:
            payload: Network payload to scan
            
        Returns:
            List of detected threats
        """
        return self.scan_text(payload)
    
    def scan_url(self, url: str) -> List[ThreatMatch]:
        """
        Scan URL for suspicious patterns
        
        Args:
            url: URL to scan
            
        Returns:
            List of detected threats
        """
        relevant_categories = ['suspicious_domains', 'http_threats', 'malware_indicators']
        return self.scan_text(url, relevant_categories)
    
    def scan_dns_query(self, query: str) -> List[ThreatMatch]:
        """
        Scan DNS query for threats
        
        Args:
            query: DNS query to scan
            
        Returns:
            List of detected threats
        """
        relevant_categories = ['dns_threats', 'suspicious_domains']
        return self.scan_text(query, relevant_categories)
    
    def scan_http_content(self, content: str) -> List[ThreatMatch]:
        """
        Scan HTTP content for injection attacks
        
        Args:
            content: HTTP content to scan
            
        Returns:
            List of detected threats
        """
        relevant_categories = ['sql_injection', 'xss', 'command_injection', 'http_threats']
        return self.scan_text(content, relevant_categories)
    
    def get_threat_summary(self, matches: List[ThreatMatch]) -> Dict[str, Any]:
        """
        Generate summary statistics for threat matches
        
        Args:
            matches: List of threat matches
            
        Returns:
            Dict with threat summary
        """
        if not matches:
            return {
                'total_threats': 0,
                'severity_distribution': {},
                'category_distribution': {},
                'owasp_mapping': {},
                'nist_mapping': {},
                'iso_mapping': {}
            }
        
        summary = {
            'total_threats': len(matches),
            'severity_distribution': {},
            'category_distribution': {},
            'owasp_mapping': {},
            'nist_mapping': {},
            'iso_mapping': {},
            'top_threats': []
        }
        
        # Count by severity
        for match in matches:
            severity_name = match.severity.name
            summary['severity_distribution'][severity_name] = \
                summary['severity_distribution'].get(severity_name, 0) + 1
        
        # Count by category
        for match in matches:
            category = match.category
            summary['category_distribution'][category] = \
                summary['category_distribution'].get(category, 0) + 1
        
        # Map to frameworks
        for match in matches:
            if match.owasp_category:
                summary['owasp_mapping'][match.owasp_category] = \
                    summary['owasp_mapping'].get(match.owasp_category, 0) + 1
            
            if match.nist_category:
                summary['nist_mapping'][match.nist_category] = \
                    summary['nist_mapping'].get(match.nist_category, 0) + 1
            
            if match.iso_category:
                summary['iso_mapping'][match.iso_category] = \
                    summary['iso_mapping'].get(match.iso_category, 0) + 1
        
        # Get top threats by severity
        sorted_matches = sorted(matches, key=lambda x: x.severity.value, reverse=True)
        summary['top_threats'] = [
            {
                'rule_name': match.rule_name,
                'category': match.category,
                'severity': match.severity.name,
                'description': match.description,
                'matched_text': match.matched_text[:100] + '...' if len(match.matched_text) > 100 else match.matched_text
            }
            for match in sorted_matches[:10]
        ]
        
        return summary
    
    def add_custom_rule(self, category: str, rule_name: str, pattern: str, 
                       severity: ThreatSeverity, description: str, 
                       mitigation: str, **kwargs):
        """
        Add a custom threat detection rule
        
        Args:
            category: Rule category
            rule_name: Unique rule name
            pattern: Regex pattern
            severity: Threat severity level
            description: Rule description
            mitigation: Mitigation advice
            **kwargs: Additional metadata (owasp, nist, iso)
        """
        if category not in self.rules:
            self.rules[category] = {}
        
        self.rules[category][rule_name] = {
            'pattern': pattern,
            'severity': severity,
            'description': description,
            'mitigation': mitigation,
            **kwargs
        }
        
        # Recompile patterns
        self._compile_patterns()
        
        logger.info(f"Added custom rule: {category}.{rule_name}")


if __name__ == "__main__":
    # Example usage and testing
    detector = RegexThreatDetector()
    
    # Test samples
    test_samples = [
        "SELECT * FROM users WHERE id = 1 UNION SELECT password FROM admin",
        "<script>alert('XSS')</script>",
        "http://192.168.1.1/malware.exe",
        "api_key=abc123def456ghi789jkl012",
        "password=secretpassword123"
    ]
    
    print("=== Regex Threat Detection Demo ===")
    for sample in test_samples:
        print(f"\nTesting: {sample}")
        matches = detector.scan_text(sample)
        for match in matches:
            print(f"  - {match.rule_name}: {match.description} (Severity: {match.severity.name})")
    
    # Summary
    all_matches = []
    for sample in test_samples:
        all_matches.extend(detector.scan_text(sample))
    
    summary = detector.get_threat_summary(all_matches)
    print(f"\n=== Summary ===")
    print(f"Total threats detected: {summary['total_threats']}")
    print(f"Severity distribution: {summary['severity_distribution']}")
    print(f"Category distribution: {summary['category_distribution']}")
