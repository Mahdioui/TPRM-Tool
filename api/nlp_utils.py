import re
import string
from collections import Counter

class SimpleNLPAnalyzer:
    """Simple NLP analyzer without external dependencies"""
    
    def __init__(self):
        # Common malicious keywords and patterns
        self.malicious_keywords = [
            'malware', 'virus', 'trojan', 'backdoor', 'rootkit', 'spyware',
            'keylogger', 'ransomware', 'botnet', 'ddos', 'phishing', 'scam',
            'hack', 'exploit', 'vulnerability', 'breach', 'leak', 'steal',
            'password', 'credential', 'token', 'session', 'cookie', 'auth',
            'admin', 'root', 'privilege', 'escalation', 'bypass', 'injection',
            'sql', 'xss', 'csrf', 'lfi', 'rfi', 'command', 'execution',
            'download', 'upload', 'transfer', 'exfiltrate', 'data', 'sensitive'
        ]
        
        # Suspicious command patterns
        self.suspicious_commands = [
            r'cmd\.exe', r'powershell', r'wget', r'curl', r'nc\s+-l', r'ncat\s+-l',
            r'python\s+-c', r'perl\s+-e', r'bash\s+-c', r'sh\s+-c', r'\.exe\s+',
            r'\.bat\s+', r'\.ps1\s+', r'\.vbs\s+', r'\.js\s+', r'\.py\s+',
            r'net\s+cat', r'netcat', r'telnet', r'ssh\s+', r'scp\s+', r'rsync\s+'
        ]
        
        # Data exfiltration patterns
        self.exfiltration_patterns = [
            r'POST\s+/upload', r'POST\s+/data', r'GET\s+/download', r'FTP\s+STOR',
            r'SMTP\s+DATA', r'HTTP/1\.1\s+200', r'Content-Length:\s+\d+',
            r'Transfer-Encoding:\s+chunked', r'base64', r'hex', r'encrypt'
        ]
        
        # Network scanning patterns
        self.scanning_patterns = [
            r'port\s+scan', r'nmap', r'ping\s+sweep', r'arp\s+scan', r'syn\s+flood',
            r'udp\s+flood', r'icmp\s+flood', r'brute\s+force', r'dictionary\s+attack',
            r'rainbow\s+table', r'hash\s+cracking', r'password\s+spray'
        ]
    
    def analyze_text(self, text):
        """Analyze text for malicious content"""
        if not text:
            return {}
        
        # Convert to lowercase for analysis
        text_lower = text.lower()
        
        # Count malicious keywords
        keyword_matches = []
        for keyword in self.malicious_keywords:
            if keyword in text_lower:
                keyword_matches.append(keyword)
        
        # Check for suspicious commands
        command_matches = []
        for pattern in self.suspicious_commands:
            matches = re.findall(pattern, text_lower, re.IGNORECASE)
            command_matches.extend(matches)
        
        # Check for data exfiltration
        exfiltration_matches = []
        for pattern in self.exfiltration_patterns:
            matches = re.findall(pattern, text_lower, re.IGNORECASE)
            exfiltration_matches.extend(matches)
        
        # Check for scanning activity
        scanning_matches = []
        for pattern in self.scanning_patterns:
            matches = re.findall(pattern, text_lower, re.IGNORECASE)
            scanning_matches.extend(matches)
        
        # Calculate text statistics
        words = text.split()
        word_count = len(words)
        unique_words = len(set(words))
        avg_word_length = sum(len(word) for word in words) / word_count if word_count > 0 else 0
        
        # Calculate entropy (simplified)
        entropy = self._calculate_entropy(text)
        
        # Determine threat level
        threat_score = self._calculate_threat_score(
            keyword_matches, command_matches, exfiltration_matches, scanning_matches
        )
        
        return {
            'keyword_matches': keyword_matches,
            'command_matches': command_matches,
            'exfiltration_matches': exfiltration_matches,
            'scanning_matches': scanning_matches,
            'text_stats': {
                'word_count': word_count,
                'unique_words': unique_words,
                'avg_word_length': round(avg_word_length, 2),
                'entropy': round(entropy, 2)
            },
            'threat_score': threat_score,
            'threat_level': self._get_threat_level(threat_score)
        }
    
    def _calculate_entropy(self, text):
        """Calculate simplified entropy of text"""
        if not text:
            return 0
        
        # Count character frequencies
        char_counts = Counter(text)
        text_len = len(text)
        
        # Calculate entropy
        entropy = 0
        for count in char_counts.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    def _calculate_threat_score(self, keywords, commands, exfiltration, scanning):
        """Calculate threat score from 0-100"""
        score = 0
        
        # Keyword matches
        score += len(keywords) * 5
        
        # Suspicious commands
        score += len(commands) * 15
        
        # Data exfiltration
        score += len(exfiltration) * 20
        
        # Scanning activity
        score += len(scanning) * 25
        
        return min(score, 100)
    
    def _get_threat_level(self, score):
        """Get threat level description"""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        else:
            return "MINIMAL"
    
    def extract_entities(self, text):
        """Extract basic entities from text"""
        entities = {
            'ips': [],
            'urls': [],
            'emails': [],
            'domains': []
        }
        
        # Extract IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        entities['ips'] = re.findall(ip_pattern, text)
        
        # Extract URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        entities['urls'] = re.findall(url_pattern, text)
        
        # Extract emails
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        entities['emails'] = re.findall(email_pattern, text)
        
        # Extract domains
        domain_pattern = r'\b[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        domains = re.findall(domain_pattern, text)
        # Filter out common non-domain patterns
        entities['domains'] = [d for d in domains if not d.startswith('.') and not d.endswith('.')]
        
        return entities
    
    def analyze_payload(self, payload_data):
        """Analyze binary payload data"""
        if not payload_data:
            return {}
        
        try:
            # Try to decode as text
            text_content = payload_data.decode('utf-8', errors='ignore')
            text_analysis = self.analyze_text(text_content)
            
            # Analyze binary characteristics
            binary_analysis = self._analyze_binary(payload_data)
            
            # Combine results
            return {
                'text_analysis': text_analysis,
                'binary_analysis': binary_analysis,
                'entities': self.extract_entities(text_content)
            }
            
        except Exception:
            # If text analysis fails, just do binary analysis
            return {
                'text_analysis': {},
                'binary_analysis': self._analyze_binary(payload_data),
                'entities': {}
            }
    
    def _analyze_binary(self, data):
        """Analyze binary data characteristics"""
        if not data:
            return {}
        
        # Calculate entropy
        entropy = self._calculate_entropy(data)
        
        # Check for common file signatures
        file_signatures = {
            b'PK\x03\x04': 'ZIP',
            b'\x1f\x8b\x08': 'GZIP',
            b'\x89PNG\r\n\x1a\n': 'PNG',
            b'GIF8': 'GIF',
            b'JFIF': 'JPEG',
            b'%PDF': 'PDF',
            b'MZ': 'EXE/DLL',
            b'\x7fELF': 'ELF',
            b'\xfe\xed\xfa': 'Mach-O'
        }
        
        detected_format = 'Unknown'
        for signature, format_name in file_signatures.items():
            if data.startswith(signature):
                detected_format = format_name
                break
        
        # Check for encrypted/compressed content
        is_encrypted = entropy > 7.5
        is_compressed = detected_format in ['ZIP', 'GZIP']
        
        return {
            'size': len(data),
            'entropy': round(entropy, 2),
            'format': detected_format,
            'is_encrypted': is_encrypted,
            'is_compressed': is_compressed,
            'null_bytes': data.count(b'\x00'),
            'printable_ratio': sum(1 for b in data if b in string.printable.encode()) / len(data)
        }

# Create global instance
nlp_analyzer = SimpleNLPAnalyzer()
