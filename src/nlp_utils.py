"""
NLP Utilities - Natural Language Processing for payload analysis
Advanced text analysis using NLTK and spaCy for anomaly detection
"""

import re
import logging
import math
import string
from typing import Dict, List, Tuple, Any, Optional, Set
from collections import Counter, defaultdict
from dataclasses import dataclass
import statistics

# Try to import NLP libraries, handle gracefully if not available
try:
    import nltk
    from nltk.corpus import stopwords
    from nltk.tokenize import word_tokenize, sent_tokenize
    from nltk.stem import PorterStemmer, WordNetLemmatizer
    from nltk.chunk import ne_chunk
    from nltk.tag import pos_tag
    NLTK_AVAILABLE = True
except ImportError:
    NLTK_AVAILABLE = False
    logging.warning("NLTK not available. Some NLP features will be limited.")

try:
    import spacy
    SPACY_AVAILABLE = True
except ImportError:
    SPACY_AVAILABLE = False
    logging.warning("spaCy not available. Some NLP features will be limited.")

try:
    from textblob import TextBlob
    TEXTBLOB_AVAILABLE = True
except ImportError:
    TEXTBLOB_AVAILABLE = False
    logging.warning("TextBlob not available. Sentiment analysis will be limited.")

logger = logging.getLogger(__name__)

@dataclass
class PayloadAnalysis:
    """Structure to hold payload analysis results"""
    text: str
    length: int
    entropy: float
    language_score: float
    suspicious_keywords: List[str]
    sentiment_score: float
    anomaly_score: float
    token_count: int
    unique_tokens: int
    special_chars_ratio: float
    numeric_ratio: float
    uppercase_ratio: float
    base64_likelihood: float
    hex_likelihood: float
    compression_ratio: float
    
@dataclass
class TextFeatures:
    """Extracted text features for analysis"""
    char_frequency: Dict[str, int]
    bigram_frequency: Dict[str, int]
    trigram_frequency: Dict[str, int]
    word_frequency: Dict[str, int]
    sentence_count: int
    avg_word_length: float
    avg_sentence_length: float
    punctuation_count: int
    named_entities: List[str]
    pos_tags: List[Tuple[str, str]]

class PayloadNLPAnalyzer:
    """
    Advanced NLP-based payload analyzer for detecting anomalies
    and extracting insights from network payload data
    """
    
    def __init__(self):
        """Initialize the NLP analyzer with necessary components"""
        self.suspicious_keywords = self._load_suspicious_keywords()
        self.common_words = self._load_common_words()
        self.stemmer = None
        self.lemmatizer = None
        self.nlp_model = None
        
        # Initialize NLTK components if available
        if NLTK_AVAILABLE:
            try:
                # Download required NLTK data
                self._download_nltk_data()
                self.stemmer = PorterStemmer()
                self.lemmatizer = WordNetLemmatizer()
                self.stop_words = set(stopwords.words('english'))
            except Exception as e:
                logger.warning(f"Error initializing NLTK components: {e}")
        
        # Initialize spaCy model if available
        if SPACY_AVAILABLE:
            try:
                self.nlp_model = spacy.load("en_core_web_sm")
            except Exception as e:
                logger.warning(f"spaCy model not available: {e}")
                try:
                    # Try smaller model
                    self.nlp_model = spacy.load("en_core_web_md")
                except:
                    logger.warning("No spaCy models available")
    
    def _download_nltk_data(self):
        """Download required NLTK data"""
        required_data = [
            'punkt', 'stopwords', 'averaged_perceptron_tagger',
            'wordnet', 'maxent_ne_chunker', 'words'
        ]
        
        for data in required_data:
            try:
                nltk.download(data, quiet=True)
            except Exception as e:
                logger.warning(f"Could not download NLTK data {data}: {e}")
    
    def _load_suspicious_keywords(self) -> Dict[str, List[str]]:
        """
        Load predefined suspicious keywords categorized by threat type
        
        Returns:
            Dict mapping threat categories to keyword lists
        """
        return {
            'malware': [
                'trojan', 'virus', 'worm', 'backdoor', 'rootkit', 'botnet',
                'keylogger', 'spyware', 'adware', 'ransomware', 'cryptolocker',
                'payload', 'shellcode', 'exploit', 'metasploit', 'meterpreter'
            ],
            'commands': [
                'cmd.exe', 'powershell', 'bash', 'sh', '/bin/', 'system(',
                'exec(', 'eval(', 'shell_exec', 'passthru', 'popen',
                'proc_open', 'file_get_contents', 'curl_exec', 'wget'
            ],
            'credentials': [
                'password', 'passwd', 'pwd', 'secret', 'token', 'key',
                'auth', 'login', 'username', 'user', 'admin', 'root',
                'administrator', 'credential', 'session', 'cookie'
            ],
            'network': [
                'connect', 'socket', 'bind', 'listen', 'accept', 'send',
                'recv', 'proxy', 'tunnel', 'backdoor', 'reverse_shell',
                'netcat', 'nc', 'telnet', 'ssh', 'ftp', 'tftp'
            ],
            'data_exfiltration': [
                'copy', 'move', 'xcopy', 'robocopy', 'scp', 'rsync',
                'compress', 'zip', 'rar', 'tar', 'gzip', 'archive',
                'base64', 'encode', 'decode', 'encrypt', 'decrypt'
            ],
            'persistence': [
                'autorun', 'startup', 'registry', 'reg', 'schtasks',
                'crontab', 'service', 'daemon', 'dll', 'injection',
                'hook', 'persistence', 'install', 'hide'
            ],
            'reconnaissance': [
                'scan', 'enum', 'discover', 'fingerprint', 'probe',
                'nmap', 'masscan', 'dirb', 'gobuster', 'nikto',
                'sqlmap', 'burp', 'owasp', 'metasploit'
            ]
        }
    
    def _load_common_words(self) -> Set[str]:
        """
        Load common English words for language detection
        
        Returns:
            Set of common English words
        """
        common_words = {
            'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have',
            'it', 'for', 'not', 'on', 'with', 'he', 'as', 'you', 'do',
            'at', 'this', 'but', 'his', 'by', 'from', 'they', 'she',
            'or', 'an', 'will', 'my', 'one', 'all', 'would', 'there',
            'their', 'what', 'so', 'up', 'out', 'if', 'about', 'who',
            'get', 'which', 'go', 'me', 'when', 'make', 'can', 'like',
            'time', 'no', 'just', 'him', 'know', 'take', 'people',
            'into', 'year', 'your', 'good', 'some', 'could', 'them',
            'see', 'other', 'than', 'then', 'now', 'look', 'only',
            'come', 'its', 'over', 'think', 'also', 'back', 'after',
            'use', 'two', 'how', 'our', 'work', 'first', 'well', 'way',
            'even', 'new', 'want', 'because', 'any', 'these', 'give',
            'day', 'most', 'us'
        }
        return common_words
    
    def calculate_entropy(self, text: str) -> float:
        """
        Calculate Shannon entropy of text
        
        Args:
            text: Input text
            
        Returns:
            float: Entropy value (0-8, higher = more random)
        """
        if not text:
            return 0.0
        
        # Count character frequencies
        char_counts = Counter(text.lower())
        text_len = len(text)
        
        # Calculate entropy
        entropy = 0.0
        for count in char_counts.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def calculate_language_score(self, text: str) -> float:
        """
        Calculate how much the text resembles natural language
        
        Args:
            text: Input text
            
        Returns:
            float: Language score (0-1, higher = more language-like)
        """
        if not text or len(text) < 10:
            return 0.0
        
        # Clean text for analysis
        clean_text = re.sub(r'[^\w\s]', ' ', text.lower())
        words = clean_text.split()
        
        if not words:
            return 0.0
        
        # Check common words ratio
        common_word_count = sum(1 for word in words if word in self.common_words)
        common_ratio = common_word_count / len(words)
        
        # Check vowel ratio
        vowel_count = sum(1 for char in clean_text if char in 'aeiou')
        vowel_ratio = vowel_count / len(clean_text) if clean_text else 0
        
        # Ideal vowel ratio is around 0.3-0.4 for English
        vowel_score = 1.0 - abs(vowel_ratio - 0.35) * 2
        vowel_score = max(0.0, min(1.0, vowel_score))
        
        # Check character distribution (natural language has more variety)
        char_diversity = len(set(clean_text)) / len(clean_text) if clean_text else 0
        
        # Combine scores
        language_score = (common_ratio * 0.5 + vowel_score * 0.3 + char_diversity * 0.2)
        return min(1.0, language_score)
    
    def detect_suspicious_keywords(self, text: str) -> List[str]:
        """
        Detect suspicious keywords in text
        
        Args:
            text: Input text to analyze
            
        Returns:
            List of detected suspicious keywords
        """
        detected = []
        text_lower = text.lower()
        
        for category, keywords in self.suspicious_keywords.items():
            for keyword in keywords:
                if keyword.lower() in text_lower:
                    detected.append(f"{keyword} ({category})")
        
        return detected
    
    def calculate_sentiment(self, text: str) -> float:
        """
        Calculate sentiment score of text
        
        Args:
            text: Input text
            
        Returns:
            float: Sentiment score (-1 to 1, negative to positive)
        """
        if not TEXTBLOB_AVAILABLE or not text:
            return 0.0
        
        try:
            blob = TextBlob(text)
            return blob.sentiment.polarity
        except Exception as e:
            logger.warning(f"Error calculating sentiment: {e}")
            return 0.0
    
    def calculate_base64_likelihood(self, text: str) -> float:
        """
        Calculate likelihood that text is Base64 encoded
        
        Args:
            text: Input text
            
        Returns:
            float: Base64 likelihood score (0-1)
        """
        if not text or len(text) < 4:
            return 0.0
        
        # Base64 characteristics
        base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        
        # Check character set
        valid_chars = sum(1 for char in text if char in base64_chars)
        char_ratio = valid_chars / len(text)
        
        # Check length (Base64 length should be multiple of 4)
        length_score = 1.0 if len(text) % 4 == 0 else 0.5
        
        # Check padding
        padding_score = 1.0 if text.endswith('=') or text.endswith('==') else 0.0
        
        # Check entropy (Base64 should have high entropy)
        entropy = self.calculate_entropy(text)
        entropy_score = min(1.0, entropy / 6.0)  # Normalize to 0-1
        
        # Combine scores
        base64_score = (char_ratio * 0.4 + length_score * 0.2 + 
                       padding_score * 0.2 + entropy_score * 0.2)
        
        return base64_score
    
    def calculate_hex_likelihood(self, text: str) -> float:
        """
        Calculate likelihood that text is hexadecimal encoded
        
        Args:
            text: Input text
            
        Returns:
            float: Hex likelihood score (0-1)
        """
        if not text or len(text) < 4:
            return 0.0
        
        # Hex characteristics
        hex_chars = set('0123456789ABCDEFabcdef')
        
        # Check character set
        valid_chars = sum(1 for char in text if char in hex_chars)
        char_ratio = valid_chars / len(text)
        
        # Check length (hex strings are often even length)
        length_score = 1.0 if len(text) % 2 == 0 else 0.7
        
        # Check patterns (common hex prefixes)
        pattern_score = 0.0
        if text.startswith(('0x', '\\x', '%')):
            pattern_score = 1.0
        elif re.search(r'[0-9a-fA-F]{8,}', text):
            pattern_score = 0.8
        
        # Combine scores
        hex_score = (char_ratio * 0.6 + length_score * 0.2 + pattern_score * 0.2)
        
        return hex_score
    
    def extract_text_features(self, text: str) -> TextFeatures:
        """
        Extract comprehensive text features for analysis
        
        Args:
            text: Input text
            
        Returns:
            TextFeatures object with extracted features
        """
        if not text:
            return TextFeatures(
                char_frequency={}, bigram_frequency={}, trigram_frequency={},
                word_frequency={}, sentence_count=0, avg_word_length=0.0,
                avg_sentence_length=0.0, punctuation_count=0,
                named_entities=[], pos_tags=[]
            )
        
        # Character frequency
        char_freq = Counter(text.lower())
        
        # N-gram frequency
        bigrams = Counter()
        trigrams = Counter()
        for i in range(len(text) - 1):
            bigrams[text[i:i+2].lower()] += 1
        for i in range(len(text) - 2):
            trigrams[text[i:i+3].lower()] += 1
        
        # Word analysis
        words = re.findall(r'\w+', text.lower())
        word_freq = Counter(words)
        avg_word_length = sum(len(word) for word in words) / len(words) if words else 0
        
        # Sentence analysis
        sentences = re.split(r'[.!?]+', text)
        sentence_count = len([s for s in sentences if s.strip()])
        avg_sentence_length = len(words) / sentence_count if sentence_count > 0 else 0
        
        # Punctuation
        punctuation_count = sum(1 for char in text if char in string.punctuation)
        
        # Named entities and POS tags
        named_entities = []
        pos_tags = []
        
        if NLTK_AVAILABLE and len(text) > 10:
            try:
                tokens = word_tokenize(text)
                pos_tags = pos_tag(tokens)
                
                # Extract named entities
                chunked = ne_chunk(pos_tags)
                for chunk in chunked:
                    if hasattr(chunk, 'label'):
                        entity = ' '.join([token for token, pos in chunk.leaves()])
                        named_entities.append(entity)
            except Exception as e:
                logger.warning(f"Error extracting features with NLTK: {e}")
        
        return TextFeatures(
            char_frequency=dict(char_freq.most_common(50)),
            bigram_frequency=dict(bigrams.most_common(20)),
            trigram_frequency=dict(trigrams.most_common(20)),
            word_frequency=dict(word_freq.most_common(50)),
            sentence_count=sentence_count,
            avg_word_length=avg_word_length,
            avg_sentence_length=avg_sentence_length,
            punctuation_count=punctuation_count,
            named_entities=named_entities,
            pos_tags=pos_tags
        )
    
    def calculate_anomaly_score(self, analysis: PayloadAnalysis) -> float:
        """
        Calculate overall anomaly score based on various factors
        
        Args:
            analysis: PayloadAnalysis object
            
        Returns:
            float: Anomaly score (0-1, higher = more anomalous)
        """
        scores = []
        
        # High entropy is suspicious
        entropy_score = min(1.0, analysis.entropy / 8.0)
        scores.append(entropy_score * 0.2)
        
        # Low language score is suspicious
        language_score = 1.0 - analysis.language_score
        scores.append(language_score * 0.25)
        
        # High ratio of special characters is suspicious
        scores.append(analysis.special_chars_ratio * 0.15)
        
        # High ratio of numbers can be suspicious
        scores.append(min(1.0, analysis.numeric_ratio * 2) * 0.1)
        
        # All uppercase can be suspicious
        scores.append(min(1.0, analysis.uppercase_ratio * 2) * 0.1)
        
        # Base64/hex encoding is suspicious
        scores.append(analysis.base64_likelihood * 0.1)
        scores.append(analysis.hex_likelihood * 0.1)
        
        # Suspicious keywords heavily weighted
        keyword_score = min(1.0, len(analysis.suspicious_keywords) / 5)
        scores.append(keyword_score * 0.3)
        
        return sum(scores)
    
    def analyze_payload(self, payload: str) -> PayloadAnalysis:
        """
        Perform comprehensive NLP analysis on payload
        
        Args:
            payload: Network payload to analyze
            
        Returns:
            PayloadAnalysis object with results
        """
        if not payload:
            return PayloadAnalysis(
                text="", length=0, entropy=0.0, language_score=0.0,
                suspicious_keywords=[], sentiment_score=0.0, anomaly_score=0.0,
                token_count=0, unique_tokens=0, special_chars_ratio=0.0,
                numeric_ratio=0.0, uppercase_ratio=0.0, base64_likelihood=0.0,
                hex_likelihood=0.0, compression_ratio=0.0
            )
        
        # Basic metrics
        length = len(payload)
        entropy = self.calculate_entropy(payload)
        language_score = self.calculate_language_score(payload)
        suspicious_keywords = self.detect_suspicious_keywords(payload)
        sentiment_score = self.calculate_sentiment(payload)
        
        # Token analysis
        tokens = re.findall(r'\w+', payload)
        token_count = len(tokens)
        unique_tokens = len(set(tokens))
        
        # Character ratios
        special_chars = sum(1 for char in payload if char in string.punctuation)
        special_chars_ratio = special_chars / length if length > 0 else 0
        
        numeric_chars = sum(1 for char in payload if char.isdigit())
        numeric_ratio = numeric_chars / length if length > 0 else 0
        
        uppercase_chars = sum(1 for char in payload if char.isupper())
        uppercase_ratio = uppercase_chars / length if length > 0 else 0
        
        # Encoding likelihood
        base64_likelihood = self.calculate_base64_likelihood(payload)
        hex_likelihood = self.calculate_hex_likelihood(payload)
        
        # Compression ratio (simple estimate)
        try:
            import zlib
            compressed = zlib.compress(payload.encode('utf-8', errors='ignore'))
            compression_ratio = len(compressed) / length if length > 0 else 0
        except:
            compression_ratio = 0.0
        
        # Create analysis object
        analysis = PayloadAnalysis(
            text=payload[:1000],  # Limit stored text
            length=length,
            entropy=entropy,
            language_score=language_score,
            suspicious_keywords=suspicious_keywords,
            sentiment_score=sentiment_score,
            anomaly_score=0.0,  # Will be calculated below
            token_count=token_count,
            unique_tokens=unique_tokens,
            special_chars_ratio=special_chars_ratio,
            numeric_ratio=numeric_ratio,
            uppercase_ratio=uppercase_ratio,
            base64_likelihood=base64_likelihood,
            hex_likelihood=hex_likelihood,
            compression_ratio=compression_ratio
        )
        
        # Calculate anomaly score
        analysis.anomaly_score = self.calculate_anomaly_score(analysis)
        
        return analysis
    
    def batch_analyze_payloads(self, payloads: List[str]) -> List[PayloadAnalysis]:
        """
        Analyze multiple payloads in batch
        
        Args:
            payloads: List of payloads to analyze
            
        Returns:
            List of PayloadAnalysis objects
        """
        return [self.analyze_payload(payload) for payload in payloads]
    
    def get_analysis_summary(self, analyses: List[PayloadAnalysis]) -> Dict[str, Any]:
        """
        Generate summary statistics from multiple payload analyses
        
        Args:
            analyses: List of PayloadAnalysis objects
            
        Returns:
            Dict with summary statistics
        """
        if not analyses:
            return {}
        
        # Collect metrics
        entropies = [a.entropy for a in analyses]
        language_scores = [a.language_score for a in analyses]
        anomaly_scores = [a.anomaly_score for a in analyses]
        lengths = [a.length for a in analyses]
        
        # Count suspicious payloads
        high_anomaly_count = sum(1 for a in analyses if a.anomaly_score > 0.7)
        low_language_count = sum(1 for a in analyses if a.language_score < 0.3)
        high_entropy_count = sum(1 for a in analyses if a.entropy > 6.0)
        
        # Collect all suspicious keywords
        all_keywords = []
        for analysis in analyses:
            all_keywords.extend(analysis.suspicious_keywords)
        keyword_freq = Counter(all_keywords)
        
        # Encoding detection
        base64_count = sum(1 for a in analyses if a.base64_likelihood > 0.7)
        hex_count = sum(1 for a in analyses if a.hex_likelihood > 0.7)
        
        summary = {
            'total_payloads': len(analyses),
            'avg_entropy': statistics.mean(entropies) if entropies else 0,
            'avg_language_score': statistics.mean(language_scores) if language_scores else 0,
            'avg_anomaly_score': statistics.mean(anomaly_scores) if anomaly_scores else 0,
            'avg_length': statistics.mean(lengths) if lengths else 0,
            'high_anomaly_count': high_anomaly_count,
            'low_language_count': low_language_count,
            'high_entropy_count': high_entropy_count,
            'base64_detected': base64_count,
            'hex_detected': hex_count,
            'top_suspicious_keywords': dict(keyword_freq.most_common(10)),
            'anomaly_distribution': {
                'low (0-0.3)': sum(1 for s in anomaly_scores if s <= 0.3),
                'medium (0.3-0.7)': sum(1 for s in anomaly_scores if 0.3 < s <= 0.7),
                'high (0.7-1.0)': sum(1 for s in anomaly_scores if s > 0.7)
            }
        }
        
        return summary


if __name__ == "__main__":
    # Example usage and testing
    analyzer = PayloadNLPAnalyzer()
    
    # Test samples
    test_payloads = [
        "Hello, this is a normal HTTP request with standard content.",
        "SELECT * FROM users WHERE id = 1 UNION SELECT password FROM admin",
        "YWRtaW46cGFzc3dvcmQ=",  # Base64: admin:password
        "\\x48\\x65\\x6c\\x6c\\x6f",  # Hex: Hello
        "cmd.exe /c whoami && net user admin password123",
        "asdfghjklqwertyuiopzxcvbnm1234567890",  # Random string
        "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    ]
    
    print("=== NLP Payload Analysis Demo ===")
    for i, payload in enumerate(test_payloads, 1):
        print(f"\nPayload {i}: {payload[:50]}{'...' if len(payload) > 50 else ''}")
        analysis = analyzer.analyze_payload(payload)
        print(f"  Entropy: {analysis.entropy:.2f}")
        print(f"  Language Score: {analysis.language_score:.2f}")
        print(f"  Anomaly Score: {analysis.anomaly_score:.2f}")
        print(f"  Base64 Likelihood: {analysis.base64_likelihood:.2f}")
        print(f"  Hex Likelihood: {analysis.hex_likelihood:.2f}")
        if analysis.suspicious_keywords:
            print(f"  Suspicious Keywords: {analysis.suspicious_keywords}")
    
    # Summary
    all_analyses = [analyzer.analyze_payload(payload) for payload in test_payloads]
    summary = analyzer.get_analysis_summary(all_analyses)
    print(f"\n=== Summary ===")
    print(f"Total payloads: {summary['total_payloads']}")
    print(f"Average anomaly score: {summary['avg_anomaly_score']:.3f}")
    print(f"High anomaly payloads: {summary['high_anomaly_count']}")
    print(f"Base64 detected: {summary['base64_detected']}")
    print(f"Hex detected: {summary['hex_detected']}")
    if summary['top_suspicious_keywords']:
        print(f"Top suspicious keywords: {list(summary['top_suspicious_keywords'].keys())[:5]}")
