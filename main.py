"""
PCAP Analyzer - Main CLI Entry Point
Professional network security analysis tool with comprehensive reporting
"""

import os
import sys
import time
import argparse
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.analyzer import PcapAnalyzer
from src.extractor import ConnectionExtractor
from src.regex_utils import RegexThreatDetector
from src.nlp_utils import PayloadNLPAnalyzer
from src.risk_calculator import RiskCalculator
from src.report_generator import ReportGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('pcap_analyzer.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class PCAPAnalyzerCLI:
    """
    Command Line Interface for the PCAP Analyzer
    Orchestrates the complete analysis pipeline
    """
    
    def __init__(self):
        """Initialize the CLI with all analysis components"""
        self.analyzer = None
        self.extractor = None
        self.threat_detector = RegexThreatDetector()
        self.nlp_analyzer = PayloadNLPAnalyzer()
        self.risk_calculator = RiskCalculator()
        self.report_generator = ReportGenerator()
        
        # Analysis results storage
        self.analysis_results = {}
        self.flows = {}
        self.connections = {}
        self.threat_matches = []
        self.nlp_analyses = []
        self.risk_assessment = None
        
    def validate_inputs(self, args) -> bool:
        """
        Validate command line arguments
        
        Args:
            args: Parsed command line arguments
            
        Returns:
            bool: True if inputs are valid
        """
        # Check if PCAP file exists
        if not os.path.exists(args.file):
            logger.error(f"PCAP file not found: {args.file}")
            return False
        
        # Check if file is readable
        if not os.access(args.file, os.R_OK):
            logger.error(f"PCAP file not readable: {args.file}")
            return False
        
        # Create output directory if it doesn't exist
        output_dir = os.path.dirname(args.report) if args.report else "output"
        os.makedirs(output_dir, exist_ok=True)
        
        # Check output directory is writable
        if not os.access(output_dir, os.W_OK):
            logger.error(f"Output directory not writable: {output_dir}")
            return False
        
        return True
    
    def run_pcap_analysis(self, pcap_file: str, max_packets: Optional[int] = None) -> bool:
        """
        Run PCAP analysis
        
        Args:
            pcap_file: Path to PCAP file
            max_packets: Maximum packets to process
            
        Returns:
            bool: True if analysis successful
        """
        logger.info(f"Starting PCAP analysis of {pcap_file}")
        
        try:
            # Initialize analyzer
            self.analyzer = PcapAnalyzer(pcap_file)
            
            # Run analysis
            self.analysis_results = self.analyzer.analyze_pcap(max_packets)
            
            if "error" in self.analysis_results:
                logger.error(f"PCAP analysis failed: {self.analysis_results['error']}")
                return False
            
            logger.info(f"PCAP analysis completed. Processed {self.analysis_results['packets']} packets")
            return True
            
        except Exception as e:
            logger.error(f"Error during PCAP analysis: {e}")
            return False
    
    def run_connection_analysis(self) -> bool:
        """
        Run connection and flow analysis
        
        Returns:
            bool: True if analysis successful
        """
        if not self.analyzer or not self.analyzer.packets:
            logger.error("No packet data available for connection analysis")
            return False
        
        try:
            logger.info("Running connection analysis...")
            
            # Initialize extractor
            self.extractor = ConnectionExtractor(self.analyzer.packets)
            
            # Run full analysis
            extraction_results = self.extractor.run_full_analysis()
            
            self.flows = extraction_results.get('flows', {})
            self.connections = extraction_results.get('connections', {})
            
            logger.info(f"Connection analysis completed. Found {len(self.flows)} flows")
            return True
            
        except Exception as e:
            logger.error(f"Error during connection analysis: {e}")
            return False
    
    def run_threat_detection(self) -> bool:
        """
        Run regex-based threat detection
        
        Returns:
            bool: True if detection successful
        """
        if not self.analyzer or not self.analyzer.packets:
            logger.error("No packet data available for threat detection")
            return False
        
        try:
            logger.info("Running threat detection...")
            
            self.threat_matches = []
            
            # Scan payloads for threats
            for packet in self.analyzer.packets:
                if packet.payload:
                    matches = self.threat_detector.scan_payload(packet.payload)
                    self.threat_matches.extend(matches)
            
            logger.info(f"Threat detection completed. Found {len(self.threat_matches)} potential threats")
            return True
            
        except Exception as e:
            logger.error(f"Error during threat detection: {e}")
            return False
    
    def run_nlp_analysis(self) -> bool:
        """
        Run NLP-based payload analysis
        
        Returns:
            bool: True if analysis successful
        """
        if not self.analyzer or not self.analyzer.packets:
            logger.error("No packet data available for NLP analysis")
            return False
        
        try:
            logger.info("Running NLP analysis...")
            
            # Extract payloads
            payloads = [packet.payload for packet in self.analyzer.packets 
                       if packet.payload and len(packet.payload) > 10]
            
            # Limit payloads for performance
            if len(payloads) > 1000:
                logger.info(f"Limiting NLP analysis to 1000 payloads (out of {len(payloads)})")
                payloads = payloads[:1000]
            
            # Run NLP analysis
            self.nlp_analyses = self.nlp_analyzer.batch_analyze_payloads(payloads)
            
            logger.info(f"NLP analysis completed. Analyzed {len(self.nlp_analyses)} payloads")
            return True
            
        except Exception as e:
            logger.error(f"Error during NLP analysis: {e}")
            return False
    
    def run_risk_assessment(self) -> bool:
        """
        Run comprehensive risk assessment
        
        Returns:
            bool: True if assessment successful
        """
        try:
            logger.info("Running risk assessment...")
            
            # Run comprehensive risk calculation
            self.risk_assessment = self.risk_calculator.calculate_comprehensive_risk(
                flows=self.flows,
                connections=self.connections,
                threat_matches=self.threat_matches,
                nlp_analyses=self.nlp_analyses
            )
            
            logger.info(f"Risk assessment completed. Overall risk: {self.risk_assessment.risk_level.name}")
            return True
            
        except Exception as e:
            logger.error(f"Error during risk assessment: {e}")
            return False
    
    def generate_report(self, output_path: str) -> bool:
        """
        Generate comprehensive PDF report
        
        Args:
            output_path: Path for output report
            
        Returns:
            bool: True if report generated successfully
        """
        if not self.risk_assessment:
            logger.error("No risk assessment available for report generation")
            return False
        
        try:
            logger.info(f"Generating report: {output_path}")
            
            # Generate the report (will auto-fallback to text if PDF unavailable)
            try:
                report_path = self.report_generator.generate_comprehensive_report(
                    analysis_results=self.analysis_results,
                    risk_assessment=self.risk_assessment,
                    flows=self.extractor.get_flow_summary() if self.extractor else {},
                    connections=self.extractor.get_connection_summary() if self.extractor else {},
                    threat_matches=self.threat_matches,
                    nlp_analyses=self.nlp_analyses,
                    output_filename=os.path.basename(output_path)
                )
            except Exception as e:
                logger.error(f"Error generating PDF report: {e}")
                # Generate simple text report as ultimate fallback
                report_path = self.report_generator.generate_text_report(
                    analysis_results=self.analysis_results,
                    risk_assessment=self.risk_assessment,
                    flows=self.extractor.get_flow_summary() if self.extractor else {},
                    connections=self.extractor.get_connection_summary() if self.extractor else {},
                    threat_matches=self.threat_matches,
                    nlp_analyses=self.nlp_analyses,
                    output_filename=os.path.basename(output_path).replace('.pdf', '.txt')
                )
            
            logger.info(f"Report generated successfully: {report_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            return False
    
    def print_quick_summary(self):
        """Print quick summary to console"""
        if self.risk_assessment and self.analysis_results:
            summary = self.report_generator.create_quick_summary(
                self.risk_assessment, 
                self.analysis_results
            )
            print("\n" + summary + "\n")
        else:
            print("No analysis results available for summary")
    
    def run_complete_analysis(self, pcap_file: str, output_report: str, 
                            max_packets: Optional[int] = None, 
                            quick_mode: bool = False) -> bool:
        """
        Run complete analysis pipeline
        
        Args:
            pcap_file: Path to PCAP file
            output_report: Path for output report
            max_packets: Maximum packets to process
            quick_mode: Run in quick mode (skip some analyses)
            
        Returns:
            bool: True if all analyses completed successfully
        """
        start_time = time.time()
        
        # Step 1: PCAP Analysis
        if not self.run_pcap_analysis(pcap_file, max_packets):
            return False
        
        # Step 2: Connection Analysis
        if not self.run_connection_analysis():
            return False
        
        # Step 3: Threat Detection
        if not self.run_threat_detection():
            return False
        
        # Step 4: NLP Analysis (skip in quick mode)
        if not quick_mode:
            if not self.run_nlp_analysis():
                logger.warning("NLP analysis failed, continuing without it")
                self.nlp_analyses = []  # Continue with empty NLP results
        else:
            logger.info("Skipping NLP analysis (quick mode)")
            self.nlp_analyses = []
        
        # Step 5: Risk Assessment
        if not self.run_risk_assessment():
            return False
        
        # Step 6: Report Generation
        if not self.generate_report(output_report):
            return False
        
        # Print summary
        self.print_quick_summary()
        
        total_time = time.time() - start_time
        logger.info(f"Complete analysis finished in {total_time:.2f} seconds")
        
        return True

def create_argument_parser() -> argparse.ArgumentParser:
    """
    Create command line argument parser
    
    Returns:
        argparse.ArgumentParser: Configured argument parser
    """
    parser = argparse.ArgumentParser(
        description="Professional PCAP Network Security Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --file traffic.pcap --report security_report.pdf
  %(prog)s --file capture.pcap --report analysis.pdf --max-packets 10000
  %(prog)s --file network.pcap --report report.pdf --quick --verbose
  
For more information, visit: https://github.com/your-repo/pcap-analyzer
        """
    )
    
    # Required arguments
    parser.add_argument(
        '--file', '-f',
        required=True,
        help='Path to the PCAP file to analyze'
    )
    
    # Optional arguments
    parser.add_argument(
        '--report', '-r',
        default='output/security_analysis_report.pdf',
        help='Output path for the PDF report (default: output/security_analysis_report.pdf)'
    )
    
    parser.add_argument(
        '--max-packets', '-m',
        type=int,
        help='Maximum number of packets to process (default: all packets)'
    )
    
    parser.add_argument(
        '--quick', '-q',
        action='store_true',
        help='Run in quick mode (skip NLP analysis for faster processing)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--output-dir', '-o',
        default='output',
        help='Output directory for reports and charts (default: output)'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='PCAP Analyzer v1.0.0'
    )
    
    return parser

def main():
    """Main entry point for the CLI"""
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Print banner
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                         PCAP SECURITY ANALYZER v1.0                         ║
║                    Professional Network Security Analysis                    ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ • Comprehensive packet analysis with threat detection                       ║
║ • Advanced risk scoring with ISO/NIST/OWASP mapping                        ║
║ • Professional PDF reports with visualizations                              ║
║ • NLP-based payload analysis and anomaly detection                          ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    # Initialize CLI
    cli = PCAPAnalyzerCLI()
    
    # Update output directory if specified
    if args.output_dir:
        cli.report_generator.output_dir = args.output_dir
        os.makedirs(args.output_dir, exist_ok=True)
    
    # Validate inputs
    if not cli.validate_inputs(args):
        sys.exit(1)
    
    # Run analysis
    logger.info(f"Starting analysis of {args.file}")
    success = cli.run_complete_analysis(
        pcap_file=args.file,
        output_report=args.report,
        max_packets=args.max_packets,
        quick_mode=args.quick
    )
    
    if success:
        print(f"\n✅ Analysis completed successfully!")
        print(f"📊 Report saved to: {args.report}")
        print(f"📁 Charts and data saved to: {cli.report_generator.output_dir}")
        sys.exit(0)
    else:
        print(f"\n❌ Analysis failed. Check the logs for details.")
        sys.exit(1)

if __name__ == "__main__":
    main()
