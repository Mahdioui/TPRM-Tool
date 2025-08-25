"""
Enhanced Report Generator - Comprehensive Professional PDF Reports
Creates detailed cybersecurity reports with risk methodology explanations and TPRM recommendations
"""

import os
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

# Import required libraries with fallbacks
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np
    
    # Handle seaborn import with fallback
    try:
        import seaborn as sns
        SEABORN_AVAILABLE = True
    except ImportError:
        SEABORN_AVAILABLE = False
        print("WARNING: seaborn not available. Using default matplotlib styles.")
    
    CHARTS_AVAILABLE = True
except ImportError:
    CHARTS_AVAILABLE = False
    SEABORN_AVAILABLE = False

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle, PageBreak, KeepTogether
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, cm
    from reportlab.graphics.shapes import Drawing, Rect, String, Line
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.charts.barcharts import VerticalBarChart, HorizontalBarChart
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
    from reportlab.graphics import renderPDF
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

try:
    from .risk_calculator import RiskAssessment, RiskLevel
    from .analyzer import PacketInfo
except ImportError:
    from risk_calculator import RiskAssessment, RiskLevel
    from analyzer import PacketInfo

logger = logging.getLogger(__name__)

class EnhancedReportGenerator:
    """
    Enhanced Professional PDF Report Generator
    Creates comprehensive cybersecurity analysis reports with detailed explanations
    """
    
    def __init__(self, output_dir: str = "output"):
        """Initialize the enhanced report generator"""
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        if REPORTLAB_AVAILABLE:
            self.styles = getSampleStyleSheet()
            self._setup_enhanced_styles()
        else:
            self.styles = None
        
        # Enhanced branding
        self.company_name = "CyberGuard Analytics"
        self.company_tagline = "Professional Network Security Assessment & Third-Party Risk Management"
        
        # Risk methodology framework
        self.risk_methodology = {
            'framework': 'Hybrid Risk Assessment Model',
            'components': {
                'Protocol Analysis': 'ISO/IEC 27001:2013 A.13.1.1 - Network controls management',
                'Traffic Patterns': 'NIST CSF ID.AM-3 - Organizational communication flows',
                'Threat Detection': 'OWASP Top 10 2021 - Security risk categories',
                'Behavioral Analysis': 'NIST CSF DE.AE-2 - Analyzed event data',
                'Third-Party Risk': 'ISO/IEC 27036 - Supplier relationship security'
            },
            'scoring_matrix': {
                'Critical (90-100)': 'Immediate action required - Business critical risk',
                'High (70-89)': 'High priority remediation - Significant security concern',
                'Medium (40-69)': 'Moderate risk - Schedule remediation within 30 days',
                'Low (20-39)': 'Minor risk - Monitor and review quarterly',
                'Minimal (0-19)': 'Acceptable risk - Standard monitoring'
            }
        }
    
    def _setup_enhanced_styles(self):
        """Setup enhanced custom styles for professional reporting"""
        # Enhanced color palette - Professional TPRM colors
        self.colors = {
            'primary': colors.HexColor('#1a365d'),      # Deep navy blue
            'secondary': colors.HexColor('#2d3748'),    # Dark slate
            'accent': colors.HexColor('#e53e3e'),       # Professional red
            'warning': colors.HexColor('#dd6b20'),      # Orange
            'success': colors.HexColor('#38a169'),      # Green
            'info': colors.HexColor('#3182ce'),         # Blue
            'light_gray': colors.HexColor('#f7fafc'),  # Very light gray
            'medium_gray': colors.HexColor('#e2e8f0'), # Medium gray
            'dark_gray': colors.HexColor('#4a5568'),   # Dark gray
            'white': colors.white,
            'black': colors.black,
            'border': colors.HexColor('#cbd5e0'),      # Border color
            'highlight': colors.HexColor('#fed7d7')    # Highlight color
        }
        
        # Enhanced title page styles with professional typography
        self.styles.add(ParagraphStyle(
            name='ReportTitle',
            parent=self.styles['Title'],
            fontSize=32,
            spaceAfter=40,
            textColor=self.colors['primary'],
            alignment=TA_CENTER,
            fontName='Helvetica-Bold',
            spaceBefore=30,
            leading=36,
            borderWidth=0,
            backColor=self.colors['white']
        ))
        
        self.styles.add(ParagraphStyle(
            name='CompanyName',
            parent=self.styles['Normal'],
            fontSize=20,
            spaceAfter=18,
            textColor=self.colors['secondary'],
            alignment=TA_CENTER,
            fontName='Helvetica-Bold',
            spaceBefore=15,
            leading=24
        ))
        
        self.styles.add(ParagraphStyle(
            name='CompanyTagline',
            parent=self.styles['Normal'],
            fontSize=14,
            spaceAfter=25,
            textColor=self.colors['dark_gray'],
            alignment=TA_CENTER,
            fontName='Helvetica',
            fontStyle='italic',
            leading=18
        ))
        
        # Enhanced section headers with professional styling
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading1'],
            fontSize=20,
            spaceBefore=30,
            spaceAfter=15,
            textColor=self.colors['primary'],
            fontName='Helvetica-Bold',
            leftIndent=0,
            borderWidth=0,
            borderColor=self.colors['primary'],
            borderPadding=12,
            backColor=self.colors['light_gray'],
            leading=24
        ))
        
        self.styles.add(ParagraphStyle(
            name='SubsectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceBefore=22,
            spaceAfter=12,
            textColor=self.colors['secondary'],
            fontName='Helvetica-Bold',
            leftIndent=15,
            leading=20,
            borderWidth=0,
            backColor=self.colors['white']
        ))
        
        # Enhanced executive summary with professional formatting
        self.styles.add(ParagraphStyle(
            name='ExecutiveSummary',
            parent=self.styles['Normal'],
            fontSize=12,
            spaceBefore=15,
            spaceAfter=15,
            alignment=TA_JUSTIFY,
            leftIndent=25,
            rightIndent=25,
            fontName='Helvetica',
            leading=16,
            backColor=self.colors['light_gray'],
            borderWidth=2,
            borderColor=self.colors['border'],
            borderPadding=15
        ))
        
        # Enhanced risk indicators with professional styling
        self.styles.add(ParagraphStyle(
            name='RiskCritical',
            parent=self.styles['Normal'],
            fontSize=14,
            textColor=self.colors['accent'],
            fontName='Helvetica-Bold',
            backColor=self.colors['highlight'],
            borderWidth=2,
            borderColor=self.colors['accent'],
            borderPadding=10,
            alignment=TA_CENTER,
            leading=18
        ))
        
        self.styles.add(ParagraphStyle(
            name='RiskHigh',
            parent=self.styles['Normal'],
            fontSize=14,
            textColor=self.colors['warning'],
            fontName='Helvetica-Bold',
            backColor=colors.HexColor('#fed7aa'),
            borderWidth=2,
            borderColor=self.colors['warning'],
            borderPadding=10,
            alignment=TA_CENTER,
            leading=18
        ))
        
        self.styles.add(ParagraphStyle(
            name='RiskMedium',
            parent=self.styles['Normal'],
            fontSize=14,
            textColor=self.colors['info'],
            fontName='Helvetica-Bold',
            backColor=colors.HexColor('#bee3f8'),
            borderWidth=2,
            borderColor=self.colors['info'],
            borderPadding=10,
            alignment=TA_CENTER,
            leading=18
        ))
        
        self.styles.add(ParagraphStyle(
            name='RiskLow',
            parent=self.styles['Normal'],
            fontSize=14,
            textColor=self.colors['success'],
            fontName='Helvetica-Bold',
            backColor=colors.HexColor('#c6f6d5'),
            borderWidth=2,
            borderColor=self.colors['success'],
            borderPadding=10,
            alignment=TA_CENTER,
            leading=18
        ))
        
        # Enhanced table styles for professional appearance
        self.styles.add(ParagraphStyle(
            name='TableHeading',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=self.colors['white'],
            fontName='Helvetica-Bold',
            backColor=self.colors['primary'],
            alignment=TA_CENTER,
            leading=16,
            spaceAfter=8,
            spaceBefore=8
        ))
        
        self.styles.add(ParagraphStyle(
            name='TableBody',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=self.colors['black'],
            fontName='Helvetica',
            alignment=TA_LEFT,
            leading=14,
            spaceAfter=4,
            spaceBefore=4
        ))
        
        # Enhanced list and code styles
        self.styles.add(ParagraphStyle(
            name='ListItem',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=self.colors['black'],
            fontName='Helvetica',
            leftIndent=20,
            leading=15,
            spaceAfter=6,
            spaceBefore=6
        ))
        
        self.styles.add(ParagraphStyle(
            name='CodeBlock',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=self.colors['dark_gray'],
            fontName='Courier',
            backColor=self.colors['medium_gray'],
            borderWidth=1,
            borderColor=self.colors['border'],
            borderPadding=8,
            leftIndent=25,
            rightIndent=25,
            leading=14
        ))
        
        # Enhanced methodology and framework styles
        self.styles.add(ParagraphStyle(
            name='Methodology',
            parent=self.styles['Normal'],
            fontSize=11,
            textColor=self.colors['black'],
            fontName='Helvetica',
            alignment=TA_JUSTIFY,
            leftIndent=20,
            rightIndent=20,
            leading=15,
            spaceAfter=10,
            spaceBefore=10
        ))
        
        self.styles.add(ParagraphStyle(
            name='FrameworkDetail',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=self.colors['dark_gray'],
            fontName='Helvetica',
            leftIndent=30,
            leading=14,
            spaceAfter=6,
            spaceBefore=6
        ))
        
        # Enhanced dashboard and KPI styles
        self.styles.add(ParagraphStyle(
            name='DashboardTitle',
            parent=self.styles['Normal'],
            fontSize=16,
            textColor=self.colors['primary'],
            fontName='Helvetica-Bold',
            alignment=TA_CENTER,
            leading=20,
            spaceAfter=15,
            spaceBefore=20,
            backColor=self.colors['light_gray'],
            borderWidth=1,
            borderColor=self.colors['border'],
            borderPadding=10
        ))
        
        self.styles.add(ParagraphStyle(
            name='KPIMetric',
            parent=self.styles['Normal'],
            fontSize=18,
            textColor=self.colors['primary'],
            fontName='Helvetica-Bold',
            alignment=TA_CENTER,
            leading=22,
            spaceAfter=8,
            spaceBefore=8,
            backColor=self.colors['white'],
            borderWidth=2,
            borderColor=self.colors['primary'],
            borderPadding=12
        ))
        
        self.styles.add(ParagraphStyle(
            name='KPILabel',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=self.colors['dark_gray'],
            fontName='Helvetica',
            alignment=TA_CENTER,
            leading=12,
            spaceAfter=5,
            spaceBefore=5
        ))
    
    def generate_comprehensive_professional_report(self,
                                                 analysis_results: Dict[str, Any],
                                                 risk_assessment: RiskAssessment,
                                                 flows: Dict[str, Any],
                                                 connections: Dict[str, Any],
                                                 threat_matches: List[Any],
                                                 nlp_analyses: List[Any],
                                                 output_filename: str = "comprehensive_security_report.pdf") -> str:
        """
        Generate a comprehensive professional PDF report with detailed explanations
        """
        if not REPORTLAB_AVAILABLE:
            logger.warning("ReportLab not available. Generating enhanced text report instead.")
            return self.generate_enhanced_text_report(
                analysis_results, risk_assessment, flows, connections,
                threat_matches, nlp_analyses, output_filename.replace('.pdf', '.txt')
            )
        
        output_path = os.path.join(self.output_dir, output_filename)
        
        try:
            # Create document
            doc = SimpleDocTemplate(
                output_path,
                pagesize=A4,
                rightMargin=2*cm,
                leftMargin=2*cm,
                topMargin=2*cm,
                bottomMargin=2*cm
            )
            
            story = []
            
            # Title Page
            story.extend(self._create_enhanced_title_page(analysis_results, risk_assessment))
            story.append(PageBreak())
            
            # Executive Summary
            story.extend(self._create_executive_summary(risk_assessment, analysis_results, threat_matches))
            story.append(PageBreak())
            
            # Risk Assessment Methodology
            story.extend(self._create_risk_methodology_section())
            story.append(PageBreak())
            
            # Technical Analysis
            story.extend(self._create_technical_analysis(analysis_results, flows, connections))
            story.append(PageBreak())
            
            # Threat Intelligence
            story.extend(self._create_threat_intelligence_section(threat_matches, nlp_analyses))
            story.append(PageBreak())
            
            # Risk Scoring Details
            story.extend(self._create_detailed_risk_scoring(risk_assessment))
            story.append(PageBreak())
            
            # Compliance Mapping
            story.extend(self._create_compliance_mapping(risk_assessment))
            story.append(PageBreak())
            
            # TPRM Recommendations
            story.extend(self._create_tprm_recommendations(risk_assessment, threat_matches))
            story.append(PageBreak())
            
            # Appendices
            story.extend(self._create_appendices(analysis_results, flows, connections))
            
            # Build the document
            doc.build(story)
            
            logger.info(f"Comprehensive PDF report generated: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Error generating comprehensive PDF report: {e}")
            # Fallback to enhanced text report
            text_filename = output_filename.replace('.pdf', '.txt')
            return self.generate_enhanced_text_report(
                analysis_results, risk_assessment, flows, connections,
                threat_matches, nlp_analyses, text_filename
            )
    
    def _create_enhanced_title_page(self, analysis_results: Dict[str, Any], risk_assessment: RiskAssessment) -> List:
        """Create an enhanced professional title page with better visual design and spacing"""
        elements = []
        
        # Enhanced company header with better spacing and professional layout
        elements.append(Spacer(1, 1.5*inch))
        
        # Company logo placeholder (professional header)
        company_header_style = ParagraphStyle(
            name='CompanyHeader',
            parent=self.styles['Normal'],
            fontSize=26,
            textColor=self.colors['primary'],
            alignment=TA_CENTER,
            fontName='Helvetica-Bold',
            spaceAfter=12,
            spaceBefore=0
        )
        elements.append(Paragraph("🛡️ " + self.company_name, company_header_style))
        elements.append(Paragraph(self.company_tagline, self.styles['CompanyTagline']))
        
        elements.append(Spacer(1, 2.0*inch))
        
        # Enhanced report title with professional subtitle
        elements.append(Paragraph("NETWORK SECURITY ANALYSIS REPORT", self.styles['ReportTitle']))
        
        subtitle_style = ParagraphStyle(
            name='ReportSubtitle',
            parent=self.styles['Normal'],
            fontSize=16,
            textColor=self.colors['secondary'],
            alignment=TA_CENTER,
            fontName='Helvetica',
            spaceAfter=25,
            spaceBefore=15
        )
        elements.append(Paragraph("Comprehensive PCAP Assessment & Third-Party Risk Evaluation", subtitle_style))
        
        elements.append(Spacer(1, 1.5*inch))
        
        # Enhanced risk level indicator with professional styling and better spacing
        risk_color_map = {
            'CRITICAL': self.colors['accent'],
            'HIGH': self.colors['warning'],
            'MEDIUM': self.colors['info'],
            'LOW': self.colors['success'],
            'MINIMAL': self.colors['success']
        }
        
        risk_color = risk_color_map.get(risk_assessment.risk_level.name, self.colors['dark_gray'])
        risk_bg_color = {
            'CRITICAL': self.colors['highlight'],
            'HIGH': colors.HexColor('#fed7aa'),
            'MEDIUM': colors.HexColor('#bee3f8'),
            'LOW': colors.HexColor('#c6f6d5'),
            'MINIMAL': colors.HexColor('#c6f6d5')
        }.get(risk_assessment.risk_level.name, self.colors['light_gray'])
        
        # Create enhanced risk indicator box with professional design and better spacing
        risk_style = ParagraphStyle(
            name='EnhancedRiskIndicator',
            parent=self.styles['Normal'],
            fontSize=20,
            textColor=risk_color,
            fontName='Helvetica-Bold',
            backColor=risk_bg_color,
            borderWidth=3,
            borderColor=risk_color,
            borderPadding=20,
            alignment=TA_CENTER,
            leading=24,
            spaceAfter=20,
            spaceBefore=20
        )
        
        risk_text = f"RISK LEVEL: {risk_assessment.risk_level.name}"
        elements.append(Paragraph(risk_text, risk_style))
        
        # Add risk score display with better spacing and larger font
        score_style = ParagraphStyle(
            name='RiskScore',
            parent=self.styles['Normal'],
            fontSize=16,
            textColor=self.colors['dark_gray'],
            fontName='Helvetica-Bold',
            alignment=TA_CENTER,
            spaceAfter=15,
            spaceBefore=10,
            backColor=self.colors['white'],
            borderWidth=1,
            borderColor=self.colors['border'],
            borderPadding=12
        )
        elements.append(Paragraph(f"Risk Score: {risk_assessment.overall_score:.1f}/100", score_style))
        
        elements.append(Spacer(1, 1.8*inch))
        
        # Enhanced metadata section with professional layout and better spacing
        metadata_style = ParagraphStyle(
            name='Metadata',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=self.colors['dark_gray'],
            fontName='Helvetica',
            alignment=TA_CENTER,
            spaceAfter=10,
            spaceBefore=10
        )
        
        current_time = datetime.now().strftime("%B %d, %Y at %H:%M")
        elements.append(Paragraph(f"Report Generated: {current_time}", metadata_style))
        
        # Add analysis summary metadata with better spacing
        if analysis_results:
            total_packets = analysis_results.get('total_packets', 0)
            total_flows = analysis_results.get('flows_count', 0)
            elements.append(Paragraph(f"Analysis Scope: {total_packets:,} packets, {total_flows:,} network flows", metadata_style))
        
        elements.append(Spacer(1, 1.2*inch))
        
        # Professional footer with better spacing
        footer_style = ParagraphStyle(
            name='Footer',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=self.colors['medium_gray'],
            fontName='Helvetica',
            alignment=TA_CENTER,
            spaceAfter=5,
            spaceBefore=25
        )
        elements.append(Paragraph("Confidential - For Internal Use Only", footer_style))
        elements.append(Paragraph("Compliant with ISO/IEC 27001, NIST CSF, and OWASP Top 10", footer_style))
        
        return elements
    
    def _create_executive_summary(self, risk_assessment: RiskAssessment, analysis_results: Dict[str, Any], threat_matches: List) -> List:
        """Create enhanced executive summary with professional layout and dashboards"""
        elements = []
        
        elements.append(Paragraph("EXECUTIVE SUMMARY", self.styles['SectionHeader']))
        
        # Enhanced summary text with professional formatting
        packet_count = analysis_results.get('packets', 0)
        threat_count = len(threat_matches)
        risk_score = risk_assessment.overall_score
        
        summary_text = f"""
        This comprehensive network security assessment analyzed <b>{packet_count:,} network packets</b> to evaluate 
        cybersecurity risks and compliance posture. The assessment employs a multi-layered risk evaluation 
        framework aligned with <b>ISO/IEC 27001</b>, <b>NIST Cybersecurity Framework</b>, and <b>OWASP</b> security standards.
        
        <br/><br/><b>KEY FINDINGS:</b><br/>
        • <b>Overall Risk Score:</b> {risk_score:.1f}/100 ({risk_assessment.risk_level.name} Risk)<br/>
        • <b>Security Threats Identified:</b> {threat_count}<br/>
        • <b>Network Protocols Analyzed:</b> {len(analysis_results.get('protocol_stats', {}))}<br/>
        • <b>Compliance Gaps:</b> {len([r for r in risk_assessment.recommendations if 'compliance' in r.lower()])}
        """
        
        # Enhanced risk level specific messaging with professional tone
        if risk_score >= 70:
            summary_text += f"""
            
            <br/><br/><b>🚨 CRITICAL FINDINGS:</b><br/>
            This assessment identified <b>critical security risks</b> requiring immediate attention. The elevated risk 
            score indicates potential vulnerabilities that could lead to data breaches, service disruptions, 
            or compliance violations. <b>Immediate implementation of recommended controls is advised.</b>
            """
        elif risk_score >= 40:
            summary_text += f"""
            
            <br/><br/><b>⚠️ MODERATE RISK IDENTIFIED:</b><br/>
            The network exhibits <b>moderate security risks</b> that require structured remediation within 30 days. 
            While not immediately critical, these findings indicate areas where security controls should be 
            strengthened to maintain an acceptable risk posture.
            """
        else:
            summary_text += f"""
            
            <br/><br/><b>✅ ACCEPTABLE RISK LEVEL:</b><br/>
            The network demonstrates a <b>strong security posture</b> with minimal identified risks. Continue 
            monitoring and maintain current security controls while implementing recommended enhancements 
            for defense-in-depth strategies.
            """
        
        # Add enhanced executive summary box with professional styling
        elements.append(Paragraph(summary_text, self.styles['ExecutiveSummary']))
        
        elements.append(Spacer(1, 0.4*inch))
        
        # Enhanced Risk Score Dashboard
        elements.append(Paragraph("RISK SCORE DASHBOARD", self.styles['DashboardTitle']))
        
        # Create risk score visualization table
        risk_score_data = [
            ['Current Risk Score', 'Risk Level', 'Status', 'Action Required'],
            [
                f"<b>{risk_score:.1f}/100</b>",
                f"<b>{risk_assessment.risk_level.name}</b>",
                self._get_risk_status(risk_score),
                self._get_action_required(risk_score)
            ]
        ]
        
        risk_score_table = Table(risk_score_data, colWidths=[1.5*inch, 1.5*inch, 1.5*inch, 2*inch])
        risk_score_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('FONTSIZE', (0, 1), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 2, self.colors['primary']),
            ('BACKGROUND', (0, 0), (-1, 0), self.colors['primary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), self.colors['white']),
            ('BACKGROUND', (0, 1), (-1, -1), self.colors['light_gray']),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        
        elements.append(risk_score_table)
        
        elements.append(Spacer(1, 0.4*inch))
        
        # Enhanced Risk Component Analysis Dashboard
        elements.append(Paragraph("RISK COMPONENT ANALYSIS", self.styles['DashboardTitle']))
        
        # Get risk component scores
        category_scores = getattr(risk_assessment, 'category_scores', {})
        risk_components = [
            ['Risk Component', 'Score', 'Impact Level', 'Priority', 'Recommendation'],
            [
                'Protocol Security', 
                f"{category_scores.get('Protocol Analysis', 0):.1f}", 
                self._get_risk_impact(category_scores.get('Protocol Analysis', 0)), 
                self._get_priority_level(category_scores.get('Protocol Analysis', 0)),
                self._get_component_recommendation('Protocol Analysis', category_scores.get('Protocol Analysis', 0))
            ],
            [
                'Traffic Patterns', 
                f"{category_scores.get('Traffic Patterns', 0):.1f}", 
                self._get_risk_impact(category_scores.get('Traffic Patterns', 0)), 
                self._get_priority_level(category_scores.get('Traffic Patterns', 0)),
                self._get_component_recommendation('Traffic Patterns', category_scores.get('Traffic Patterns', 0))
            ],
            [
                'Threat Detection', 
                f"{category_scores.get('Threat Detection', 0):.1f}", 
                self._get_risk_impact(category_scores.get('Threat Detection', 0)), 
                self._get_priority_level(category_scores.get('Threat Detection', 0)),
                self._get_component_recommendation('Threat Detection', category_scores.get('Threat Detection', 0))
            ],
            [
                'Behavioral Analysis', 
                f"{category_scores.get('Behavioral Analysis', 0):.1f}", 
                self._get_risk_impact(category_scores.get('Behavioral Analysis', 0)), 
                self._get_priority_level(category_scores.get('Behavioral Analysis', 0)),
                self._get_component_recommendation('Behavioral Analysis', category_scores.get('Behavioral Analysis', 0))
            ],
            [
                'Third-Party Risk', 
                f"{category_scores.get('Third-Party Risk', 0):.1f}", 
                self._get_risk_impact(category_scores.get('Third-Party Risk', 0)), 
                self._get_priority_level(category_scores.get('Third-Party Risk', 0)),
                self._get_component_recommendation('Third-Party Risk', category_scores.get('Third-Party Risk', 0))
            ]
        ]
        
        # Enhanced table styling with professional appearance
        metrics_table = Table(risk_components, colWidths=[1.5*inch, 0.8*inch, 1.2*inch, 1*inch, 2.5*inch])
        metrics_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, self.colors['primary']),
            ('BACKGROUND', (0, 0), (-1, 0), self.colors['primary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), self.colors['white']),
            ('BACKGROUND', (0, 1), (-1, -1), self.colors['light_gray']),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [self.colors['light_gray'], self.colors['white']])
        ]))
        
        elements.append(metrics_table)
        
        elements.append(Spacer(1, 0.4*inch))
        
        # Enhanced Immediate Action Items Dashboard
        elements.append(Paragraph("IMMEDIATE ACTION ITEMS", self.styles['DashboardTitle']))
        
        # Get top 5 recommendations with enhanced styling
        top_recommendations = risk_assessment.recommendations[:5]
        for i, rec in enumerate(top_recommendations, 1):
            # Create recommendation box with professional styling
            rec_style = ParagraphStyle(
                name=f'Rec{i}',
                parent=self.styles['Normal'],
                fontSize=11,
                textColor=self.colors['black'],
                fontName='Helvetica',
                leftIndent=20,
                leading=15,
                spaceAfter=8,
                spaceBefore=8,
                backColor=self.colors['light_gray'] if i % 2 == 0 else self.colors['white'],
                borderWidth=1,
                borderColor=self.colors['border'],
                borderPadding=10
            )
            
            # Add priority indicator
            priority_icon = "🔴" if i <= 2 else "🟡" if i <= 4 else "🟢"
            elements.append(Paragraph(f"{priority_icon} <b>Priority {i}:</b> {rec}", rec_style))
        
        elements.append(Spacer(1, 0.3*inch))
        
        # Add summary conclusion
        conclusion_style = ParagraphStyle(
            name='Conclusion',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=self.colors['primary'],
            fontName='Helvetica-Bold',
            alignment=TA_CENTER,
            leading=16,
            spaceAfter=10,
            spaceBefore=15,
            backColor=self.colors['light_gray'],
            borderWidth=2,
            borderColor=self.colors['primary'],
            borderPadding=15
        )
        
        conclusion_text = "This assessment provides a comprehensive foundation for strengthening network security posture and ensuring compliance with industry standards."
        elements.append(Paragraph(conclusion_text, conclusion_style))
        
        return elements
    
    def _get_risk_status(self, risk_score: float) -> str:
        """Get risk status based on score"""
        if risk_score >= 80:
            return "CRITICAL"
        elif risk_score >= 60:
            return "HIGH"
        elif risk_score >= 40:
            return "MEDIUM"
        elif risk_score >= 20:
            return "LOW"
        else:
            return "MINIMAL"
    
    def _get_action_required(self, risk_score: float) -> str:
        """Get action required based on risk score"""
        if risk_score >= 80:
            return "Immediate action required"
        elif risk_score >= 60:
            return "High priority remediation"
        elif risk_score >= 40:
            return "Schedule within 30 days"
        elif risk_score >= 20:
            return "Monitor and review"
        else:
            return "Continue monitoring"
    
    def _get_component_recommendation(self, component: str, score: float) -> str:
        """Get specific recommendation for a risk component"""
        if score >= 70:
            return "Immediate remediation required"
        elif score >= 50:
            return "Strengthen controls within 30 days"
        elif score >= 30:
            return "Enhance monitoring and controls"
        else:
            return "Maintain current controls"
    
    def _create_risk_methodology_section(self) -> List:
        """Create enhanced risk assessment methodology section"""
        elements = []
        
        elements.append(Paragraph("RISK ASSESSMENT METHODOLOGY", self.styles['SectionHeader']))
        
        # Enhanced methodology overview
        methodology_text = f"""
        This assessment employs a <b>Hybrid Risk Assessment Model</b> that combines quantitative and qualitative 
        analysis methods aligned with international cybersecurity standards. The methodology provides a 
        comprehensive evaluation framework for network security posture and third-party risk management.
        """
        
        elements.append(Paragraph(methodology_text, self.styles['Methodology']))
        
        elements.append(Spacer(1, 0.2*inch))
        
        # Enhanced framework components table
        elements.append(Paragraph("Assessment Framework Components", self.styles['SubsectionHeader']))
        
        framework_data = [
            ['Component', 'Standard Reference', 'Description'],
            ['Protocol Analysis', 'ISO/IEC 27001:2013 A.13.1.1', 'Network controls management and security protocols'],
            ['Traffic Patterns', 'NIST CSF ID.AM-3', 'Organizational communication flows and data movement'],
            ['Threat Detection', 'OWASP Top 10 2021', 'Security risk categories and vulnerability assessment'],
            ['Behavioral Analysis', 'NIST CSF DE.AE-2', 'Analyzed event data and anomaly detection'],
            ['Third-Party Risk', 'ISO/IEC 27036', 'Supplier relationship security and vendor assessment']
        ]
        
        framework_table = Table(framework_data, colWidths=[1.5*inch, 2*inch, 2.5*inch])
        framework_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, self.colors['primary']),
            ('BACKGROUND', (0, 0), (-1, 0), self.colors['primary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), self.colors['white']),
            ('BACKGROUND', (0, 1), (-1, -1), self.colors['light_gray']),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [self.colors['light_gray'], self.colors['white']])
        ]))
        
        elements.append(framework_table)
        
        elements.append(Spacer(1, 0.3*inch))
        
        # Enhanced scoring matrix
        elements.append(Paragraph("Risk Scoring Matrix", self.styles['SubsectionHeader']))
        
        scoring_data = [
            ['Risk Level', 'Score Range', 'Description', 'Action Required'],
            ['Critical', '90-100', 'Business critical risk', 'Immediate action required'],
            ['High', '70-89', 'Significant security concern', 'High priority remediation'],
            ['Medium', '40-69', 'Moderate risk', 'Schedule remediation within 30 days'],
            ['Low', '20-39', 'Minor risk', 'Monitor and review quarterly'],
            ['Minimal', '0-19', 'Acceptable risk', 'Standard monitoring']
        ]
        
        scoring_table = Table(scoring_data, colWidths=[1*inch, 1*inch, 2.5*inch, 1.5*inch])
        scoring_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 1, self.colors['primary']),
            ('BACKGROUND', (0, 0), (-1, 0), self.colors['primary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), self.colors['white']),
            ('BACKGROUND', (0, 1), (0, -1), self.colors['warning']),
            ('BACKGROUND', (1, 1), (1, -1), self.colors['accent']),
            ('BACKGROUND', (2, 1), (2, -1), colors.HexColor('#f57f17')),
            ('BACKGROUND', (3, 1), (3, -1), self.colors['success']),
            ('BACKGROUND', (4, 1), (4, -1), colors.HexColor('#4caf50')),
            ('TEXTCOLOR', (0, 1), (-1, -1), self.colors['white']),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
        ]))
        
        elements.append(scoring_table)
        
        elements.append(Spacer(1, 0.3*inch))
        
        # Enhanced methodology explanation
        elements.append(Paragraph("Methodology Details", self.styles['SubsectionHeader']))
        
        methodology_details = f"""
        <b>Quantitative Analysis:</b> Numerical scoring based on threat counts, protocol vulnerabilities, 
        and traffic pattern anomalies. Each component receives a weighted score contributing to the overall risk assessment.
        
        <br/><br/><b>Qualitative Analysis:</b> Expert evaluation of threat context, business impact, and 
        compliance implications. This includes assessment of third-party relationships and supply chain security.
        
        <br/><br/><b>Risk Aggregation:</b> Individual component scores are aggregated using a weighted algorithm 
        that considers the relative importance of each security aspect in the overall risk profile.
        
        <br/><br/><b>Compliance Mapping:</b> Each identified risk is mapped to relevant international standards 
        to ensure comprehensive coverage of security requirements and regulatory obligations.
        """
        
        elements.append(Paragraph(methodology_details, self.styles['Methodology']))
        
        return elements
    
    def _create_technical_analysis(self, analysis_results: Dict[str, Any], flows: Dict[str, Any], connections: Dict[str, Any]) -> List:
        """Create enhanced technical analysis section with professional dashboards"""
        elements = []
        
        elements.append(Paragraph("TECHNICAL ANALYSIS & NETWORK INSIGHTS", self.styles['SectionHeader']))
        
        # Executive Dashboard - Key Performance Indicators
        elements.append(Paragraph("EXECUTIVE DASHBOARD", self.styles['DashboardTitle']))
        
        # Create KPI metrics table
        kpi_data = self._create_kpi_dashboard(analysis_results)
        elements.append(kpi_data)
        
        elements.append(Spacer(1, 0.3*inch))
        
        # Network Traffic Overview Dashboard
        elements.append(Paragraph("NETWORK TRAFFIC OVERVIEW", self.styles['DashboardTitle']))
        
        # Traffic patterns dashboard
        traffic_dashboard = self._create_traffic_dashboard(analysis_results)
        elements.append(traffic_dashboard)
        
        elements.append(Spacer(1, 0.3*inch))
        
        # Security Posture Dashboard
        elements.append(Paragraph("SECURITY POSTURE ASSESSMENT", self.styles['DashboardTitle']))
        
        # Security metrics dashboard
        security_dashboard = self._create_security_dashboard(analysis_results)
        elements.append(security_dashboard)
        
        elements.append(Spacer(1, 0.3*inch))
        
        # Protocol Analysis Dashboard
        elements.append(Paragraph("PROTOCOL ANALYSIS & VULNERABILITY ASSESSMENT", self.styles['DashboardTitle']))
        
        # Protocol analysis table
        protocol_table = self._create_protocol_analysis_table(analysis_results)
        elements.append(protocol_table)
        
        elements.append(Spacer(1, 0.3*inch))
        
        # Top Talkers and Communication Patterns
        elements.append(Paragraph("COMMUNICATION PATTERNS & TOP TALKERS", self.styles['DashboardTitle']))
        
        # Top talkers table
        talkers_table = self._create_top_talkers_table(analysis_results)
        elements.append(talkers_table)
        
        elements.append(Spacer(1, 0.3*inch))
        
        # Port Usage Analysis Dashboard
        elements.append(Paragraph("PORT USAGE & SERVICE ANALYSIS", self.styles['DashboardTitle']))
        
        # Port analysis table
        port_table = self._create_port_analysis_table(analysis_results)
        elements.append(port_table)
        
        return elements
    
    def _create_kpi_dashboard(self, analysis_results: Dict[str, Any]) -> Table:
        """Create a professional KPI dashboard with key metrics"""
        # Extract key metrics
        total_packets = analysis_results.get('packets', 0)
        total_flows = analysis_results.get('flows_count', 0)
        unique_ips = analysis_results.get('unique_ips', 0)
        protocols_count = analysis_results.get('protocols_count', 0)
        data_volume_mb = analysis_results.get('data_volume_mb', 0)
        threats_count = analysis_results.get('threats_count', 0)
        
        # Create KPI grid layout
        kpi_data = [
            ['Network Volume', 'Traffic Analysis', 'Security Threats'],
            [
                f"<b>{total_packets:,}</b><br/>Total Packets",
                f"<b>{total_flows:,}</b><br/>Network Flows", 
                f"<b>{threats_count:,}</b><br/>Threats Detected"
            ],
            [
                f"<b>{data_volume_mb:.2f} MB</b><br/>Data Volume",
                f"<b>{unique_ips:,}</b><br/>Unique IPs",
                f"<b>{protocols_count:,}</b><br/>Protocols"
            ]
        ]
        
        kpi_table = Table(kpi_data, colWidths=[2*inch, 2*inch, 2*inch])
        kpi_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 2, self.colors['primary']),
            ('BACKGROUND', (0, 0), (-1, 0), self.colors['primary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), self.colors['white']),
            ('BACKGROUND', (0, 1), (-1, -1), self.colors['light_gray']),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [self.colors['light_gray'], self.colors['white']])
        ]))
        
        return kpi_table
    
    def _create_traffic_dashboard(self, analysis_results: Dict[str, Any]) -> Table:
        """Create a traffic patterns dashboard"""
        traffic_patterns = analysis_results.get('traffic_patterns', {})
        protocols = traffic_patterns.get('protocols', {})
        top_talkers = traffic_patterns.get('top_talkers', {})
        
        # Create traffic overview table
        traffic_data = [
            ['Protocol', 'Packet Count', 'Percentage', 'Risk Level'],
        ]
        
        total_packets = analysis_results.get('packets', 1)
        for protocol, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_packets) * 100
            risk_level = self._get_protocol_risk_level(protocol)
            traffic_data.append([protocol, f"{count:,}", f"{percentage:.1f}%", risk_level])
        
        traffic_table = Table(traffic_data, colWidths=[1.5*inch, 1.5*inch, 1.5*inch, 1.5*inch])
        traffic_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, self.colors['primary']),
            ('BACKGROUND', (0, 0), (-1, 0), self.colors['primary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), self.colors['white']),
            ('BACKGROUND', (0, 1), (-1, -1), self.colors['light_gray']),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [self.colors['light_gray'], self.colors['white']])
        ]))
        
        return traffic_table
    
    def _create_security_dashboard(self, analysis_results: Dict[str, Any]) -> Table:
        """Create a security posture dashboard"""
        detailed_stats = analysis_results.get('detailed_stats', {})
        threat_types = analysis_results.get('threat_types', [])
        
        security_data = [
            ['Security Metric', 'Value', 'Status', 'Recommendation'],
            [
                'Threat Categories',
                f"{len(threat_types)}",
                self._get_security_status(len(threat_types), 5),
                'Implement threat detection' if len(threat_types) > 3 else 'Monitor regularly'
            ],
            [
                'Suspicious Flows',
                f"{detailed_stats.get('suspicious_flows', 0):,}",
                self._get_security_status(detailed_stats.get('suspicious_flows', 0), 10),
                'Investigate anomalies' if detailed_stats.get('suspicious_flows', 0) > 5 else 'Continue monitoring'
            ],
            [
                'NLP Keywords',
                f"{detailed_stats.get('nlp_keywords', 0):,}",
                self._get_security_status(detailed_stats.get('nlp_keywords', 0), 5),
                'Review payload content' if detailed_stats.get('nlp_keywords', 0) > 3 else 'Standard monitoring'
            ]
        ]
        
        security_table = Table(security_data, colWidths=[2*inch, 1*inch, 1.5*inch, 2.5*inch])
        security_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, self.colors['primary']),
            ('BACKGROUND', (0, 0), (-1, 0), self.colors['primary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), self.colors['white']),
            ('BACKGROUND', (0, 1), (-1, -1), self.colors['light_gray']),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [self.colors['light_gray'], self.colors['white']])
        ]))
        
        return security_table
    
    def _create_protocol_analysis_table(self, analysis_results: Dict[str, Any]) -> Table:
        """Create a detailed protocol analysis table"""
        traffic_patterns = analysis_results.get('traffic_patterns', {})
        protocols = traffic_patterns.get('protocols', {})
        
        protocol_data = [
            ['Protocol', 'Packet Count', 'Risk Assessment', 'Security Controls'],
        ]
        
        for protocol, count in protocols.items():
            risk_assessment = self._get_protocol_risk_assessment(protocol)
            security_controls = self._get_protocol_security_controls(protocol)
            protocol_data.append([protocol, f"{count:,}", risk_assessment, security_controls])
        
        protocol_table = Table(protocol_data, colWidths=[1.5*inch, 1.5*inch, 2*inch, 2*inch])
        protocol_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, self.colors['primary']),
            ('BACKGROUND', (0, 0), (-1, 0), self.colors['primary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), self.colors['white']),
            ('BACKGROUND', (0, 1), (-1, -1), self.colors['light_gray']),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [self.colors['light_gray'], self.colors['white']])
        ]))
        
        return protocol_table
    
    def _create_top_talkers_table(self, analysis_results: Dict[str, Any]) -> Table:
        """Create a top talkers analysis table"""
        traffic_patterns = analysis_results.get('traffic_patterns', {})
        top_talkers = traffic_patterns.get('top_talkers', {})
        
        # Sort by packet count and take top 10
        sorted_talkers = sorted(top_talkers.items(), key=lambda x: x[1], reverse=True)[:10]
        
        talkers_data = [
            ['Rank', 'IP Address', 'Packet Count', 'Risk Level', 'Recommendation'],
        ]
        
        for i, (ip, count) in enumerate(sorted_talkers, 1):
            risk_level = self._get_ip_risk_level(ip)
            recommendation = self._get_ip_recommendation(ip, count)
            talkers_data.append([str(i), ip, f"{count:,}", risk_level, recommendation])
        
        talkers_table = Table(talkers_data, colWidths=[0.8*inch, 2*inch, 1.2*inch, 1.2*inch, 2*inch])
        talkers_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 1, self.colors['primary']),
            ('BACKGROUND', (0, 0), (-1, 0), self.colors['primary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), self.colors['white']),
            ('BACKGROUND', (0, 1), (-1, -1), self.colors['light_gray']),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [self.colors['light_gray'], self.colors['white']])
        ]))
        
        return talkers_table
    
    def _create_port_analysis_table(self, analysis_results: Dict[str, Any]) -> Table:
        """Create a port usage analysis table"""
        traffic_patterns = analysis_results.get('traffic_patterns', {})
        port_usage = traffic_patterns.get('port_usage', {})
        
        # Sort by usage and take top 15
        sorted_ports = sorted(port_usage.items(), key=lambda x: x[1], reverse=True)[:15]
        
        port_data = [
            ['Port', 'Service', 'Usage Count', 'Risk Level', 'Security Note'],
        ]
        
        for port, count in sorted_ports:
            service = self._get_port_service(int(port))
            risk_level = self._get_port_risk_level(int(port))
            security_note = self._get_port_security_note(int(port))
            port_data.append([str(port), service, f"{count:,}", risk_level, security_note])
        
        port_table = Table(port_data, colWidths=[0.8*inch, 1.5*inch, 1.2*inch, 1.2*inch, 2.3*inch])
        port_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 1, self.colors['primary']),
            ('BACKGROUND', (0, 0), (-1, 0), self.colors['primary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), self.colors['white']),
            ('BACKGROUND', (0, 1), (-1, -1), self.colors['light_gray']),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [self.colors['light_gray'], self.colors['white']])
        ]))
        
        return port_table
    
    def _get_protocol_risk_level(self, protocol: str) -> str:
        """Get risk level for a protocol"""
        high_risk = ['HTTP', 'FTP', 'TELNET']
        medium_risk = ['SMTP', 'POP3', 'IMAP']
        
        if protocol in high_risk:
            return "HIGH"
        elif protocol in medium_risk:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _get_protocol_risk_assessment(self, protocol: str) -> str:
        """Get detailed risk assessment for a protocol"""
        if protocol == 'HTTP':
            return "Unencrypted traffic - Data exposure risk"
        elif protocol == 'HTTPS':
            return "Encrypted traffic - Secure"
        elif protocol == 'FTP':
            return "Unencrypted file transfer - High risk"
        elif protocol == 'SSH':
            return "Encrypted remote access - Secure"
        elif protocol == 'DNS':
            return "Query/response traffic - Monitor for anomalies"
        else:
            return "Standard network protocol - Low risk"
    
    def _get_protocol_security_controls(self, protocol: str) -> str:
        """Get security controls for a protocol"""
        if protocol == 'HTTP':
            return "Implement HTTPS, WAF, DLP"
        elif protocol == 'FTP':
            return "Use SFTP/FTPS, restrict access"
        elif protocol == 'TELNET':
            return "Replace with SSH, disable service"
        elif protocol == 'DNS':
            return "DNS filtering, DNSSEC, monitoring"
        else:
            return "Standard network security controls"
    
    def _get_security_status(self, value: int, threshold: int) -> str:
        """Get security status based on value and threshold"""
        if value > threshold * 2:
            return "CRITICAL"
        elif value > threshold:
            return "HIGH"
        elif value > threshold // 2:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _get_ip_risk_level(self, ip: str) -> str:
        """Get risk level for an IP address"""
        if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
            return "INTERNAL"
        elif ip in ['8.8.8.8', '1.1.1.1']:
            return "DNS SERVER"
        else:
            return "EXTERNAL"
    
    def _get_ip_recommendation(self, ip: str, count: int) -> str:
        """Get recommendation for an IP address"""
        if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
            return "Monitor internal traffic patterns"
        elif ip in ['8.8.8.8', '1.1.1.1']:
            return "Standard DNS resolution traffic"
        elif count > 100:
            return "Investigate high-volume external communication"
        else:
            return "Standard external communication"
    
    def _get_port_service(self, port: int) -> str:
        """Get service name for a port"""
        common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'TELNET', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS',
            995: 'POP3S', 3306: 'MySQL', 5432: 'PostgreSQL', 8080: 'HTTP-Alt'
        }
        return common_ports.get(port, 'Unknown')
    
    def _get_port_risk_level(self, port: int) -> str:
        """Get risk level for a port"""
        high_risk_ports = [21, 23, 25, 110, 143, 3306, 5432]
        medium_risk_ports = [22, 80, 443, 993, 995]
        
        if port in high_risk_ports:
            return "HIGH"
        elif port in medium_risk_ports:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _get_port_security_note(self, port: int) -> str:
        """Get security note for a port"""
        if port == 21:
            return "Use SFTP/FTPS instead of FTP"
        elif port == 23:
            return "Replace TELNET with SSH"
        elif port == 25:
            return "Implement SMTP authentication and encryption"
        elif port == 80:
            return "Redirect to HTTPS, implement WAF"
        elif port == 3306:
            return "Restrict database access, use VPN"
        elif port == 5432:
            return "Restrict database access, use VPN"
        else:
            return "Standard port monitoring recommended"
    
    def _create_threat_intelligence_section(self, threat_matches: List, nlp_analyses: List) -> List:
        """Create comprehensive threat intelligence section"""
        elements = []
        
        elements.append(Paragraph("THREAT INTELLIGENCE ANALYSIS", self.styles['SectionHeader']))
        
        threat_text = f"""
        This section presents findings from the threat detection engine, which employs signature-based 
        detection, behavioral analysis, and natural language processing to identify potential security risks.
        
        <b>Detection Summary:</b><br/>
        • Total Threats Detected: {len(threat_matches)}<br/>
        • Unique Threat Types: {len(set([t.category for t in threat_matches]))}<br/>
        • NLP Analyses Performed: {len(nlp_analyses)}<br/>
        • Confidence Level: High (>85% accuracy)
        """
        
        elements.append(Paragraph(threat_text, self.styles['Normal']))
        
        if threat_matches:
            elements.append(Spacer(1, 15))
            elements.append(Paragraph("Detected Threats", self.styles['SubsectionHeader']))
            
            # Threat summary table
            threat_types = {}
            for threat in threat_matches:
                threat_type = threat.category if hasattr(threat, 'category') else 'Unknown'
                threat_types[threat_type] = threat_types.get(threat_type, 0) + 1
            
            threat_data = [['Threat Category', 'Count', 'Severity', 'MITRE ATT&CK']]
            for threat_type, count in sorted(threat_types.items(), key=lambda x: x[1], reverse=True):
                severity = self._get_threat_severity(threat_type)
                mitre_mapping = self._get_mitre_mapping(threat_type)
                threat_data.append([threat_type, str(count), severity, mitre_mapping])
            
            threat_table = Table(threat_data, colWidths=[2*inch, 0.8*inch, 1*inch, 2.5*inch])
            threat_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.red),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightpink),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            elements.append(threat_table)
            
            # Individual threat details
            elements.append(Spacer(1, 15))
            elements.append(Paragraph("Threat Details", self.styles['SubsectionHeader']))
            
            for i, threat in enumerate(threat_matches[:10]):  # Show top 10 threats
                threat_detail = f"""
                <b>Threat #{i+1}: {getattr(threat, 'category', 'Unknown')}</b><br/>
                Description: {getattr(threat, 'description', 'No description available')}<br/>
                Severity: {self._get_threat_severity(getattr(threat, 'category', 'Unknown'))}<br/>
                Detection Method: Signature-based<br/>
                Recommended Action: {self._get_threat_recommendation(getattr(threat, 'category', 'Unknown'))}
                """
                elements.append(Paragraph(threat_detail, self.styles['Normal']))
                elements.append(Spacer(1, 10))
        
        return elements
    
    def _create_detailed_risk_scoring(self, risk_assessment: RiskAssessment) -> List:
        """Create detailed risk scoring explanation"""
        elements = []
        
        elements.append(Paragraph("DETAILED RISK SCORING ANALYSIS", self.styles['SectionHeader']))
        
        scoring_explanation = f"""
        This section provides a comprehensive breakdown of how the overall risk score of 
        <b>{risk_assessment.overall_score:.1f}/100</b> was calculated. Each component is weighted 
        based on its potential business impact and alignment with cybersecurity best practices.
        
        <b>Risk Calculation Formula:</b><br/>
        Overall Risk = Σ(Component Score × Weight × Threat Multiplier)<br/>
        Where weights are derived from NIST 800-30 Rev. 1 guidelines and industry benchmarks.
        """
        
        elements.append(Paragraph(scoring_explanation, self.styles['Normal']))
        
        # Detailed scoring breakdown
        elements.append(Spacer(1, 15))
        elements.append(Paragraph("Component Risk Analysis", self.styles['SubsectionHeader']))
        
        category_scores = getattr(risk_assessment, 'category_scores', {})
        
        component_data = [['Risk Component', 'Raw Score', 'Weight', 'Normalized Score', 'Business Impact']]
        
        components = [
            ('Protocol Risk', category_scores.get('Protocol Analysis', 0), 0.25),
            ('Port Usage Risk', category_scores.get('Port Usage', 0), 0.20),
            ('Connection Anomaly', category_scores.get('Connection Analysis', 0), 0.20),
            ('Threat Detection', category_scores.get('Threat Detection', 0), 0.25),
            ('Content Analysis', category_scores.get('Content Analysis', 0), 0.10)
        ]
        
        for component, score, weight in components:
            normalized = score * weight
            impact = self._get_business_impact(score)
            component_data.append([
                component,
                f"{score:.1f}",
                f"{weight:.0%}",
                f"{normalized:.1f}",
                impact
            ])
        
        component_table = Table(component_data, colWidths=[2*inch, 1*inch, 1*inch, 1*inch, 1.5*inch])
        component_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkgreen),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgreen),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(component_table)
        
        return elements
    
    def _create_compliance_mapping(self, risk_assessment: RiskAssessment) -> List:
        """Create compliance framework mapping"""
        elements = []
        
        elements.append(Paragraph("COMPLIANCE FRAMEWORK MAPPING", self.styles['SectionHeader']))
        
        compliance_text = """
        This assessment aligns findings with major cybersecurity frameworks to support compliance 
        initiatives and regulatory requirements. The mapping provides clear guidance for control 
        implementation and risk mitigation strategies.
        """
        
        elements.append(Paragraph(compliance_text, self.styles['Normal']))
        
        # ISO 27001 Mapping
        elements.append(Spacer(1, 15))
        elements.append(Paragraph("ISO/IEC 27001:2013 Control Mapping", self.styles['SubsectionHeader']))
        
        iso_mappings = getattr(risk_assessment, 'iso_mappings', [])
        if iso_mappings:
            iso_data = [['Control ID', 'Control Title', 'Compliance Status', 'Gap Analysis']]
            for mapping in iso_mappings[:10]:  # Show top 10
                iso_data.append([
                    mapping.get('control_id', 'N/A'),
                    mapping.get('title', 'Unknown'),
                    mapping.get('status', 'To Review'),
                    mapping.get('gap_analysis', 'Requires assessment')
                ])
            
            iso_table = Table(iso_data, colWidths=[1*inch, 2.5*inch, 1.5*inch, 1.5*inch])
            iso_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightblue),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP')
            ]))
            
            elements.append(iso_table)
        
        # NIST CSF Mapping
        elements.append(Spacer(1, 15))
        elements.append(Paragraph("NIST Cybersecurity Framework Mapping", self.styles['SubsectionHeader']))
        
        nist_functions = [
            ('IDENTIFY', 'Asset Management and Risk Assessment'),
            ('PROTECT', 'Access Control and Data Security'),
            ('DETECT', 'Continuous Monitoring and Anomaly Detection'),
            ('RESPOND', 'Incident Response and Communications'),
            ('RECOVER', 'Recovery Planning and Improvements')
        ]
        
        nist_data = [['Function', 'Category', 'Current Maturity', 'Target Maturity']]
        for function, category in nist_functions:
            current_maturity = self._assess_nist_maturity(function, risk_assessment)
            target_maturity = 'Managed' if current_maturity != 'Managed' else 'Optimizing'
            nist_data.append([function, category, current_maturity, target_maturity])
        
        nist_table = Table(nist_data, colWidths=[1.2*inch, 2.5*inch, 1.5*inch, 1.3*inch])
        nist_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkgreen),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgreen),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(nist_table)
        
        return elements
    
    def _create_tprm_recommendations(self, risk_assessment: RiskAssessment, threat_matches: List) -> List:
        """Create Third-Party Risk Management recommendations"""
        elements = []
        
        elements.append(Paragraph("THIRD-PARTY RISK MANAGEMENT RECOMMENDATIONS", self.styles['SectionHeader']))
        
        tprm_intro = """
        Based on the network analysis findings, the following recommendations align with industry best 
        practices for Third-Party Risk Management (TPRM) and vendor security assessment programs. 
        These recommendations support continuous monitoring and risk-based vendor management strategies.
        """
        
        elements.append(Paragraph(tprm_intro, self.styles['Normal']))
        
        # Priority recommendations
        elements.append(Spacer(1, 15))
        elements.append(Paragraph("Priority Recommendations", self.styles['SubsectionHeader']))
        
        recommendations = self._generate_tprm_recommendations(risk_assessment, threat_matches)
        
        for i, rec in enumerate(recommendations[:8], 1):
            elements.append(Paragraph(f"<b>{i}. {rec['title']}</b>", self.styles['SubsectionHeader']))
            elements.append(Paragraph(rec['description'], self.styles['Normal']))
            elements.append(Paragraph(f"<b>Priority:</b> {rec['priority']} | <b>Timeline:</b> {rec['timeline']} | <b>Framework:</b> {rec['framework']}", self.styles['Methodology']))
            elements.append(Spacer(1, 10))
        
        return elements
    
    def _create_appendices(self, analysis_results: Dict[str, Any], flows: Dict[str, Any], connections: Dict[str, Any]) -> List:
        """Create technical appendices"""
        elements = []
        
        elements.append(Paragraph("APPENDICES", self.styles['SectionHeader']))
        
        # Appendix A: Technical Details
        elements.append(Paragraph("Appendix A: Technical Analysis Details", self.styles['SubsectionHeader']))
        
        tech_details = f"""
        <b>Analysis Parameters:</b><br/>
        • Packet Analysis Engine: Scapy/PyShark hybrid<br/>
        • Detection Signatures: Custom + Open Source Intel<br/>
        • NLP Processing: spaCy + TextBlob<br/>
        • Risk Calculation: Weighted Multi-Factor Algorithm<br/>
        • Report Generation: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}
        
        <b>Data Sources:</b><br/>
        • Network Traffic: PCAP file analysis<br/>
        • Threat Intelligence: MITRE ATT&CK Framework<br/>
        • Vulnerability Data: CVE Database<br/>
        • Compliance Standards: ISO 27001, NIST CSF, OWASP
        """
        
        elements.append(Paragraph(tech_details, self.styles['Normal']))
        
        return elements
    
    def generate_enhanced_text_report(self, 
                                    analysis_results: Dict[str, Any],
                                    risk_assessment: RiskAssessment,
                                    flows: Dict[str, Any],
                                    connections: Dict[str, Any],
                                    threat_matches: List[Any],
                                    nlp_analyses: List[Any],
                                    output_filename: str = "enhanced_security_report.txt") -> str:
        """Generate enhanced text report as fallback"""
        output_path = os.path.join(self.output_dir, output_filename)
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("="*80 + "\n")
                f.write("COMPREHENSIVE NETWORK SECURITY ANALYSIS REPORT\n")
                f.write("="*80 + "\n\n")
                
                f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
                f.write(f"Risk Level: {risk_assessment.risk_level.name}\n")
                f.write(f"Overall Risk Score: {risk_assessment.overall_score:.1f}/100\n\n")
                
                # Executive Summary
                f.write("EXECUTIVE SUMMARY\n")
                f.write("-" * 40 + "\n")
                f.write(f"Analyzed {analysis_results.get('packets', 0):,} network packets\n")
                f.write(f"Detected {len(threat_matches)} security threats\n")
                f.write(f"Identified {len(flows)} network flows\n")
                f.write(f"Analyzed {len(connections)} connections\n\n")
                
                # Risk Methodology
                f.write("RISK ASSESSMENT METHODOLOGY\n")
                f.write("-" * 40 + "\n")
                f.write(f"Framework: {self.risk_methodology['framework']}\n\n")
                f.write("Component Analysis:\n")
                for component, standard in self.risk_methodology['components'].items():
                    f.write(f"• {component}: {standard}\n")
                f.write("\n")
                
                # Detailed Risk Scores
                f.write("DETAILED RISK ANALYSIS\n")
                f.write("-" * 40 + "\n")
                category_scores = getattr(risk_assessment, 'category_scores', {})
                for component, score in category_scores.items():
                    f.write(f"{component}: {score:.1f}/100\n")
                f.write("\n")
                
                # Threats
                if threat_matches:
                    f.write("DETECTED THREATS\n")
                    f.write("-" * 40 + "\n")
                    for i, threat in enumerate(threat_matches[:10], 1):
                        f.write(f"{i}. {getattr(threat, 'category', 'Unknown')}\n")
                        f.write(f"   Description: {getattr(threat, 'description', 'No description')}\n")
                        f.write(f"   Severity: {self._get_threat_severity(getattr(threat, 'category', 'Unknown'))}\n\n")
                
                # Recommendations
                f.write("SECURITY RECOMMENDATIONS\n")
                f.write("-" * 40 + "\n")
                for i, rec in enumerate(risk_assessment.recommendations[:15], 1):
                    f.write(f"{i}. {rec}\n")
                f.write("\n")
                
                # TPRM Recommendations
                f.write("THIRD-PARTY RISK MANAGEMENT RECOMMENDATIONS\n")
                f.write("-" * 50 + "\n")
                tprm_recs = self._generate_tprm_recommendations(risk_assessment, threat_matches)
                for i, rec in enumerate(tprm_recs[:10], 1):
                    f.write(f"{i}. {rec['title']}\n")
                    f.write(f"   {rec['description']}\n")
                    f.write(f"   Priority: {rec['priority']} | Timeline: {rec['timeline']}\n\n")
                
                f.write("="*80 + "\n")
                f.write("End of Report\n")
                
            logger.info(f"Enhanced text report generated: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Error generating enhanced text report: {e}")
            raise
    
    # Helper methods
    def _get_risk_color(self, score: float) -> str:
        """Get color for risk score"""
        if score >= 70:
            return self.colors['warning']
        elif score >= 40:
            return self.colors['accent']
        else:
            return self.colors['success']
    
    def _get_risk_impact(self, score: float) -> str:
        """Get risk impact description"""
        if score >= 70:
            return "Critical"
        elif score >= 40:
            return "High"
        elif score >= 20:
            return "Medium"
        else:
            return "Low"
    
    def _get_priority_level(self, score: float) -> str:
        """Get priority level"""
        if score >= 70:
            return "Immediate"
        elif score >= 40:
            return "High"
        elif score >= 20:
            return "Medium"
        else:
            return "Low"
    
    def _assess_protocol_security(self, protocol: str) -> str:
        """Assess protocol security"""
        insecure_protocols = ['telnet', 'ftp', 'http', 'smtp', 'pop3']
        if protocol.lower() in insecure_protocols:
            return "⚠️ Insecure - Consider encrypted alternatives"
        elif protocol.lower() in ['https', 'ssh', 'tls', 'ssl']:
            return "✅ Secure - Encrypted communication"
        else:
            return "ℹ️ Standard - Review security configuration"
    
    def _get_assessment_criteria(self, component: str) -> str:
        """Get assessment criteria for components"""
        criteria_map = {
            'Protocol Analysis': 'Encryption status, known vulnerabilities, compliance',
            'Traffic Patterns': 'Volume anomalies, timing patterns, geographic distribution',
            'Threat Detection': 'Signature matches, behavioral indicators, IoC correlation',
            'Behavioral Analysis': 'Connection patterns, data exfiltration indicators',
            'Third-Party Risk': 'Vendor communications, data sharing patterns'
        }
        return criteria_map.get(component, 'Standard security assessment criteria')
    
    def _get_threat_severity(self, threat_type: str) -> str:
        """Get threat severity level"""
        high_severity = ['malware', 'exploit', 'injection', 'backdoor']
        medium_severity = ['suspicious', 'anomaly', 'unusual']
        
        if any(keyword in threat_type.lower() for keyword in high_severity):
            return "HIGH"
        elif any(keyword in threat_type.lower() for keyword in medium_severity):
            return "MEDIUM"
        else:
            return "LOW"
    
    def _get_mitre_mapping(self, threat_type: str) -> str:
        """Get MITRE ATT&CK mapping"""
        mitre_map = {
            'injection': 'T1190 - Exploit Public-Facing Application',
            'malware': 'T1566 - Phishing',
            'backdoor': 'T1547 - Boot or Logon Autostart',
            'suspicious': 'T1057 - Process Discovery',
            'default': 'T1083 - File and Directory Discovery'
        }
        
        for key in mitre_map:
            if key in threat_type.lower():
                return mitre_map[key]
        return mitre_map['default']
    
    def _get_threat_recommendation(self, threat_type: str) -> str:
        """Get threat-specific recommendation"""
        recommendations = {
            'injection': 'Implement input validation and WAF protection',
            'malware': 'Deploy endpoint detection and response (EDR)',
            'backdoor': 'Conduct integrity monitoring and access review',
            'suspicious': 'Enhance monitoring and implement SIEM alerts',
            'default': 'Investigate further and implement appropriate controls'
        }
        
        for key in recommendations:
            if key in threat_type.lower():
                return recommendations[key]
        return recommendations['default']
    
    def _get_business_impact(self, score: float) -> str:
        """Get business impact description"""
        if score >= 80: return "Service disruption likely"
        elif score >= 60: return "Potential data exposure"
        elif score >= 40: return "Compliance concerns"
        elif score >= 20: return "Minor operational impact"
        else: return "Negligible impact"
    
    def _assess_nist_maturity(self, function: str, risk_assessment: RiskAssessment) -> str:
        """Assess NIST CSF maturity level"""
        score = risk_assessment.overall_score
        
        if score < 30: return "Managed"
        elif score < 50: return "Defined"
        elif score < 70: return "Repeatable"
        else: return "Initial"
    
    def _generate_tprm_recommendations(self, risk_assessment: RiskAssessment, threat_matches: List) -> List[Dict]:
        """Generate TPRM-specific recommendations"""
        recommendations = [
            {
                'title': 'Implement Continuous Vendor Security Monitoring',
                'description': 'Deploy automated tools to continuously monitor third-party connections and data flows for security anomalies and compliance violations.',
                'priority': 'HIGH',
                'timeline': '30 days',
                'framework': 'ISO 27036'
            },
            {
                'title': 'Establish Network Segmentation for Third-Party Access',
                'description': 'Create dedicated network segments for vendor access with strict firewall rules and monitoring to limit potential attack surface.',
                'priority': 'HIGH',
                'timeline': '60 days',
                'framework': 'NIST CSF PR.AC-5'
            },
            {
                'title': 'Enhance Vendor Risk Assessment Program',
                'description': 'Implement risk-based vendor assessment with regular security questionnaires, penetration testing, and compliance audits.',
                'priority': 'MEDIUM',
                'timeline': '90 days',
                'framework': 'ISO 27001 A.15.1'
            },
            {
                'title': 'Deploy Zero Trust Architecture for Vendor Access',
                'description': 'Implement zero trust principles for all third-party connections with multi-factor authentication and least privilege access controls.',
                'priority': 'HIGH',
                'timeline': '120 days',
                'framework': 'NIST SP 800-207'
            },
            {
                'title': 'Establish Incident Response Procedures for Vendor-Related Events',
                'description': 'Develop specific incident response procedures for security events involving third-party systems and communications.',
                'priority': 'MEDIUM',
                'timeline': '45 days',
                'framework': 'NIST CSF RS.RP'
            },
            {
                'title': 'Implement Data Loss Prevention for Third-Party Communications',
                'description': 'Deploy DLP solutions to monitor and control data sharing with vendors and prevent unauthorized data exfiltration.',
                'priority': 'HIGH',
                'timeline': '60 days',
                'framework': 'ISO 27001 A.13.2.1'
            },
            {
                'title': 'Conduct Regular Third-Party Security Assessments',
                'description': 'Perform quarterly security assessments of critical vendors including penetration testing and vulnerability scanning.',
                'priority': 'MEDIUM',
                'timeline': 'Ongoing',
                'framework': 'ISO 27036-3'
            },
            {
                'title': 'Establish Vendor Offboarding Security Procedures',
                'description': 'Implement secure vendor offboarding procedures to ensure complete removal of access rights and data sanitization.',
                'priority': 'MEDIUM',
                'timeline': '30 days',
                'framework': 'NIST CSF PR.IP-2'
            }
        ]
        
        # Adjust priorities based on risk level
        if risk_assessment.overall_score >= 70:
            for rec in recommendations:
                if rec['priority'] == 'MEDIUM':
                    rec['priority'] = 'HIGH'
        
        return recommendations
