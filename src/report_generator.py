"""
Report Generator - Professional PDF report generation
Creates comprehensive, corporate-style cybersecurity reports with charts and analysis
"""

import os
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import base64
from io import BytesIO

# Import required libraries with fallbacks
try:
    import matplotlib
    matplotlib.use('Agg')  # Use non-interactive backend
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

# Handle seaborn import with fallback
try:
    import seaborn as sns
    SEABORN_AVAILABLE = True
except ImportError:
    SEABORN_AVAILABLE = False
    print("WARNING: seaborn not available. Using default matplotlib styles.")

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.graphics.shapes import Drawing, Rect
    from reportlab.graphics.charts.piecharts import Pie
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
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

class ReportGenerator:
    """
    Professional PDF report generator for PCAP analysis results
    Creates comprehensive cybersecurity reports with executive summaries,
    technical details, visualizations, and compliance mappings
    """
    
    def __init__(self, output_dir: str = "output"):
        """
        Initialize the report generator
        
        Args:
            output_dir: Directory for output files
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # Configure matplotlib style if available
        if MATPLOTLIB_AVAILABLE and SEABORN_AVAILABLE:
            try:
                plt.style.use('seaborn-v0_8')
                sns.set_palette("husl")
            except:
                # Fallback for older seaborn versions
                pass
        
        # Initialize styles if reportlab available
        if REPORTLAB_AVAILABLE:
            self.styles = getSampleStyleSheet()
            self._setup_custom_styles()
        else:
            self.styles = None
        
        # Company branding (placeholder)
        self.company_name = "CyberSec Analytics"
        self.company_tagline = "Advanced Network Security Intelligence"
        
    def _setup_custom_styles(self):
        """Setup custom paragraph styles for the report"""
        
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.darkblue,
            alignment=TA_CENTER
        ))
        
        # Section header style
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading1'],
            fontSize=16,
            spaceAfter=12,
            spaceBefore=20,
            textColor=colors.darkblue,
            borderWidth=1,
            borderColor=colors.darkblue,
            borderPadding=5
        ))
        
        # Subsection header style
        self.styles.add(ParagraphStyle(
            name='SubsectionHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceAfter=8,
            spaceBefore=12,
            textColor=colors.blue
        ))
        
        # Executive summary style
        self.styles.add(ParagraphStyle(
            name='ExecutiveSummary',
            parent=self.styles['Normal'],
            fontSize=11,
            leading=14,
            spaceAfter=6,
            leftIndent=20,
            rightIndent=20,
            borderWidth=1,
            borderColor=colors.grey,
            borderPadding=10,
            backColor=colors.lightgrey
        ))
        
        # Risk level styles
        risk_colors = {
            'critical': colors.darkred,
            'high': colors.red,
            'medium': colors.orange,
            'low': colors.yellow,
            'minimal': colors.green
        }
        
        for level, color in risk_colors.items():
            self.styles.add(ParagraphStyle(
                name=f'Risk{level.title()}',
                parent=self.styles['Normal'],
                fontSize=12,
                textColor=color,
                fontName='Helvetica-Bold'
            ))
    
    def create_chart(self, chart_type: str, data: Dict[str, Any], 
                    title: str, filename: str) -> str:
        """
        Create various types of charts for the report
        
        Args:
            chart_type: Type of chart ('pie', 'bar', 'line', 'scatter')
            data: Chart data
            title: Chart title
            filename: Output filename
            
        Returns:
            str: Path to the generated chart image
        """
        if not MATPLOTLIB_AVAILABLE:
            # Return empty string if matplotlib not available
            return ""
        
        plt.figure(figsize=(10, 6))
        chart_path = os.path.join(self.output_dir, f"{filename}.png")
        
        try:
            if chart_type == 'pie':
                labels = list(data.keys())
                sizes = list(data.values())
                colors = plt.cm.Set3(np.linspace(0, 1, len(labels)))
                
                plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', 
                       startangle=90)
                plt.axis('equal')
                
            elif chart_type == 'bar':
                labels = list(data.keys())
                values = list(data.values())
                colors = plt.cm.viridis(np.linspace(0, 1, len(labels)))
                
                bars = plt.bar(labels, values, color=colors)
                plt.xticks(rotation=45, ha='right')
                plt.ylabel('Count')
                
                # Add value labels on bars
                for bar in bars:
                    height = bar.get_height()
                    plt.text(bar.get_x() + bar.get_width()/2., height,
                           f'{int(height)}', ha='center', va='bottom')
                
            elif chart_type == 'horizontal_bar':
                labels = list(data.keys())
                values = list(data.values())
                colors = plt.cm.plasma(np.linspace(0, 1, len(labels)))
                
                plt.barh(labels, values, color=colors)
                plt.xlabel('Score')
                
            elif chart_type == 'line':
                # Expecting data to be {x_values: y_values}
                x_vals = list(data.keys())
                y_vals = list(data.values())
                plt.plot(x_vals, y_vals, marker='o', linewidth=2, markersize=6)
                plt.xticks(rotation=45)
                plt.ylabel('Value')
                
            elif chart_type == 'scatter':
                # Expecting data to be {'x': [x_vals], 'y': [y_vals]}
                plt.scatter(data.get('x', []), data.get('y', []), 
                          alpha=0.6, s=50, c='blue')
                plt.xlabel('X Values')
                plt.ylabel('Y Values')
            
            plt.title(title, fontsize=14, fontweight='bold', pad=20)
            plt.tight_layout()
            plt.savefig(chart_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            return chart_path
            
        except Exception as e:
            logger.error(f"Error creating chart {filename}: {e}")
            # Create placeholder chart
            plt.text(0.5, 0.5, f'Chart Error:\n{str(e)}', 
                    ha='center', va='center', transform=plt.gca().transAxes)
            plt.title(title)
            plt.savefig(chart_path, dpi=300, bbox_inches='tight')
            plt.close()
            return chart_path
    
    def create_risk_gauge(self, risk_score: float, filename: str) -> str:
        """
        Create a risk gauge chart
        
        Args:
            risk_score: Risk score (0-100)
            filename: Output filename
            
        Returns:
            str: Path to the generated gauge image
        """
        fig, ax = plt.subplots(figsize=(8, 6), subplot_kw=dict(projection='polar'))
        
        # Define risk levels and colors
        levels = [20, 40, 60, 80, 100]
        colors_list = ['green', 'yellow', 'orange', 'red', 'darkred']
        labels = ['Minimal', 'Low', 'Medium', 'High', 'Critical']
        
        # Create gauge
        theta = np.linspace(0, np.pi, 100)
        r = np.ones_like(theta)
        
        # Background segments
        for i, (level, color) in enumerate(zip(levels, colors_list)):
            start_theta = 0 if i == 0 else levels[i-1] * np.pi / 100
            end_theta = level * np.pi / 100
            theta_seg = np.linspace(start_theta, end_theta, 20)
            r_seg = np.ones_like(theta_seg)
            ax.fill_between(theta_seg, 0, r_seg, color=color, alpha=0.7)
        
        # Risk score needle
        needle_theta = risk_score * np.pi / 100
        ax.plot([needle_theta, needle_theta], [0, 1], 'k-', linewidth=4)
        ax.plot(needle_theta, 0, 'ko', markersize=10)
        
        # Formatting
        ax.set_ylim(0, 1)
        ax.set_theta_zero_location('W')
        ax.set_theta_direction(1)
        ax.set_thetagrids(np.arange(0, 181, 20), 
                         [f'{i}' for i in range(0, 101, 20)])
        ax.set_title(f'Risk Score: {risk_score:.1f}/100', 
                    fontsize=16, fontweight='bold', pad=30)
        
        gauge_path = os.path.join(self.output_dir, f"{filename}.png")
        plt.savefig(gauge_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return gauge_path
    
    def create_timeline_chart(self, timestamps: List[float], filename: str) -> str:
        """
        Create a timeline chart of network activity
        
        Args:
            timestamps: List of packet timestamps
            filename: Output filename
            
        Returns:
            str: Path to the generated chart
        """
        if not timestamps:
            return self.create_chart('bar', {'No Data': 1}, 'Timeline', filename)
        
        # Convert timestamps to datetime
        datetimes = [datetime.fromtimestamp(ts) for ts in timestamps]
        
        # Create time bins (10-minute intervals)
        start_time = min(datetimes)
        end_time = max(datetimes)
        
        # Calculate duration and appropriate bin size
        duration = (end_time - start_time).total_seconds()
        if duration < 300:  # Less than 5 minutes
            bin_size = 30  # 30-second bins
        elif duration < 3600:  # Less than 1 hour
            bin_size = 300  # 5-minute bins
        else:
            bin_size = 600  # 10-minute bins
        
        # Create bins
        current_time = start_time
        bins = []
        counts = []
        
        while current_time <= end_time:
            bin_end = current_time + pd.Timedelta(seconds=bin_size)
            count = sum(1 for dt in datetimes if current_time <= dt < bin_end)
            bins.append(current_time.strftime('%H:%M'))
            counts.append(count)
            current_time = bin_end
        
        # Create timeline chart
        plt.figure(figsize=(12, 6))
        plt.plot(bins, counts, marker='o', linewidth=2, markersize=4)
        plt.xlabel('Time')
        plt.ylabel('Packet Count')
        plt.title('Network Activity Timeline', fontsize=14, fontweight='bold')
        plt.xticks(rotation=45)
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        
        chart_path = os.path.join(self.output_dir, f"{filename}.png")
        plt.savefig(chart_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return chart_path
    
    def create_cover_page(self) -> List:
        """
        Create the report cover page
        
        Returns:
            List of Platypus flowables for the cover page
        """
        story = []
        
        # Company logo placeholder (you can replace with actual logo)
        story.append(Spacer(1, 1*inch))
        
        # Title
        title = Paragraph("NETWORK SECURITY ANALYSIS REPORT", self.styles['CustomTitle'])
        story.append(title)
        story.append(Spacer(1, 0.5*inch))
        
        # Subtitle
        subtitle = Paragraph(f"{self.company_name}<br/>{self.company_tagline}", 
                           self.styles['Heading2'])
        story.append(subtitle)
        story.append(Spacer(1, 1*inch))
        
        # Report details
        current_time = datetime.now().strftime("%B %d, %Y at %I:%M %p")
        details = f"""
        <b>Report Generated:</b> {current_time}<br/>
        <b>Analysis Type:</b> PCAP Network Traffic Analysis<br/>
        <b>Report Version:</b> 1.0<br/>
        <b>Classification:</b> Confidential
        """
        story.append(Paragraph(details, self.styles['Normal']))
        story.append(Spacer(1, 1*inch))
        
        # Disclaimer
        disclaimer = """
        <b>DISCLAIMER:</b> This report contains analysis of network traffic data 
        and identified potential security threats. The information contained herein 
        is confidential and should be handled according to your organization's 
        data classification policies. This analysis is based on available data 
        and threat intelligence at the time of generation.
        """
        story.append(Paragraph(disclaimer, self.styles['Normal']))
        
        story.append(PageBreak())
        return story
    
    def create_executive_summary(self, risk_assessment: RiskAssessment, 
                               analysis_stats: Dict[str, Any]) -> List:
        """
        Create executive summary section
        
        Args:
            risk_assessment: Risk assessment results
            analysis_stats: Analysis statistics
            
        Returns:
            List of Platypus flowables
        """
        story = []
        
        # Section header
        story.append(Paragraph("EXECUTIVE SUMMARY", self.styles['SectionHeader']))
        
        # Key findings
        findings = f"""
        Our comprehensive analysis of the network traffic data has identified 
        a <b>{risk_assessment.risk_level.name}</b> risk level with an overall 
        risk score of <b>{risk_assessment.overall_score:.1f}/100</b>.
        
        The analysis processed <b>{analysis_stats.get('total_packets', 0):,}</b> 
        network packets across <b>{analysis_stats.get('flows_count', 0)}</b> 
        unique flows, involving <b>{len(analysis_stats.get('unique_ips', []))}</b> 
        unique IP addresses.
        """
        
        story.append(Paragraph(findings, self.styles['ExecutiveSummary']))
        story.append(Spacer(1, 0.2*inch))
        
        # Risk level indicator
        risk_style = f"Risk{risk_assessment.risk_level.name.title()}"
        if risk_style in self.styles:
            risk_text = f"OVERALL RISK LEVEL: {risk_assessment.risk_level.name.upper()}"
            story.append(Paragraph(risk_text, self.styles[risk_style]))
        
        story.append(Spacer(1, 0.3*inch))
        
        # Key metrics table
        key_metrics_data = [
            ['Metric', 'Value'],
            ['Total Packets Analyzed', f"{analysis_stats.get('total_packets', 0):,}"],
            ['Unique IP Addresses', f"{len(analysis_stats.get('unique_ips', []))}"],
            ['Network Flows', f"{analysis_stats.get('flows_count', 0)}"],
            ['Risk Score', f"{risk_assessment.overall_score:.1f}/100"],
            ['Confidence Level', f"{risk_assessment.confidence*100:.1f}%"],
            ['Analysis Duration', f"{analysis_stats.get('duration', 0):.1f} seconds"]
        ]
        
        key_metrics_table = Table(key_metrics_data, colWidths=[3*inch, 2*inch])
        key_metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(key_metrics_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Top recommendations
        story.append(Paragraph("IMMEDIATE RECOMMENDATIONS", self.styles['SubsectionHeader']))
        
        top_recommendations = risk_assessment.recommendations[:5]
        for i, rec in enumerate(top_recommendations, 1):
            story.append(Paragraph(f"{i}. {rec}", self.styles['Normal']))
        
        story.append(PageBreak())
        return story
    
    def create_technical_analysis(self, flows: Dict[str, Any], 
                                connections: Dict[str, Any],
                                threat_matches: List[Any],
                                nlp_analyses: List[Any]) -> List:
        """
        Create technical analysis section with charts
        
        Args:
            flows: Flow analysis data
            connections: Connection analysis data
            threat_matches: Threat detection results
            nlp_analyses: NLP analysis results
            
        Returns:
            List of Platypus flowables
        """
        story = []
        
        # Section header
        story.append(Paragraph("TECHNICAL ANALYSIS", self.styles['SectionHeader']))
        
        # Protocol distribution
        story.append(Paragraph("Protocol Distribution", self.styles['SubsectionHeader']))
        
        if flows and 'protocol_distribution' in flows:
            protocol_chart = self.create_chart(
                'pie', 
                dict(flows['protocol_distribution']), 
                'Network Protocol Distribution',
                'protocol_distribution'
            )
            if os.path.exists(protocol_chart):
                story.append(Image(protocol_chart, width=5*inch, height=3*inch))
                story.append(Spacer(1, 0.2*inch))
        
        # Top flows analysis
        if flows and 'top_flows_by_bytes' in flows:
            story.append(Paragraph("Top Network Flows by Bytes", self.styles['SubsectionHeader']))
            
            flow_data = []
            flow_data.append(['Source IP', 'Destination IP', 'Protocol', 'Bytes', 'Packets'])
            
            for flow in flows['top_flows_by_bytes'][:10]:
                flow_data.append([
                    flow.get('src_ip', '')[:15],
                    flow.get('dst_ip', '')[:15], 
                    flow.get('protocol', ''),
                    f"{flow.get('bytes', 0):,}",
                    f"{flow.get('packets', 0):,}"
                ])
            
            flow_table = Table(flow_data, colWidths=[1.5*inch, 1.5*inch, 0.8*inch, 1*inch, 0.8*inch])
            flow_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(flow_table)
            story.append(Spacer(1, 0.3*inch))
        
        # Threat detection results
        if threat_matches:
            story.append(Paragraph("Threat Detection Results", self.styles['SubsectionHeader']))
            
            # Count threats by severity
            severity_counts = {}
            for match in threat_matches:
                severity = match.severity.name
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            if severity_counts:
                threat_chart = self.create_chart(
                    'bar',
                    severity_counts,
                    'Threats by Severity Level',
                    'threat_severity'
                )
                if os.path.exists(threat_chart):
                    story.append(Image(threat_chart, width=5*inch, height=3*inch))
                    story.append(Spacer(1, 0.2*inch))
            
            # Threat details table
            threat_data = [['Threat Type', 'Severity', 'Description']]
            for match in threat_matches[:15]:  # Limit to top 15
                threat_data.append([
                    match.category[:20],
                    match.severity.name,
                    match.description[:60] + ('...' if len(match.description) > 60 else '')
                ])
            
            threat_table = Table(threat_data, colWidths=[1.5*inch, 1*inch, 3.5*inch])
            threat_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.darkred),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(threat_table)
        
        story.append(PageBreak())
        return story
    
    def create_risk_analysis(self, risk_assessment: RiskAssessment) -> List:
        """
        Create risk analysis section
        
        Args:
            risk_assessment: Risk assessment results
            
        Returns:
            List of Platypus flowables
        """
        story = []
        
        # Section header
        story.append(Paragraph("RISK ANALYSIS", self.styles['SectionHeader']))
        
        # Risk gauge
        gauge_chart = self.create_risk_gauge(
            risk_assessment.overall_score, 
            'risk_gauge'
        )
        if os.path.exists(gauge_chart):
            story.append(Image(gauge_chart, width=4*inch, height=3*inch))
            story.append(Spacer(1, 0.3*inch))
        
        # Risk factors breakdown
        story.append(Paragraph("Risk Factors Breakdown", self.styles['SubsectionHeader']))
        
        if risk_assessment.category_scores:
            category_chart = self.create_chart(
                'horizontal_bar',
                risk_assessment.category_scores,
                'Risk Scores by Category',
                'risk_categories'
            )
            if os.path.exists(category_chart):
                story.append(Image(category_chart, width=6*inch, height=4*inch))
                story.append(Spacer(1, 0.3*inch))
        
        # Risk factors table
        risk_data = [['Risk Factor', 'Score', 'Weight', 'Impact']]
        for factor in risk_assessment.risk_factors:
            impact = factor.score * factor.weight
            risk_data.append([
                factor.name,
                f"{factor.score:.1f}",
                f"{factor.weight:.2f}",
                f"{impact:.1f}"
            ])
        
        risk_table = Table(risk_data, colWidths=[2.5*inch, 1*inch, 1*inch, 1*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(risk_table)
        story.append(PageBreak())
        return story
    
    def create_compliance_mapping(self, risk_assessment: RiskAssessment) -> List:
        """
        Create compliance mapping section
        
        Args:
            risk_assessment: Risk assessment results
            
        Returns:
            List of Platypus flowables
        """
        story = []
        
        # Section header
        story.append(Paragraph("COMPLIANCE MAPPING", self.styles['SectionHeader']))
        
        # Compliance frameworks
        frameworks = ['ISO_27001', 'NIST_CSF', 'OWASP_TOP10']
        framework_names = {
            'ISO_27001': 'ISO/IEC 27001:2013',
            'NIST_CSF': 'NIST Cybersecurity Framework',
            'OWASP_TOP10': 'OWASP Top 10 (2021)'
        }
        
        for framework in frameworks:
            if framework in risk_assessment.compliance_mapping:
                controls = risk_assessment.compliance_mapping[framework]
                if controls:
                    story.append(Paragraph(framework_names[framework], self.styles['SubsectionHeader']))
                    
                    # Create controls table
                    control_data = [['Control ID', 'Description']]
                    
                    # Add control descriptions (simplified)
                    control_descriptions = {
                        'A.9.1.1': 'Access Control Policy',
                        'A.9.1.2': 'Access to Networks and Network Services',
                        'A.10.1.1': 'Policy on the Use of Cryptographic Controls',
                        'A.12.2.1': 'Controls Against Malware',
                        'A.13.1.1': 'Network Controls',
                        'ID.AM-1': 'Physical devices and systems are inventoried',
                        'PR.AC-1': 'Identities and credentials are issued',
                        'PR.DS-1': 'Data-at-rest is protected',
                        'DE.CM-1': 'Networks are monitored',
                        'A01:2021-Broken Access Control': 'Access control enforcement failures',
                        'A02:2021-Cryptographic Failures': 'Cryptographic implementation failures',
                        'A03:2021-Injection': 'Code injection vulnerabilities'
                    }
                    
                    for control in controls[:10]:  # Limit to top 10
                        description = control_descriptions.get(control, 'Security control')
                        control_data.append([control, description])
                    
                    control_table = Table(control_data, colWidths=[2*inch, 4*inch])
                    control_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 10),
                        ('FONTSIZE', (0, 1), (-1, -1), 9),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black)
                    ]))
                    
                    story.append(control_table)
                    story.append(Spacer(1, 0.2*inch))
        
        story.append(PageBreak())
        return story
    
    def create_recommendations(self, risk_assessment: RiskAssessment) -> List:
        """
        Create recommendations section
        
        Args:
            risk_assessment: Risk assessment results
            
        Returns:
            List of Platypus flowables
        """
        story = []
        
        # Section header
        story.append(Paragraph("SECURITY RECOMMENDATIONS", self.styles['SectionHeader']))
        
        # Prioritized recommendations
        story.append(Paragraph("Prioritized Action Items", self.styles['SubsectionHeader']))
        
        for i, recommendation in enumerate(risk_assessment.recommendations, 1):
            priority = "HIGH" if "HIGH PRIORITY" in recommendation else "MEDIUM" if "MEDIUM PRIORITY" in recommendation else "STANDARD"
            
            # Clean up recommendation text
            clean_rec = recommendation.replace("HIGH PRIORITY - ", "").replace("MEDIUM PRIORITY - ", "")
            
            rec_text = f"<b>{i}. [{priority}]</b> {clean_rec}"
            story.append(Paragraph(rec_text, self.styles['Normal']))
            story.append(Spacer(1, 0.1*inch))
        
        # Implementation timeline
        story.append(Spacer(1, 0.3*inch))
        story.append(Paragraph("Recommended Implementation Timeline", self.styles['SubsectionHeader']))
        
        timeline_data = [
            ['Priority', 'Timeframe', 'Actions'],
            ['Immediate (0-7 days)', 'Critical fixes', 'Address critical and high-priority findings'],
            ['Short-term (1-4 weeks)', 'Security improvements', 'Implement medium-priority recommendations'],
            ['Medium-term (1-3 months)', 'Process improvements', 'Enhance monitoring and controls'],
            ['Long-term (3+ months)', 'Strategic initiatives', 'Comprehensive security program updates']
        ]
        
        timeline_table = Table(timeline_data, colWidths=[2*inch, 2*inch, 2.5*inch])
        timeline_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(timeline_table)
        story.append(PageBreak())
        return story
    
    def generate_comprehensive_report(self, 
                                    analysis_results: Dict[str, Any],
                                    risk_assessment: RiskAssessment,
                                    flows: Dict[str, Any],
                                    connections: Dict[str, Any],
                                    threat_matches: List[Any],
                                    nlp_analyses: List[Any],
                                    output_filename: str = "security_analysis_report.pdf") -> str:
        """
        Generate comprehensive PDF report
        
        Args:
            analysis_results: PCAP analysis results
            risk_assessment: Risk assessment results
            flows: Flow analysis data
            connections: Connection data
            threat_matches: Threat detection results
            nlp_analyses: NLP analysis results
            output_filename: Output PDF filename
            
        Returns:
            str: Path to the generated PDF report
        """
        # Check if PDF generation is available
        if not REPORTLAB_AVAILABLE:
            # Fall back to text report
            text_filename = output_filename.replace('.pdf', '.txt')
            logger.warning("ReportLab not available. Generating text report instead.")
            return self.generate_text_report(
                analysis_results, risk_assessment, flows, connections,
                threat_matches, nlp_analyses, text_filename
            )
        
        output_path = os.path.join(self.output_dir, output_filename)
        
        try:
            # Create the PDF document
            doc = SimpleDocTemplate(
                output_path,
                pagesize=A4,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=18
            )
            
            # Build the report content
            story = []
            
            # Cover page
            story.extend(self.create_cover_page())
            
            # Executive summary
            story.extend(self.create_executive_summary(risk_assessment, analysis_results))
            
            # Technical analysis
            story.extend(self.create_technical_analysis(flows, connections, threat_matches, nlp_analyses))
            
            # Risk analysis
            story.extend(self.create_risk_analysis(risk_assessment))
            
            # Compliance mapping
            story.extend(self.create_compliance_mapping(risk_assessment))
            
            # Recommendations
            story.extend(self.create_recommendations(risk_assessment))
            
            # Build the PDF
            doc.build(story)
            
            logger.info(f"Report generated successfully: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            raise
    
    def create_quick_summary(self, risk_assessment: RiskAssessment, 
                           analysis_results: Dict[str, Any]) -> str:
        """
        Create a quick text summary for console output
        
        Args:
            risk_assessment: Risk assessment results
            analysis_results: Analysis results
            
        Returns:
            str: Formatted summary text
        """
        summary = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                           SECURITY ANALYSIS SUMMARY                          ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Overall Risk Level: {risk_assessment.risk_level.name.upper():^20}                           ║
║ Risk Score:         {risk_assessment.overall_score:>6.1f}/100                                   ║
║ Confidence:         {risk_assessment.confidence*100:>6.1f}%                                     ║
║                                                                              ║
║ Analysis Stats:                                                              ║
║ • Total Packets:    {analysis_results.get('packets', 0):>8,}                                    ║
║ • Unique IPs:       {len(analysis_results.get('statistics', {}).get('unique_ips', [])):>8}                                    ║
║ • Network Flows:    {analysis_results.get('flows_count', 0):>8}                                    ║
║ • Conversations:    {analysis_results.get('conversations_count', 0):>8}                                    ║
║                                                                              ║
║ Top Recommendations:                                                         ║
"""
        
        for i, rec in enumerate(risk_assessment.recommendations[:3], 1):
            clean_rec = rec.replace("HIGH PRIORITY - ", "").replace("MEDIUM PRIORITY - ", "")
            # Truncate long recommendations
            if len(clean_rec) > 60:
                clean_rec = clean_rec[:57] + "..."
            summary += f"║ {i}. {clean_rec:<68} ║\n"
        
        summary += "╚══════════════════════════════════════════════════════════════════════════════╝"
        
        return summary
    
    def generate_text_report(self, 
                            analysis_results: Dict[str, Any],
                            risk_assessment: RiskAssessment,
                            flows: Dict[str, Any],
                            connections: Dict[str, Any],
                            threat_matches: List[Any],
                            nlp_analyses: List[Any],
                            output_filename: str = "security_analysis_report.txt") -> str:
        """
        Generate simple text report as fallback when PDF libraries unavailable
        
        Args:
            analysis_results: PCAP analysis results
            risk_assessment: Risk assessment results
            flows: Flow analysis data
            connections: Connection data
            threat_matches: Threat detection results
            nlp_analyses: NLP analysis results
            output_filename: Output text filename
            
        Returns:
            str: Path to the generated text report
        """
        output_path = os.path.join(self.output_dir, output_filename)
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("PCAP SECURITY ANALYSIS REPORT\n")
                f.write("=" * 80 + "\n\n")
                
                # Executive Summary
                f.write("EXECUTIVE SUMMARY\n")
                f.write("-" * 20 + "\n")
                f.write(f"Overall Risk Level: {risk_assessment.risk_level.name}\n")
                f.write(f"Risk Score: {risk_assessment.overall_score:.1f}/100\n")
                f.write(f"Confidence: {risk_assessment.confidence*100:.1f}%\n")
                f.write(f"Total Packets: {analysis_results.get('packets', 0):,}\n")
                f.write(f"Analysis Time: {analysis_results.get('analysis_time', 0):.2f} seconds\n\n")
                
                # Risk Factors
                f.write("RISK FACTORS\n")
                f.write("-" * 15 + "\n")
                for factor in risk_assessment.risk_factors:
                    f.write(f"• {factor.name}: {factor.score:.1f}/100\n")
                    f.write(f"  Description: {factor.description}\n")
                    f.write(f"  Mitigation: {factor.mitigation}\n\n")
                
                # Threat Detection
                if threat_matches:
                    f.write("THREAT DETECTION RESULTS\n")
                    f.write("-" * 25 + "\n")
                    f.write(f"Total threats detected: {len(threat_matches)}\n\n")
                    
                    for i, match in enumerate(threat_matches[:10], 1):
                        f.write(f"{i}. {match.rule_name} ({match.severity.name})\n")
                        f.write(f"   Category: {match.category}\n")
                        f.write(f"   Description: {match.description}\n")
                        f.write(f"   Matched: {match.matched_text[:50]}...\n\n")
                
                # Flow Summary
                if flows:
                    f.write("NETWORK FLOW SUMMARY\n")
                    f.write("-" * 22 + "\n")
                    f.write(f"Total flows: {flows.get('total_flows', 0)}\n")
                    f.write(f"Average duration: {flows.get('avg_duration', 0):.2f} seconds\n")
                    f.write(f"Average packets per flow: {flows.get('avg_packets_per_flow', 0):.1f}\n\n")
                
                # Recommendations
                f.write("SECURITY RECOMMENDATIONS\n")
                f.write("-" * 26 + "\n")
                for i, rec in enumerate(risk_assessment.recommendations[:10], 1):
                    f.write(f"{i}. {rec}\n")
                
                f.write("\n" + "=" * 80 + "\n")
                f.write("Report generated by PCAP Security Analyzer\n")
                f.write("=" * 80 + "\n")
            
            logger.info(f"Text report generated: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Error generating text report: {e}")
            raise


if __name__ == "__main__":
    # Example usage
    print("Report Generator - Professional PDF reports for PCAP analysis")
    generator = ReportGenerator()
    print(f"Output directory: {generator.output_dir}")
    print("Use generate_comprehensive_report() to create full reports")
