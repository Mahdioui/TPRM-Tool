"""
Professional PCAP Analyzer Web Interface
Clean, aesthetic dashboard for comprehensive network security analysis
"""

import os
import sys
import json
import time
import threading
import base64
import io
from datetime import datetime
from flask import Flask, request, jsonify, Response
from werkzeug.utils import secure_filename

# Chart generation
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
# Handle seaborn import with fallback
try:
    import seaborn as sns
    SEABORN_AVAILABLE = True
except ImportError:
    SEABORN_AVAILABLE = False
    print("WARNING: seaborn not available. Using default matplotlib styles.")
import numpy as np
from collections import Counter, defaultdict

# Add src to path
sys.path.insert(0, 'src')

try:
    from src.analyzer import PcapAnalyzer
    from src.extractor import ConnectionExtractor
    from src.regex_utils import RegexThreatDetector
    from src.risk_calculator import RiskCalculator
    from src.enhanced_report_generator import EnhancedReportGenerator
    from src.nlp_utils import PayloadNLPAnalyzer
except ImportError:
    from analyzer import PcapAnalyzer
    from extractor import ConnectionExtractor
    from regex_utils import RegexThreatDetector
    from risk_calculator import RiskCalculator
    from enhanced_report_generator import EnhancedReportGenerator
    from nlp_utils import PayloadNLPAnalyzer

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['OUTPUT_FOLDER'] = 'output'

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['OUTPUT_FOLDER'], exist_ok=True)

# Set style for charts
if SEABORN_AVAILABLE:
    try:
        plt.style.use('seaborn-v0_8')
        sns.set_palette("viridis")
    except:
        try:
            plt.style.use('seaborn')
            sns.set_palette("viridis")
        except:
            plt.style.use('default')
else:
    plt.style.use('default')

# Global analysis state
analysis_state = {
    'status': 'idle',
    'progress': 0,
    'results': None,
    'error': None,
    'charts': {},
    'detailed_stats': {}
}

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'pcap', 'pcapng', 'cap'}

def create_chart_base64(chart_func, *args, **kwargs):
    """Create a chart and return as base64 string"""
    try:
        fig, ax = plt.subplots(figsize=(10, 6))
        chart_func(ax, *args, **kwargs)
        
        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', dpi=300, bbox_inches='tight', 
                   facecolor='white', edgecolor='none')
        buffer.seek(0)
        chart_data = base64.b64encode(buffer.getvalue()).decode()
        plt.close(fig)
        
        return f"data:image/png;base64,{chart_data}"
    except Exception as e:
        print(f"Chart creation error: {e}")
        return None

def create_protocol_distribution_chart(ax, protocols):
    """Create protocol distribution pie chart"""
    if not protocols:
        ax.text(0.5, 0.5, 'No data available', ha='center', va='center')
        return
    
    labels = list(protocols.keys())[:8]  # Top 8
    sizes = list(protocols.values())[:8]
    
    # Use seaborn colors if available, otherwise use matplotlib default
    if SEABORN_AVAILABLE:
        colors = sns.color_palette("Set3", len(labels))
    else:
        colors = plt.cm.Set3(np.linspace(0, 1, len(labels)))
    
    wedges, texts, autotexts = ax.pie(sizes, labels=labels, autopct='%1.1f%%', 
                                     colors=colors, startangle=90)
    ax.set_title('Protocol Distribution', fontsize=14, fontweight='bold', pad=20)

def create_traffic_timeline_chart(ax, packets_by_time):
    """Create traffic timeline chart"""
    if not packets_by_time:
        ax.text(0.5, 0.5, 'No data available', ha='center', va='center')
        return
    
    times = sorted(packets_by_time.keys())
    counts = [packets_by_time[t] for t in times]
    
    ax.plot(range(len(times)), counts, linewidth=3, marker='o', markersize=6, 
           color='#2E86AB', markerfacecolor='#A23B72')
    ax.set_title('Traffic Timeline', fontsize=14, fontweight='bold', pad=20)
    ax.set_xlabel('Time Period')
    ax.set_ylabel('Packet Count')
    ax.grid(True, alpha=0.3)
    ax.set_xticks(range(0, len(times), max(1, len(times)//8)))
    ax.set_xticklabels([times[i] for i in range(0, len(times), max(1, len(times)//8))], rotation=45)

def create_top_talkers_chart(ax, top_talkers):
    """Create top talkers bar chart"""
    if not top_talkers:
        ax.text(0.5, 0.5, 'No data available', ha='center', va='center')
        return
    
    hosts = list(top_talkers.keys())[:8]
    packets = list(top_talkers.values())[:8]
    
    # Use seaborn colors if available, otherwise use matplotlib default
    if SEABORN_AVAILABLE:
        colors = sns.color_palette("plasma", len(hosts))
    else:
        colors = plt.cm.plasma(np.linspace(0, 1, len(hosts)))
    
    bars = ax.barh(hosts, packets, color=colors)
    ax.set_title('Top Network Hosts', fontsize=14, fontweight='bold', pad=20)
    ax.set_xlabel('Packet Count')
    
    # Add value labels on bars
    for bar in bars:
        width = bar.get_width()
        ax.text(width + max(packets)*0.01, bar.get_y() + bar.get_height()/2, 
               f'{int(width)}', ha='left', va='center', fontweight='bold')

def create_risk_breakdown_chart(ax, risk_components):
    """Create risk score breakdown chart"""
    if not risk_components:
        ax.text(0.5, 0.5, 'No data available', ha='center', va='center')
        return
    
    components = list(risk_components.keys())
    scores = list(risk_components.values())
    colors = ['#E63946' if s > 70 else '#F77F00' if s > 40 else '#06FFA5' for s in scores]
    
    bars = ax.bar(components, scores, color=colors, alpha=0.8)
    ax.set_title('Risk Assessment Breakdown', fontsize=14, fontweight='bold', pad=20)
    ax.set_ylabel('Risk Score (0-100)')
    ax.set_ylim(0, 100)
    
    # Add value labels on bars
    for bar in bars:
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height + 2,
               f'{height:.1f}', ha='center', va='bottom', fontweight='bold')
    
    # Rotate x-axis labels
    plt.setp(ax.xaxis.get_majorticklabels(), rotation=45, ha='right')

def analyze_traffic_patterns(packets):
    """Analyze traffic patterns for charts"""
    protocols = Counter()
    top_talkers = Counter()
    packets_by_time = defaultdict(int)
    port_usage = Counter()
    
    for packet in packets:
        # Protocol distribution
        protocols[packet.protocol] += 1
        
        # Top talkers
        top_talkers[packet.src_ip] += 1
        top_talkers[packet.dst_ip] += 1
        
        # Timeline (group by minute) - Fixed timestamp handling
        if packet.timestamp:
            try:
                # Handle both datetime objects and float timestamps
                if isinstance(packet.timestamp, float):
                    timestamp = datetime.fromtimestamp(packet.timestamp)
                    time_key = timestamp.strftime('%H:%M')
                else:
                    time_key = packet.timestamp.strftime('%H:%M')
                packets_by_time[time_key] += 1
            except (AttributeError, ValueError, OSError):
                # If timestamp parsing fails, use a default grouping
                packets_by_time['Unknown'] += 1
        
        # Port usage
        if packet.src_port:
            port_usage[packet.src_port] += 1
        if packet.dst_port:
            port_usage[packet.dst_port] += 1
    
    return {
        'protocols': dict(protocols),
        'top_talkers': dict(top_talkers),
        'packets_by_time': dict(packets_by_time),
        'port_usage': dict(port_usage)
    }

def run_analysis(pcap_file):
    """Run comprehensive analysis in background"""
    global analysis_state
    
    try:
        analysis_state['status'] = 'running'
        analysis_state['progress'] = 5
        
        # PCAP Analysis
        analyzer = PcapAnalyzer(pcap_file)
        results = analyzer.analyze_pcap(max_packets=2000)
        
        if "error" in results:
            raise Exception(results['error'])
        
        analysis_state['progress'] = 20
        
        # Connection Analysis
        extractor = ConnectionExtractor(analyzer.packets)
        extraction_results = extractor.run_full_analysis()
        
        analysis_state['progress'] = 35
        
        # Traffic Pattern Analysis
        traffic_patterns = analyze_traffic_patterns(analyzer.packets)
        
        analysis_state['progress'] = 45
        
        # Threat Detection
        detector = RegexThreatDetector()
        threats = []
        for packet in analyzer.packets[:500]:
            if packet.payload:
                matches = detector.scan_payload(packet.payload)
                threats.extend(matches)
        
        analysis_state['progress'] = 55
        
        # NLP Analysis
        nlp_analyzer = PayloadNLPAnalyzer()
        nlp_analyses = []
        for packet in analyzer.packets[:100]:
            if packet.payload and len(packet.payload) > 10:
                nlp_result = nlp_analyzer.analyze_payload(packet.payload)
                if nlp_result:
                    nlp_analyses.append(nlp_result)
        
        analysis_state['progress'] = 70
        
        # Risk Assessment
        risk_calc = RiskCalculator()
        risk_assessment = risk_calc.calculate_comprehensive_risk(
            flows=extraction_results.get('flows', {}),
            connections=extraction_results.get('connections', {}),
            threat_matches=threats,
            nlp_analyses=nlp_analyses
        )
        
        analysis_state['progress'] = 80
        
        # Create Charts
        charts = {}
        
        charts['protocol_dist'] = create_chart_base64(
            create_protocol_distribution_chart, 
            traffic_patterns['protocols']
        )
        
        charts['traffic_timeline'] = create_chart_base64(
            create_traffic_timeline_chart,
            traffic_patterns['packets_by_time']
        )
        
        charts['top_talkers'] = create_chart_base64(
            create_top_talkers_chart,
            traffic_patterns['top_talkers']
        )
        
        # Get risk component scores - handle both detailed_scores and category_scores
        category_scores = getattr(risk_assessment, 'category_scores', {})
        detailed_scores = getattr(risk_assessment, 'detailed_scores', category_scores)
        
        risk_components = {
            'Protocol Risk': detailed_scores.get('protocol_risk', category_scores.get('Protocol Analysis', 0)),
            'Port Risk': detailed_scores.get('port_usage_risk', category_scores.get('Port Usage', 0)),
            'Connection Risk': detailed_scores.get('connection_anomaly_risk', category_scores.get('Connection Analysis', 0)),
            'Threat Risk': detailed_scores.get('threat_detection_risk', category_scores.get('Threat Detection', 0)),
            'Content Risk': detailed_scores.get('nlp_analysis_risk', category_scores.get('Content Analysis', 0))
        }
        
        charts['risk_breakdown'] = create_chart_base64(
            create_risk_breakdown_chart,
            risk_components
        )
        
        analysis_state['progress'] = 90
        
        # Generate Professional PDF Report
        report_gen = EnhancedReportGenerator(app.config['OUTPUT_FOLDER'])
        pdf_filename = f"security_assessment_{int(time.time())}.pdf"
        
        try:
            pdf_report_path = report_gen.generate_comprehensive_professional_report(
                analysis_results=results,
                risk_assessment=risk_assessment,
                flows=extractor.get_flow_summary(),
                connections=extractor.get_connection_summary(),
                threat_matches=threats,
                nlp_analyses=nlp_analyses,
                output_filename=pdf_filename
            )
        except Exception as pdf_error:
            print(f"PDF generation error: {pdf_error}")
            # Fallback to text report
            pdf_filename = f"security_assessment_{int(time.time())}.txt"
            pdf_report_path = report_gen.generate_enhanced_text_report(
                analysis_results=results,
                risk_assessment=risk_assessment,
                flows=extractor.get_flow_summary(),
                connections=extractor.get_connection_summary(),
                threat_matches=threats,
                nlp_analyses=nlp_analyses,
                output_filename=pdf_filename
            )
        
        analysis_state['progress'] = 100
        analysis_state['status'] = 'completed'
        analysis_state['charts'] = charts
        
        # Detailed statistics - Fixed connection duration calculation
        connection_durations = []
        for stats in extraction_results.get('connections', {}).values():
            if hasattr(stats, 'connection_duration') and stats.connection_duration is not None:
                try:
                    duration = float(stats.connection_duration)
                    if not np.isnan(duration) and duration >= 0:
                        connection_durations.append(duration)
                except (TypeError, ValueError):
                    continue
        
        detailed_stats = {
            'total_packets': len(analyzer.packets),
            'unique_ips': len(set([p.src_ip for p in analyzer.packets] + [p.dst_ip for p in analyzer.packets])),
            'protocols_count': len(traffic_patterns['protocols']),
            'suspicious_flows': len([f for f in extraction_results.get('flows', {}).values() if hasattr(f, 'risk_score') and f.risk_score > 50]),
            'threat_categories': len(set([t.category for t in threats])),
            'nlp_keywords': len(set([kw for analysis in nlp_analyses for kw in (analysis.suspicious_keywords if hasattr(analysis, 'suspicious_keywords') else [])])),
            'connection_duration_avg': np.mean(connection_durations) if connection_durations else 0,
            'data_volume_mb': sum([len(p.payload or b'') for p in analyzer.packets]) / (1024 * 1024)
        }
        
        analysis_state['detailed_stats'] = detailed_stats
        analysis_state['results'] = {
            'packets': results['packets'],
            'risk_level': risk_assessment.risk_level.name,
            'risk_score': risk_assessment.overall_score,
            'threats_count': len(threats),
            'flows_count': len(extraction_results.get('flows', {})),
            'connections_count': len(extraction_results.get('connections', {})),
            'report_filename': pdf_filename,
            'top_threats': [t.description for t in threats[:10]],
            'threat_types': list(set([t.category for t in threats])),
            'recommendations': risk_assessment.recommendations[:10],
            'risk_components': risk_components,
            'traffic_patterns': traffic_patterns,
            'detailed_stats': detailed_stats,
            'compliance_mapping': getattr(risk_assessment, 'compliance_mapping', {})
        }
        
    except Exception as e:
        analysis_state['status'] = 'error'
        analysis_state['error'] = str(e)
        print(f"Analysis error: {e}")

@app.route('/')
def index():
    """Serve the professional dashboard page"""
    html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PCAP Security Analyzer - Professional Dashboard</title>
    <style>
        :root {
            --primary-color: #2E86AB;
            --secondary-color: #A23B72;
            --accent-color: #F18F01;
            --success-color: #06FFA5;
            --warning-color: #FFB700;
            --danger-color: #E63946;
            --dark-color: #1B263B;
            --light-color: #F5F9FC;
            --border-radius: 12px;
            --box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        * { 
            margin: 0; 
            padding: 0; 
            box-sizing: border-box; 
        }
        
        body { 
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: var(--dark-color);
            line-height: 1.6;
        }
        
        .container { 
            max-width: 1400px; 
            margin: 0 auto; 
            padding: 24px; 
        }
        
        .header { 
            background: rgba(255,255,255,0.95); 
            padding: 32px; 
            border-radius: var(--border-radius); 
            text-align: center; 
            margin-bottom: 32px;
            box-shadow: var(--box-shadow);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255,255,255,0.2);
        }
        
        .header h1 { 
            font-size: 2.75rem; 
            margin-bottom: 12px; 
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            font-weight: 700;
            letter-spacing: -0.02em;
        }
        
        .header p { 
            font-size: 1.125rem; 
            opacity: 0.8; 
            font-weight: 400;
        }
        
        .dashboard-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); 
            gap: 24px; 
            margin-bottom: 32px; 
        }
        
        .kpi-card { 
            background: rgba(255,255,255,0.95); 
            padding: 32px; 
            border-radius: var(--border-radius); 
            text-align: center;
            box-shadow: var(--box-shadow);
            backdrop-filter: blur(20px);
            transition: var(--transition);
            border: 1px solid rgba(255,255,255,0.2);
            position: relative;
            overflow: hidden;
        }
        
        .kpi-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--primary-color), var(--secondary-color));
        }
        
        .kpi-card:hover { 
            transform: translateY(-8px); 
            box-shadow: 0 8px 40px rgba(0,0,0,0.15);
        }
        
        .kpi-value { 
            font-size: 2.5rem; 
            font-weight: 700; 
            margin-bottom: 8px;
            color: var(--dark-color);
            transition: var(--transition);
        }
        
        .kpi-label { 
            font-size: 0.875rem; 
            color: #64748B; 
            text-transform: uppercase;
            letter-spacing: 0.05em;
            font-weight: 600;
        }
        
        .card { 
            background: rgba(255,255,255,0.95); 
            padding: 32px; 
            border-radius: var(--border-radius); 
            box-shadow: var(--box-shadow);
            backdrop-filter: blur(20px);
            margin-bottom: 32px;
            border: 1px solid rgba(255,255,255,0.2);
        }
        
        .upload-area { 
            border: 2px dashed var(--primary-color); 
            padding: 48px; 
            text-align: center; 
            border-radius: var(--border-radius); 
            background: rgba(46, 134, 171, 0.05);
            transition: var(--transition);
            cursor: pointer;
        }
        
        .upload-area:hover,
        .upload-area.dragover { 
            border-color: var(--secondary-color); 
            background: rgba(162, 59, 114, 0.1);
            transform: scale(1.02);
        }
        
        .upload-area h3 {
            font-size: 1.5rem;
            margin-bottom: 16px;
            color: var(--dark-color);
            font-weight: 600;
        }
        
        .upload-area p {
            color: #64748B;
            margin-bottom: 8px;
        }
        
        .btn { 
            background: linear-gradient(135deg, var(--primary-color), var(--secondary-color));
            color: white; 
            padding: 16px 32px; 
            border: none; 
            border-radius: var(--border-radius); 
            cursor: pointer; 
            font-size: 1rem;
            font-weight: 600;
            transition: var(--transition);
            box-shadow: 0 4px 15px rgba(46, 134, 171, 0.3);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        .btn:hover { 
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(46, 134, 171, 0.4);
        }
        
        .btn:disabled { 
            background: #CBD5E1; 
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }
        
        .progress { 
            width: 100%; 
            height: 8px; 
            background: #E2E8F0; 
            border-radius: 4px; 
            overflow: hidden; 
            margin: 20px 0;
        }
        
        .progress-bar { 
            height: 100%; 
            background: linear-gradient(90deg, var(--primary-color), var(--secondary-color));
            transition: width 0.5s ease;
            border-radius: 4px;
        }
        
        .charts-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(500px, 1fr)); 
            gap: 32px; 
            margin: 32px 0; 
        }
        
        .chart-container { 
            background: rgba(255,255,255,0.95); 
            padding: 24px; 
            border-radius: var(--border-radius);
            box-shadow: var(--box-shadow);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255,255,255,0.2);
        }
        
        .chart-container h3 {
            margin-bottom: 20px;
            color: var(--dark-color);
            font-weight: 600;
            font-size: 1.125rem;
        }
        
        .chart-container img { 
            width: 100%; 
            height: auto; 
            border-radius: 8px; 
            transition: opacity 0.5s ease;
        }
        
        .risk-critical { color: var(--danger-color); }
        .risk-high { color: var(--warning-color); }
        .risk-medium { color: var(--accent-color); }
        .risk-low { color: var(--success-color); }
        
        .status { 
            margin: 20px 0; 
            padding: 16px; 
            border-radius: var(--border-radius); 
            font-weight: 600;
        }
        
        .status.success { background: rgba(6, 255, 165, 0.1); color: var(--success-color); }
        .status.error { background: rgba(230, 57, 70, 0.1); color: var(--danger-color); }
        .status.info { background: rgba(46, 134, 171, 0.1); color: var(--primary-color); }
        
        input[type="file"] { display: none; }
        
        .file-info { 
            margin: 20px 0; 
            font-size: 0.875rem; 
            color: #64748B;
            padding: 12px;
            background: rgba(0,0,0,0.05);
            border-radius: 8px;
        }
        
        .details-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 24px; 
            margin: 32px 0; 
        }
        
        .detail-item { 
            background: rgba(248, 250, 252, 0.8); 
            padding: 20px; 
            border-radius: var(--border-radius); 
            text-align: center;
            border: 1px solid rgba(226, 232, 240, 0.8);
        }
        
        .detail-value { 
            font-size: 1.875rem; 
            font-weight: 700; 
            color: var(--dark-color); 
            margin-bottom: 4px;
        }
        
        .detail-label { 
            font-size: 0.75rem; 
            color: #64748B; 
            text-transform: uppercase;
            letter-spacing: 0.05em;
            font-weight: 600;
        }
        
        .section-header {
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--dark-color);
            margin-bottom: 16px;
            padding-bottom: 8px;
            border-bottom: 2px solid #E2E8F0;
        }
        
        .recommendations { 
            background: rgba(6, 255, 165, 0.1); 
            padding: 24px; 
            border-radius: var(--border-radius); 
            margin: 24px 0;
            border-left: 4px solid var(--success-color);
        }
        
        .recommendations h4 { 
            color: var(--success-color); 
            margin-bottom: 16px;
            font-weight: 600;
        }
        
        .threats { 
            background: rgba(230, 57, 70, 0.1); 
            padding: 24px; 
            border-radius: var(--border-radius); 
            margin: 24px 0;
            border-left: 4px solid var(--danger-color);
        }
        
        .threats h4 { 
            color: var(--danger-color); 
            margin-bottom: 16px;
            font-weight: 600;
        }
        
        .hidden { display: none; }
        
        @media (max-width: 768px) {
            .container { padding: 16px; }
            .header h1 { font-size: 2rem; }
            .charts-grid { grid-template-columns: 1fr; }
            .kpi-card { padding: 24px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>PCAP Security Analyzer</h1>
            <p>Professional Network Security Analysis & Risk Assessment</p>
        </div>

        <!-- KPI Dashboard -->
        <div class="dashboard-grid" id="kpiDashboard" style="display: none;">
            <div class="kpi-card">
                <div class="kpi-value" id="kpiRiskScore">-</div>
                <div class="kpi-label">Risk Score</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-value" id="kpiThreats">-</div>
                <div class="kpi-label">Threats Detected</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-value" id="kpiPackets">-</div>
                <div class="kpi-label">Packets Analyzed</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-value" id="kpiConnections">-</div>
                <div class="kpi-label">Network Connections</div>
            </div>
        </div>

        <!-- Upload Section -->
        <div class="card" id="uploadCard">
            <h2 class="section-header">Upload Network Capture File</h2>
            <div class="upload-area" id="uploadArea">
                <h3>Select PCAP File for Analysis</h3>
                <p>Drag and drop your network capture file or click to browse</p>
                <p>Supported formats: .pcap, .pcapng, .cap (Maximum size: 100MB)</p>
                <input type="file" id="fileInput" accept=".pcap,.pcapng,.cap">
                <div class="file-info" id="fileInfo"></div>
                <button class="btn" id="uploadBtn" disabled>Start Security Analysis</button>
            </div>
        </div>

        <!-- Progress Section -->
        <div class="card" id="progressCard" style="display: none;">
            <h3 class="section-header">Analysis in Progress</h3>
            <div class="progress">
                <div class="progress-bar" id="progressBar"></div>
            </div>
            <div id="statusText" class="status info">Initializing security analysis...</div>
        </div>

        <!-- Charts Section -->
        <div class="charts-grid" id="chartsSection" style="display: none;">
            <div class="chart-container">
                <h3>Protocol Distribution</h3>
                <img id="protocolChart" src="" alt="Protocol Distribution Analysis">
            </div>
            <div class="chart-container">
                <h3>Traffic Timeline</h3>
                <img id="timelineChart" src="" alt="Network Traffic Timeline">
            </div>
            <div class="chart-container">
                <h3>Top Network Hosts</h3>
                <img id="talkersChart" src="" alt="Most Active Network Hosts">
            </div>
            <div class="chart-container">
                <h3>Risk Assessment Breakdown</h3>
                <img id="riskChart" src="" alt="Security Risk Component Analysis">
            </div>
        </div>

        <!-- Detailed Results -->
        <div class="card" id="resultsCard" style="display: none;">
            <h3 class="section-header">Analysis Results</h3>
            
            <div class="details-grid">
                <div class="detail-item">
                    <div class="detail-value" id="detailIPs">-</div>
                    <div class="detail-label">Unique IP Addresses</div>
                </div>
                <div class="detail-item">
                    <div class="detail-value" id="detailProtocols">-</div>
                    <div class="detail-label">Network Protocols</div>
                </div>
                <div class="detail-item">
                    <div class="detail-value" id="detailDataVolume">-</div>
                    <div class="detail-label">Data Volume (MB)</div>
                </div>
                <div class="detail-item">
                    <div class="detail-value" id="detailSuspiciousFlows">-</div>
                    <div class="detail-label">Suspicious Flows</div>
                </div>
                <div class="detail-item">
                    <div class="detail-value" id="detailThreatCategories">-</div>
                    <div class="detail-label">Threat Categories</div>
                </div>
                <div class="detail-item">
                    <div class="detail-value" id="detailAvgDuration">-</div>
                    <div class="detail-label">Avg Connection (s)</div>
                </div>
            </div>

            <div class="threats" id="threatsList"></div>
            <div class="recommendations" id="recommendationsList"></div>
            
            <div style="text-align: center; margin-top: 32px;">
                <button class="btn" id="downloadBtn">Download Security Report</button>
            </div>
        </div>
    </div>

    <script>
        const fileInput = document.getElementById('fileInput');
        const uploadArea = document.getElementById('uploadArea');
        const uploadBtn = document.getElementById('uploadBtn');
        const progressCard = document.getElementById('progressCard');
        const resultsCard = document.getElementById('resultsCard');
        const kpiDashboard = document.getElementById('kpiDashboard');
        const chartsSection = document.getElementById('chartsSection');
        let currentFile = null;

        // Upload area events
        uploadArea.addEventListener('click', () => fileInput.click());
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('dragover');
        });
        uploadArea.addEventListener('dragleave', () => {
            uploadArea.classList.remove('dragover');
        });
        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                handleFile(files[0]);
            }
        });

        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                handleFile(e.target.files[0]);
            }
        });

        function handleFile(file) {
            const allowedTypes = ['.pcap', '.pcapng', '.cap'];
            const fileExt = '.' + file.name.split('.').pop().toLowerCase();
            
            if (!allowedTypes.includes(fileExt)) {
                alert('Please select a valid PCAP file (.pcap, .pcapng, .cap)');
                return;
            }
            
            if (file.size > 100 * 1024 * 1024) {
                alert('File too large. Maximum size is 100MB.');
                return;
            }
            
            currentFile = file;
            document.getElementById('fileInfo').innerHTML = 
                `Selected: <strong>${file.name}</strong> (${(file.size/1024/1024).toFixed(2)} MB)`;
            uploadBtn.disabled = false;
        }

        uploadBtn.addEventListener('click', uploadFile);

        function uploadFile() {
            if (!currentFile) return;
            
            const formData = new FormData();
            formData.append('file', currentFile);
            
            uploadBtn.disabled = true;
            progressCard.style.display = 'block';
            resultsCard.style.display = 'none';
            kpiDashboard.style.display = 'none';
            chartsSection.style.display = 'none';
            
            fetch('/upload', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    checkProgress();
                } else {
                    showError(data.error || 'Upload failed');
                }
            })
            .catch(error => {
                showError('Upload error: ' + error.message);
            });
        }

        function checkProgress() {
            fetch('/progress')
            .then(response => response.json())
            .then(data => {
                updateProgress(data);
                
                if (data.status === 'completed') {
                    showResults();
                } else if (data.status === 'error') {
                    showError(data.error || 'Analysis failed');
                } else {
                    setTimeout(checkProgress, 1000);
                }
            })
            .catch(error => {
                console.error('Progress check error:', error);
                setTimeout(checkProgress, 2000);
            });
        }

        function updateProgress(data) {
            const progressBar = document.getElementById('progressBar');
            const statusText = document.getElementById('statusText');
            
            progressBar.style.width = data.progress + '%';
            statusText.textContent = `Progress: ${data.progress}% - Analyzing network security...`;
            statusText.className = 'status info';
        }

        function showResults() {
            fetch('/results')
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    displayResults(data.results);
                    progressCard.style.display = 'none';
                    kpiDashboard.style.display = 'grid';
                    chartsSection.style.display = 'grid';
                    resultsCard.style.display = 'block';
                    loadCharts();
                } else {
                    showError(data.error || 'Failed to load results');
                }
            });
        }

        function displayResults(results) {
            // Animate KPIs
            animateCounter('kpiRiskScore', 0, results.risk_score, 2000, 1);
            animateCounter('kpiThreats', 0, results.threats_count, 1500, 0);
            animateCounter('kpiPackets', 0, results.packets, 2500, 0);
            animateCounter('kpiConnections', 0, results.connections_count, 1800, 0);
            
            // Color code risk score
            const riskElement = document.getElementById('kpiRiskScore');
            if (results.risk_score > 70) riskElement.className = 'kpi-value risk-critical';
            else if (results.risk_score > 40) riskElement.className = 'kpi-value risk-high';
            else riskElement.className = 'kpi-value risk-low';
            
            // Update detailed stats
            const stats = results.detailed_stats;
            document.getElementById('detailIPs').textContent = stats.unique_ips;
            document.getElementById('detailProtocols').textContent = stats.protocols_count;
            document.getElementById('detailDataVolume').textContent = stats.data_volume_mb.toFixed(2);
            document.getElementById('detailSuspiciousFlows').textContent = stats.suspicious_flows;
            document.getElementById('detailThreatCategories').textContent = stats.threat_categories;
            document.getElementById('detailAvgDuration').textContent = stats.connection_duration_avg.toFixed(2);
            
            // Show threats
            const threatsList = document.getElementById('threatsList');
            if (results.top_threats && results.top_threats.length > 0) {
                threatsList.innerHTML = '<h4>Security Threats Detected</h4><ul>' + 
                    results.top_threats.map(threat => `<li>${threat}</li>`).join('') + '</ul>';
            }
            
            // Show recommendations
            const recsList = document.getElementById('recommendationsList');
            if (results.recommendations && results.recommendations.length > 0) {
                recsList.innerHTML = '<h4>Security Recommendations</h4><ul>' + 
                    results.recommendations.map(rec => `<li>${rec}</li>`).join('') + '</ul>';
            }
            
            // Set up download
            document.getElementById('downloadBtn').onclick = () => {
                window.location.href = '/download_report';
            };
        }

        function animateCounter(elementId, start, end, duration, decimals = 0) {
            const element = document.getElementById(elementId);
            const range = end - start;
            const increment = range / (duration / 16);
            let current = start;
            
            const timer = setInterval(() => {
                current += increment;
                if (current >= end) {
                    current = end;
                    clearInterval(timer);
                }
                
                if (decimals > 0) {
                    element.textContent = current.toFixed(decimals);
                } else {
                    element.textContent = Math.floor(current).toLocaleString();
                }
            }, 16);
        }

        function loadCharts() {
            fetch('/charts')
            .then(response => response.json())
            .then(data => {
                if (data.success && data.charts) {
                    const charts = [
                        {id: 'protocolChart', src: data.charts.protocol_dist},
                        {id: 'timelineChart', src: data.charts.traffic_timeline},
                        {id: 'talkersChart', src: data.charts.top_talkers},
                        {id: 'riskChart', src: data.charts.risk_breakdown}
                    ];
                    
                    charts.forEach((chart, index) => {
                        if (chart.src) {
                            setTimeout(() => {
                                const img = document.getElementById(chart.id);
                                img.style.opacity = '0';
                                img.src = chart.src;
                                img.onload = () => {
                                    img.style.opacity = '1';
                                };
                            }, index * 200);
                        }
                    });
                }
            })
            .catch(error => console.error('Chart loading error:', error));
        }

        function showError(message) {
            progressCard.style.display = 'none';
            uploadBtn.disabled = false;
            alert('Error: ' + message);
        }
    </script>
</body>
</html>
    """
    return html

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload"""
    global analysis_state
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type'}), 400
    
    try:
        filename = secure_filename(file.filename)
        timestamp = int(time.time())
        filename = f"{timestamp}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Reset analysis state
        analysis_state = {
            'status': 'starting', 
            'progress': 0, 
            'results': None, 
            'error': None,
            'charts': {},
            'detailed_stats': {}
        }
        
        # Start analysis in background
        thread = threading.Thread(target=run_analysis, args=(filepath,))
        thread.daemon = True
        thread.start()
        
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/progress')
def get_progress():
    """Get analysis progress"""
    return jsonify(analysis_state)

@app.route('/results')
def get_results():
    """Get analysis results"""
    if analysis_state['status'] == 'completed' and analysis_state['results']:
        return jsonify({'success': True, 'results': analysis_state['results']})
    elif analysis_state['status'] == 'error':
        return jsonify({'success': False, 'error': analysis_state['error']})
    else:
        return jsonify({'success': False, 'message': 'Analysis not completed'})

@app.route('/charts')
def get_charts():
    """Get analysis charts"""
    if analysis_state['status'] == 'completed' and analysis_state['charts']:
        return jsonify({'success': True, 'charts': analysis_state['charts']})
    else:
        return jsonify({'success': False, 'message': 'Charts not available'})

@app.route('/download_report')
def download_report():
    """Download the generated report"""
    if analysis_state['status'] == 'completed' and 'report_filename' in analysis_state['results']:
        filename = analysis_state['results']['report_filename']
        filepath = os.path.join(app.config['OUTPUT_FOLDER'], filename)
        
        if os.path.exists(filepath):
            with open(filepath, 'rb') as f:
                content = f.read()
            
            # Determine content type
            content_type = 'application/pdf' if filename.endswith('.pdf') else 'text/plain'
            
            return Response(
                content,
                mimetype=content_type,
                headers={'Content-Disposition': f'attachment; filename={filename}'}
            )
    
    return jsonify({'error': 'Report not available'}), 404

if __name__ == '__main__':
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                      PCAP Analyzer - Professional Edition                   ║
║                        Network Security Analysis Dashboard                   ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Access URL: http://localhost:5000                                           ║
║ Features: Interactive Analytics | Professional Reports | Risk Assessment    ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    app.run(host='0.0.0.0', port=5000, debug=False)
