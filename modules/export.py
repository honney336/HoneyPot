#!/usr/bin/env python3
"""
Export Module for Honeypot
Handles export to XML/XSLT and JSON formats.
"""

import datetime
import json
import xml.etree.ElementTree as ET


# XSLT Stylesheet Content
XSLT_CONTENT = '''<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
<html>
<head>
    <title>Honey POT Security Audit Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #1a1a2e; color: #eee; padding: 20px; }
        h1 { color: #ffd700; border-bottom: 2px solid #ffd700; padding-bottom: 10px; }
        h2 { color: #00d4ff; margin-top: 30px; }
        .summary { display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin: 20px 0; }
        .summary-card { background: #16213e; padding: 20px; border-radius: 10px; text-align: center; border-left: 4px solid #00d4ff; }
        .summary-card.critical { border-left-color: #ff4757; }
        .summary-card.warning { border-left-color: #ffa502; }
        .summary-card h3 { margin: 0 0 10px 0; font-size: 14px; color: #888; }
        .summary-card .value { font-size: 28px; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th { background: #0f3460; color: #ffd700; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #333; }
        tr:hover { background: #1f4068; }
        .critical { color: #ff4757; font-weight: bold; }
        .warning { color: #ffa502; }
        .info { color: #2ed573; }
        .sudo { background: rgba(255, 71, 87, 0.2); }
        .header-info { color: #888; font-size: 12px; }
    </style>
</head>
<body>
    <h1>🍯 Honey POT Security Audit Report</h1>
    <p class="header-info">Generated: <xsl:value-of select="/HoneypotReport/@generated"/> | Hostname: <xsl:value-of select="/HoneypotReport/@hostname"/></p>
    
    <div class="summary">
        <div class="summary-card">
            <h3>Total Events</h3>
            <div class="value"><xsl:value-of select="/HoneypotReport/Summary/TotalEvents"/></div>
        </div>
        <div class="summary-card">
            <h3>Credentials Captured</h3>
            <div class="value"><xsl:value-of select="/HoneypotReport/Summary/TotalCredentials"/></div>
        </div>
        <div class="summary-card critical">
            <h3>Critical Events</h3>
            <div class="value critical"><xsl:value-of select="/HoneypotReport/Summary/CriticalEvents"/></div>
        </div>
        <div class="summary-card warning">
            <h3>Warnings</h3>
            <div class="value warning"><xsl:value-of select="/HoneypotReport/Summary/WarningEvents"/></div>
        </div>
        <div class="summary-card">
            <h3>Active Sessions</h3>
            <div class="value"><xsl:value-of select="/HoneypotReport/Summary/ActiveSessions"/></div>
        </div>
    </div>
    
    <h2>🔐 Captured Credentials</h2>
    <table>
        <tr><th>Timestamp</th><th>Source IP</th><th>Port</th><th>Service</th><th>Username</th><th>Password</th><th>Type</th></tr>
        <xsl:for-each select="/HoneypotReport/CapturedCredentials/Credential">
        <tr>
            <xsl:if test="Type='sudo'"><xsl:attribute name="class">sudo</xsl:attribute></xsl:if>
            <td><xsl:value-of select="Timestamp"/></td>
            <td><xsl:value-of select="SourceIP"/></td>
            <td><xsl:value-of select="SourcePort"/></td>
            <td><xsl:value-of select="Service"/></td>
            <td><xsl:value-of select="Username"/></td>
            <td><xsl:value-of select="Password"/></td>
            <td>
                <xsl:if test="Type='sudo'"><xsl:attribute name="class">critical</xsl:attribute></xsl:if>
                <xsl:value-of select="Type"/>
            </td>
        </tr>
        </xsl:for-each>
    </table>
    
    <h2>📋 Event Log</h2>
    <table>
        <tr><th>Timestamp</th><th>Level</th><th>Service</th><th>Source IP</th><th>Message</th></tr>
        <xsl:for-each select="/HoneypotReport/Events/Event">
        <tr>
            <td><xsl:value-of select="Timestamp"/></td>
            <td>
                <xsl:attribute name="class">
                    <xsl:choose>
                        <xsl:when test="@level='CRITICAL'">critical</xsl:when>
                        <xsl:when test="@level='WARNING'">warning</xsl:when>
                        <xsl:otherwise>info</xsl:otherwise>
                    </xsl:choose>
                </xsl:attribute>
                <xsl:value-of select="@level"/>
            </td>
            <td><xsl:value-of select="Service"/></td>
            <td><xsl:value-of select="SourceIP"/></td>
            <td><xsl:value-of select="Message"/></td>
        </tr>
        </xsl:for-each>
    </table>
</body>
</html>
</xsl:template>
</xsl:stylesheet>'''


def export_to_xml(filename: str, config: dict, state) -> tuple:
    """Export attack history to XML with XSLT stylesheet.
    
    Args:
        filename: Output XML filename
        config: Configuration dictionary
        state: HoneypotState object
        
    Returns:
        Tuple of (xml_filename, xslt_filename)
    """
    # Create root element
    root = ET.Element("HoneypotReport")
    root.set("generated", datetime.datetime.now().isoformat())
    root.set("hostname", config["HOSTNAME"])
    
    # Summary section
    summary = ET.SubElement(root, "Summary")
    ET.SubElement(summary, "TotalEvents").text = str(len(state.events))
    ET.SubElement(summary, "TotalCredentials").text = str(len(state.credentials))
    ET.SubElement(summary, "ActiveSessions").text = str(len(state.sessions))
    
    with state.lock:
        crit_count = sum(1 for e in state.events if e.level == "CRITICAL")
        warn_count = sum(1 for e in state.events if e.level == "WARNING")
    ET.SubElement(summary, "CriticalEvents").text = str(crit_count)
    ET.SubElement(summary, "WarningEvents").text = str(warn_count)
    
    # Credentials section
    creds_elem = ET.SubElement(root, "CapturedCredentials")
    with state.lock:
        for cred in state.credentials:
            cred_elem = ET.SubElement(creds_elem, "Credential")
            ET.SubElement(cred_elem, "Timestamp").text = cred.timestamp
            ET.SubElement(cred_elem, "SourceIP").text = cred.source_ip
            ET.SubElement(cred_elem, "SourcePort").text = str(cred.source_port)
            ET.SubElement(cred_elem, "Service").text = cred.service
            ET.SubElement(cred_elem, "Username").text = cred.username
            ET.SubElement(cred_elem, "Password").text = cred.password
            ET.SubElement(cred_elem, "Type").text = cred.credential_type
    
    # Events section
    events_elem = ET.SubElement(root, "Events")
    with state.lock:
        for event in state.events[-500:]:  # Last 500 events
            event_elem = ET.SubElement(events_elem, "Event")
            event_elem.set("level", event.level)
            ET.SubElement(event_elem, "Timestamp").text = event.timestamp
            ET.SubElement(event_elem, "Service").text = event.service
            ET.SubElement(event_elem, "SourceIP").text = event.source_ip
            ET.SubElement(event_elem, "Message").text = event.message
    
    # Write XML with XSLT reference
    xml_content = '<?xml version="1.0" encoding="UTF-8"?>\n'
    xml_content += '<?xml-stylesheet type="text/xsl" href="honeypot_report.xslt"?>\n'
    xml_content += ET.tostring(root, encoding='unicode')
    
    with open(filename, 'w') as f:
        f.write(xml_content)
    
    # Also create the XSLT stylesheet
    xslt_filename = filename.rsplit('.', 1)[0] + '.xslt'
    with open(xslt_filename, 'w') as f:
        f.write(XSLT_CONTENT)
    
    return filename, xslt_filename


def export_to_json(filename: str, config: dict, state) -> str:
    """Export attack history to JSON format.
    
    Args:
        filename: Output JSON filename
        config: Configuration dictionary
        state: HoneypotState object
        
    Returns:
        The filename that was written
    """
    report = {
        "meta": {
            "generated": datetime.datetime.now().isoformat(),
            "hostname": config["HOSTNAME"],
            "report_type": "Honey POT Security Audit"
        },
        "summary": {
            "total_events": len(state.events),
            "total_credentials": len(state.credentials),
            "active_sessions": len(state.sessions),
            "critical_events": 0,
            "warning_events": 0
        },
        "credentials": [],
        "sessions": [],
        "events": []
    }
    
    with state.lock:
        # Summary counts
        report["summary"]["critical_events"] = sum(1 for e in state.events if e.level == "CRITICAL")
        report["summary"]["warning_events"] = sum(1 for e in state.events if e.level == "WARNING")
        
        # Credentials
        for cred in state.credentials:
            report["credentials"].append({
                "timestamp": cred.timestamp,
                "source_ip": cred.source_ip,
                "source_port": cred.source_port,
                "service": cred.service,
                "username": cred.username,
                "password": cred.password,
                "type": cred.credential_type
            })
        
        # Sessions
        for session_id, session in state.sessions.items():
            report["sessions"].append({
                "session_id": session_id,
                "source_ip": session.source_ip,
                "source_port": session.source_port,
                "service": session.service,
                "start_time": session.start_time,
                "username": session.username,
                "is_elevated": session.is_elevated
            })
        
        # Events (last 500)
        for event in state.events[-500:]:
            report["events"].append({
                "timestamp": event.timestamp,
                "level": event.level,
                "service": event.service,
                "source_ip": event.source_ip,
                "message": event.message
            })
    
    with open(filename, 'w') as f:
        json.dump(report, f, indent=2)
    
    return filename
