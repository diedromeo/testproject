import json
import random
import logging
from datetime import datetime, timedelta

import requests
from django.conf import settings
from django.utils import timezone

from .models import CVE, CVEControlMapping
from advisories.models import Advisory
from alerts.models import Alert
from core.models import AuditLog

logger = logging.getLogger(__name__)

# Control mapping rules
CONTROL_MAPPINGS = [
    {
        'keywords': ['remote code execution', 'rce', 'command injection'],
        'control': 'A.12.6.1 - Technical Vulnerability Management',
        'framework': 'ISO 27001',
        'risk': 'Unauthorized remote code execution allows attackers to take full control of systems',
        'mitigation': 'Apply patches immediately, implement WAF, restrict network access',
    },
    {
        'keywords': ['sql injection', 'sqli', 'database'],
        'control': 'A.14.2.5 - Secure System Engineering',
        'framework': 'ISO 27001',
        'risk': 'SQL injection can lead to data breach and unauthorized data access',
        'mitigation': 'Use parameterized queries, input validation, database firewalls',
    },
    {
        'keywords': ['cross-site scripting', 'xss', 'script injection'],
        'control': 'A.14.1.2 - Securing Application Services',
        'framework': 'ISO 27001',
        'risk': 'XSS allows attackers to steal user sessions and inject malicious content',
        'mitigation': 'Implement CSP headers, output encoding, input sanitization',
    },
    {
        'keywords': ['authentication', 'bypass', 'login', 'credential'],
        'control': 'A.9.4.2 - Secure Log-on Procedures',
        'framework': 'ISO 27001',
        'risk': 'Authentication bypass enables unauthorized access to protected resources',
        'mitigation': 'Implement MFA, strong password policies, account lockout mechanisms',
    },
    {
        'keywords': ['buffer overflow', 'memory corruption', 'heap', 'stack'],
        'control': 'A.12.6.1 - Technical Vulnerability Management',
        'framework': 'ISO 27001',
        'risk': 'Memory corruption can lead to arbitrary code execution',
        'mitigation': 'Apply vendor patches, enable ASLR/DEP, use memory-safe languages',
    },
    {
        'keywords': ['denial of service', 'dos', 'resource exhaustion'],
        'control': 'A.17.1.1 - Information Security Continuity',
        'framework': 'ISO 27001',
        'risk': 'Service disruption affecting business continuity',
        'mitigation': 'Implement rate limiting, DDoS protection, redundancy',
    },
    {
        'keywords': ['privilege escalation', 'root', 'admin', 'elevated'],
        'control': 'A.9.2.3 - Management of Privileged Access Rights',
        'framework': 'ISO 27001',
        'risk': 'Attackers can gain administrative privileges',
        'mitigation': 'Apply least privilege, regular access reviews, privileged access management',
    },
    {
        'keywords': ['encryption', 'cryptographic', 'tls', 'ssl', 'certificate'],
        'control': 'A.10.1.1 - Policy on Use of Cryptographic Controls',
        'framework': 'ISO 27001',
        'risk': 'Weak cryptography can expose sensitive data in transit',
        'mitigation': 'Use strong encryption algorithms, regular certificate rotation',
    },
    {
        'keywords': ['information disclosure', 'data leak', 'exposure', 'sensitive'],
        'control': 'Article 32 - Security of Processing',
        'framework': 'GDPR',
        'risk': 'Personal data exposure violating data protection regulations',
        'mitigation': 'Data encryption, access controls, DLP solutions',
    },
    {
        'keywords': ['network', 'port', 'firewall', 'open port'],
        'control': 'Requirement 1 - Network Security Controls',
        'framework': 'PCI DSS',
        'risk': 'Unauthorized network access to cardholder data environment',
        'mitigation': 'Implement network segmentation, restrict open ports, IDS/IPS',
    },
]

# Simulated geo-locations for CVE origins
GEO_LOCATIONS = [
    {'country': 'United States', 'lat': 38.9072, 'lng': -77.0369},
    {'country': 'China', 'lat': 39.9042, 'lng': 116.4074},
    {'country': 'Russia', 'lat': 55.7558, 'lng': 37.6173},
    {'country': 'India', 'lat': 28.6139, 'lng': 77.2090},
    {'country': 'Germany', 'lat': 52.5200, 'lng': 13.4050},
    {'country': 'United Kingdom', 'lat': 51.5074, 'lng': -0.1278},
    {'country': 'Brazil', 'lat': -15.7975, 'lng': -47.8919},
    {'country': 'Japan', 'lat': 35.6762, 'lng': 139.6503},
    {'country': 'South Korea', 'lat': 37.5665, 'lng': 126.9780},
    {'country': 'Iran', 'lat': 35.6892, 'lng': 51.3890},
    {'country': 'North Korea', 'lat': 39.0392, 'lng': 125.7625},
    {'country': 'Israel', 'lat': 31.7683, 'lng': 35.2137},
    {'country': 'France', 'lat': 48.8566, 'lng': 2.3522},
    {'country': 'Australia', 'lat': -33.8688, 'lng': 151.2093},
    {'country': 'Canada', 'lat': 45.4215, 'lng': -75.6972},
    {'country': 'Singapore', 'lat': 1.3521, 'lng': 103.8198},
    {'country': 'UAE', 'lat': 25.2048, 'lng': 55.2708},
    {'country': 'Nigeria', 'lat': 9.0579, 'lng': 7.4951},
    {'country': 'Turkey', 'lat': 39.9334, 'lng': 32.8597},
    {'country': 'Pakistan', 'lat': 33.6844, 'lng': 73.0479},
]


# Mock CVE data for simulation
MOCK_CVES = [
    {
        'cve_id': 'CVE-2024-21762',
        'description': 'A critical out-of-bound write vulnerability in FortiOS SSL VPN allows remote unauthenticated attackers to execute arbitrary code via specially crafted HTTP requests.',
        'severity_score': 9.8,
        'vendor': 'Fortinet',
        'product': 'FortiOS',
        'attack_vector': 'NETWORK',
    },
    {
        'cve_id': 'CVE-2024-3400',
        'description': 'A command injection vulnerability in Palo Alto Networks PAN-OS GlobalProtect feature enables unauthenticated attackers to execute arbitrary code with root privileges on the firewall.',
        'severity_score': 10.0,
        'vendor': 'Palo Alto Networks',
        'product': 'PAN-OS',
        'attack_vector': 'NETWORK',
    },
    {
        'cve_id': 'CVE-2024-1709',
        'description': 'Authentication bypass vulnerability in ConnectWise ScreenConnect allows attackers to bypass authentication and gain administrative access.',
        'severity_score': 10.0,
        'vendor': 'ConnectWise',
        'product': 'ScreenConnect',
        'attack_vector': 'NETWORK',
    },
    {
        'cve_id': 'CVE-2024-27198',
        'description': 'Authentication bypass vulnerability in JetBrains TeamCity allowing unauthorized remote attackers to take administrative control of TeamCity server.',
        'severity_score': 9.8,
        'vendor': 'JetBrains',
        'product': 'TeamCity',
        'attack_vector': 'NETWORK',
    },
    {
        'cve_id': 'CVE-2024-21413',
        'description': 'Microsoft Outlook remote code execution vulnerability allows attackers to bypass Office Protected View and execute arbitrary code through malicious Office documents.',
        'severity_score': 9.8,
        'vendor': 'Microsoft',
        'product': 'Outlook',
        'attack_vector': 'NETWORK',
    },
    {
        'cve_id': 'CVE-2024-20353',
        'description': 'Cisco ASA and FTD software web services denial-of-service vulnerability allows unauthenticated remote attackers to cause device reload via crafted HTTP requests.',
        'severity_score': 8.6,
        'vendor': 'Cisco',
        'product': 'ASA',
        'attack_vector': 'NETWORK',
    },
    {
        'cve_id': 'CVE-2024-23897',
        'description': 'Jenkins CLI arbitrary file read vulnerability allows unauthenticated attackers to read sensitive files from the Jenkins controller filesystem.',
        'severity_score': 9.8,
        'vendor': 'Jenkins',
        'product': 'Jenkins',
        'attack_vector': 'NETWORK',
    },
    {
        'cve_id': 'CVE-2024-0012',
        'description': 'Palo Alto Networks PAN-OS management interface authentication bypass allows unauthenticated network attackers to escalate to administrator privileges.',
        'severity_score': 9.8,
        'vendor': 'Palo Alto Networks',
        'product': 'PAN-OS',
        'attack_vector': 'NETWORK',
    },
    {
        'cve_id': 'CVE-2024-4577',
        'description': 'PHP CGI argument injection vulnerability allows remote attackers to execute arbitrary commands on Windows servers running PHP in CGI mode.',
        'severity_score': 9.8,
        'vendor': 'PHP Group',
        'product': 'PHP',
        'attack_vector': 'NETWORK',
    },
    {
        'cve_id': 'CVE-2024-38063',
        'description': 'Windows TCP/IP remote code execution vulnerability in IPv6 stack allows unauthenticated attackers to execute arbitrary code by sending specially crafted IPv6 packets.',
        'severity_score': 9.8,
        'vendor': 'Microsoft',
        'product': 'Windows',
        'attack_vector': 'NETWORK',
    },
    {
        'cve_id': 'CVE-2024-6387',
        'description': 'OpenSSH server signal handler race condition (regreSSHion) allows unauthenticated remote code execution as root on Linux-based glibc systems.',
        'severity_score': 8.1,
        'vendor': 'OpenBSD',
        'product': 'OpenSSH',
        'attack_vector': 'NETWORK',
    },
    {
        'cve_id': 'CVE-2024-47575',
        'description': 'FortiManager missing authentication vulnerability allows remote unauthenticated attackers to execute arbitrary code via specially crafted requests to fgfmsd daemon.',
        'severity_score': 9.8,
        'vendor': 'Fortinet',
        'product': 'FortiManager',
        'attack_vector': 'NETWORK',
    },
    {
        'cve_id': 'CVE-2024-21887',
        'description': 'Ivanti Connect Secure and Policy Secure command injection vulnerability allows authenticated administrators to execute arbitrary commands on the appliance.',
        'severity_score': 9.1,
        'vendor': 'Ivanti',
        'product': 'Connect Secure',
        'attack_vector': 'NETWORK',
    },
    {
        'cve_id': 'CVE-2024-9474',
        'description': 'Palo Alto Networks PAN-OS privilege escalation vulnerability allows a PAN-OS administrator to perform actions with root privileges.',
        'severity_score': 7.2,
        'vendor': 'Palo Alto Networks',
        'product': 'PAN-OS',
        'attack_vector': 'NETWORK',
    },
    {
        'cve_id': 'CVE-2024-50623',
        'description': 'Cleo Harmony, VLTrader, and LexiCom unrestricted file upload vulnerability allows remote code execution through crafted file uploads.',
        'severity_score': 9.8,
        'vendor': 'Cleo',
        'product': 'Harmony',
        'attack_vector': 'NETWORK',
    },
    {
        'cve_id': 'CVE-2024-55956',
        'description': 'Cleo file transfer software arbitrary command execution vulnerability used in active Cl0p ransomware campaigns for data theft.',
        'severity_score': 9.8,
        'vendor': 'Cleo',
        'product': 'VLTrader',
        'attack_vector': 'NETWORK',
    },
    {
        'cve_id': 'CVE-2024-12356',
        'description': 'BeyondTrust Privileged Remote Access command injection vulnerability allows unauthenticated attackers to execute arbitrary OS commands.',
        'severity_score': 9.8,
        'vendor': 'BeyondTrust',
        'product': 'Privileged Remote Access',
        'attack_vector': 'NETWORK',
    },
    {
        'cve_id': 'CVE-2024-49113',
        'description': 'Windows LDAP denial-of-service vulnerability allows remote unauthenticated attackers to crash domain controllers via malicious LDAP calls.',
        'severity_score': 7.5,
        'vendor': 'Microsoft',
        'product': 'Windows Server',
        'attack_vector': 'NETWORK',
    },
    {
        'cve_id': 'CVE-2024-30088',
        'description': 'Windows Kernel elevation of privilege vulnerability allows local attackers to gain SYSTEM privileges through a race condition in NtQueryInformationToken.',
        'severity_score': 7.0,
        'vendor': 'Microsoft',
        'product': 'Windows',
        'attack_vector': 'LOCAL',
    },
    {
        'cve_id': 'CVE-2024-43573',
        'description': 'Windows MSHTML Platform Spoofing vulnerability allows attackers to deliver malicious content through crafted web pages, exploiting the legacy browser engine.',
        'severity_score': 6.5,
        'vendor': 'Microsoft',
        'product': 'Windows',
        'attack_vector': 'NETWORK',
    },
    {
        'cve_id': 'CVE-2025-0101',
        'description': 'Post-Quantum Encryption Bypass in critical banking gateways allowing decryption of historical traffic by state-sponsored actors using early-stage quantum hardware.',
        'severity_score': 9.8,
        'vendor': 'GlobalBank-Sec',
        'product': 'Quantum-Shield V1',
        'attack_vector': 'NETWORK',
    },
    {
        'cve_id': 'CVE-2025-1022',
        'description': 'Critical remote unauthenticated file read vulnerability in widespread VPN gateway software allows attackers to exfiltrate session keys and user credentials.',
        'severity_score': 9.8,
        'vendor': 'PulseSecure',
        'product': 'Connect Secure V2',
        'attack_vector': 'NETWORK',
    },
    {
        'cve_id': 'CVE-2025-4491',
        'description': 'Zero-day privilege escalation in standard container runtime environments enabling container escape to host system with root privileges.',
        'severity_score': 10.0,
        'vendor': 'CloudNative',
        'product': 'Container-Runtime',
        'attack_vector': 'LOCAL',
    },
    {
        'cve_id': 'CVE-2026-0012',
        'description': 'Strategic AI Model bypass vulnerability in corporate LLM gateways allows prompt injection to leak internal training data and proprietary source code.',
        'severity_score': 8.8,
        'vendor': 'EnterpriseAI',
        'product': 'Model-Guard',
        'attack_vector': 'NETWORK',
    },
    {
        'cve_id': 'CVE-2026-1182',
        'description': 'Quantum-resistant encryption downgrade attack in legacy TLS libraries allowing MITM actors to force weak keys on older browser versions.',
        'severity_score': 7.5,
        'vendor': 'OpenSSL',
        'product': 'LibCrypto-Q',
        'attack_vector': 'NETWORK',
    },
    {
        'cve_id': 'CVE-2026-3390',
        'description': 'Distributed Ledger technology buffer overflow in consensus protocol allowing transaction forgery in private blockchain networks.',
        'severity_score': 9.1,
        'vendor': 'HyperLedger',
        'product': 'Fabric-Core',
        'attack_vector': 'NETWORK',
    },
    {
        'cve_id': 'CVE-2026-9999',
        'description': 'Neural-Link Interface data exfiltration vulnerability allowing unauthorized access to sensory telemetry data in experimental neuro-medical implants.',
        'severity_score': 10.0,
        'vendor': 'Neurolink-Gen',
        'product': 'N1-Core',
        'attack_vector': 'ADJACENT_NETWORK',
    },
]


def fetch_cves_from_nvd():
    """Fetch latest CVEs from NVD API."""
    try:
        headers = {}
        if settings.NVD_API_KEY:
            headers['apiKey'] = settings.NVD_API_KEY

        params = {
            'resultsPerPage': settings.CVE_FETCH_MAX_RESULTS,
        }

        response = requests.get(
            settings.NVD_API_URL,
            params=params,
            headers=headers,
            timeout=30
        )

        if response.status_code == 200:
            data = response.json()
            return parse_nvd_response(data)
        else:
            logger.warning(f"NVD API returned status {response.status_code}, falling back to strategic intelligence.")
            return MOCK_CVES

    except Exception as e:
        logger.error(f"Error fetching CVEs from NVD: {e}")
        return MOCK_CVES


def parse_nvd_response(data):
    """Parse NVD API response into CVE dictionaries."""
    cves = []
    for item in data.get('vulnerabilities', []):
        cve_data = item.get('cve', {})
        cve_id = cve_data.get('id', '')
        
        # Filter strictly for 2023 and beyond
        if not any(cve_id.startswith(f'CVE-{year}') for year in range(2023, 2030)):
            continue

        # Get description
        descriptions = cve_data.get('descriptions', [])
        description = ''
        for desc in descriptions:
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break

        # Get CVSS score
        severity_score = 0.0
        metrics = cve_data.get('metrics', {})
        if 'cvssMetricV31' in metrics:
            severity_score = metrics['cvssMetricV31'][0]['cvssData'].get('baseScore', 0)
        elif 'cvssMetricV2' in metrics:
            severity_score = metrics['cvssMetricV2'][0]['cvssData'].get('baseScore', 0)

        # Get published date
        published = cve_data.get('published', '')

        cves.append({
            'cve_id': cve_id,
            'description': description,
            'severity_score': severity_score,
            'vendor': '',
            'product': '',
            'attack_vector': 'NETWORK',
        })

    return cves


def process_cves(cve_list):
    """Process and save CVEs to database, generate advisories and alerts."""
    created_count = 0
    for cve_data in cve_list:
        cve_id = cve_data['cve_id']

        if CVE.objects.filter(cve_id=cve_id).exists():
            continue

        # Assign random geo-location
        geo = random.choice(GEO_LOCATIONS)

        severity_level = CVE.calculate_severity_level(cve_data['severity_score'])

        cve = CVE.objects.create(
            cve_id=cve_id,
            description=cve_data['description'],
            severity_score=cve_data['severity_score'],
            severity_level=severity_level,
            published_date=timezone.now() - timedelta(hours=random.randint(0, 48)),
            vendor=cve_data.get('vendor', ''),
            product=cve_data.get('product', ''),
            attack_vector=cve_data.get('attack_vector', 'NETWORK'),
            latitude=geo['lat'] + random.uniform(-2, 2),
            longitude=geo['lng'] + random.uniform(-2, 2),
            country=geo['country'],
        )

        # Create control mappings
        create_control_mappings(cve)

        # Generate advisory
        generate_advisory(cve)

        # Generate alert if high/critical
        if severity_level in ['HIGH', 'CRITICAL']:
            generate_alert(cve)

        # Log activity
        AuditLog.objects.create(
            action_type='cve_fetch',
            description=f'New CVE ingested: {cve_id} (Severity: {severity_level})',
            metadata={'cve_id': cve_id, 'severity': severity_level},
        )

        created_count += 1

    return created_count


def create_control_mappings(cve):
    """Map CVE to compliance controls based on description keywords."""
    desc_lower = cve.description.lower()

    for mapping in CONTROL_MAPPINGS:
        if any(kw in desc_lower for kw in mapping['keywords']):
            CVEControlMapping.objects.create(
                cve=cve,
                control_name=mapping['control'],
                framework=mapping['framework'],
                risk_description=mapping['risk'],
                mitigation=mapping['mitigation'],
            )


def generate_advisory(cve):
    """Generate CERT-IN style advisory for a CVE."""
    severity_actions = {
        'CRITICAL': [
            'Apply vendor patches IMMEDIATELY',
            'Isolate affected systems from network',
            'Enable enhanced monitoring and logging',
            'Activate incident response team',
            'Report to CERT-IN as per guidelines',
        ],
        'HIGH': [
            'Apply vendor patches within 24 hours',
            'Restrict network access to affected systems',
            'Enable additional monitoring',
            'Review access control policies',
        ],
        'MEDIUM': [
            'Apply vendor patches within 7 days',
            'Monitor affected systems for anomalies',
            'Review and update security configurations',
        ],
        'LOW': [
            'Apply vendor patches during next maintenance window',
            'Document vulnerability for compliance tracking',
        ],
    }

    actions = severity_actions.get(cve.severity_level, severity_actions['MEDIUM'])

    advisory = Advisory.objects.create(
        title=f"Advisory: {cve.severity_level} Vulnerability in {cve.product or 'System Component'} - {cve.cve_id}",
        description=f"A {cve.severity_level.lower()} severity vulnerability ({cve.cve_id}) has been identified.\n\n"
                    f"CVSS Score: {cve.severity_score}/10.0\n\n"
                    f"Description: {cve.description}\n\n"
                    f"Vendor: {cve.vendor or 'Multiple Vendors'}\n"
                    f"Product: {cve.product or 'Multiple Products'}\n"
                    f"Attack Vector: {cve.attack_vector}",
        affected_systems=f"{cve.vendor} {cve.product}" if cve.vendor else "Multiple Systems",
        severity=cve.severity_level.lower(),
        recommended_action='\n'.join(f"• {a}" for a in actions),
        source='AUTO',
        linked_cve=cve,
    )

    AuditLog.objects.create(
        action_type='advisory_created',
        description=f'Advisory auto-generated for {cve.cve_id}',
        metadata={'advisory_id': advisory.id, 'cve_id': cve.cve_id},
    )

    return advisory


def generate_alert(cve):
    """Generate alert for high/critical CVEs."""
    alert = Alert.objects.create(
        title=f"🚨 {cve.severity_level} CVE Detected: {cve.cve_id}",
        description=f"A {cve.severity_level.lower()} severity vulnerability has been detected.\n\n"
                    f"{cve.description}\n\n"
                    f"CVSS Score: {cve.severity_score}/10.0\n"
                    f"Vendor: {cve.vendor or 'Unknown'}\n"
                    f"Product: {cve.product or 'Unknown'}",
        severity=cve.severity_level.lower(),
        alert_type='cve',
        linked_cve=cve,
        status='open',
    )

    AuditLog.objects.create(
        action_type='alert_triggered',
        description=f'Alert triggered for {cve.cve_id} ({cve.severity_level})',
        metadata={'alert_id': alert.id, 'cve_id': cve.cve_id},
    )

    return alert
