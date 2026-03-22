"""
Management command to seed the database with sample data.
"""
import random
from datetime import timedelta
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.contrib.auth.models import User

from compliance.models import ComplianceFramework, ComplianceControl, AuditRecord
from vendors.models import Vendor, VendorAssessment
from cve_engine.services import fetch_cves_from_nvd, process_cves


class Command(BaseCommand):
    help = 'Seed database with sample compliance, vendor, and CVE data'

    def handle(self, *args, **options):
        self.stdout.write('[SEED] Seeding database...')

        self._create_superuser()
        self._create_frameworks()
        self._create_vendors()
        self._seed_cves()

        self.stdout.write(self.style.SUCCESS('[OK] Database seeded successfully!'))

    def _create_superuser(self):
        if not User.objects.filter(username='admin').exists():
            User.objects.create_superuser('admin', 'admin@threatshield.ai', 'admin123')
            self.stdout.write('  [OK] Superuser created (admin/admin123)')
        else:
            self.stdout.write('  [INFO] Superuser already exists')

    def _create_frameworks(self):
        frameworks_data = [
            {
                'name': 'ISO 27001:2022',
                'framework_type': 'ISO27001',
                'description': 'International standard for Information Security Management Systems (ISMS)',
                'version': '2022',
                'controls': [
                    ('A.5.1', 'Policies for Information Security', 'Organizational Controls'),
                    ('A.5.2', 'Information Security Roles and Responsibilities', 'Organizational Controls'),
                    ('A.6.1', 'Screening', 'People Controls'),
                    ('A.6.2', 'Terms and Conditions of Employment', 'People Controls'),
                    ('A.7.1', 'Physical Security Perimeters', 'Physical Controls'),
                    ('A.7.2', 'Physical Entry', 'Physical Controls'),
                    ('A.8.1', 'User Endpoint Devices', 'Technological Controls'),
                    ('A.8.2', 'Privileged Access Rights', 'Technological Controls'),
                    ('A.8.3', 'Information Access Restriction', 'Technological Controls'),
                    ('A.8.5', 'Secure Authentication', 'Technological Controls'),
                    ('A.8.7', 'Protection Against Malware', 'Technological Controls'),
                    ('A.8.8', 'Management of Technical Vulnerabilities', 'Technological Controls'),
                    ('A.8.9', 'Configuration Management', 'Technological Controls'),
                    ('A.8.15', 'Logging', 'Technological Controls'),
                    ('A.8.16', 'Monitoring Activities', 'Technological Controls'),
                ],
            },
            {
                'name': 'GDPR Compliance',
                'framework_type': 'GDPR',
                'description': 'EU General Data Protection Regulation',
                'version': '2016/679',
                'controls': [
                    ('Art.5', 'Principles of Data Processing', 'Data Principles'),
                    ('Art.6', 'Lawfulness of Processing', 'Legal Basis'),
                    ('Art.7', 'Conditions for Consent', 'Consent'),
                    ('Art.13', 'Information to Data Subjects', 'Transparency'),
                    ('Art.15', 'Right of Access', 'Data Subject Rights'),
                    ('Art.17', 'Right to Erasure', 'Data Subject Rights'),
                    ('Art.25', 'Data Protection by Design', 'Technical Measures'),
                    ('Art.32', 'Security of Processing', 'Technical Measures'),
                    ('Art.33', 'Breach Notification to Authority', 'Breach Management'),
                    ('Art.35', 'Data Protection Impact Assessment', 'Risk Management'),
                ],
            },
            {
                'name': 'DPDP Act 2023',
                'framework_type': 'DPDP',
                'description': 'India Digital Personal Data Protection Act 2023',
                'version': '2023',
                'controls': [
                    ('S.4', 'Lawful Purpose Processing', 'Processing'),
                    ('S.5', 'Notice Requirements', 'Consent'),
                    ('S.6', 'Consent Requirements', 'Consent'),
                    ('S.7', 'Consent Manager Obligations', 'Consent'),
                    ('S.8', 'Data Fiduciary Obligations', 'Obligations'),
                    ('S.9', 'Processing for Children', 'Special Categories'),
                    ('S.11', 'Data Principal Rights', 'Rights'),
                    ('S.12', 'Data Breach Notification', 'Breach'),
                    ('S.15', 'Cross-border Transfer', 'Transfer'),
                    ('S.16', 'Significant Data Fiduciary', 'Obligations'),
                ],
            },
            {
                'name': 'SOC 2 Type II',
                'framework_type': 'SOC2',
                'description': 'Service Organization Control 2 - Trust Service Criteria',
                'version': 'Type II',
                'controls': [
                    ('CC1.1', 'COSO Integrity and Ethics', 'Common Criteria'),
                    ('CC2.1', 'Internal Communication', 'Common Criteria'),
                    ('CC3.1', 'Risk Assessment', 'Common Criteria'),
                    ('CC5.1', 'Logical and Physical Access', 'Common Criteria'),
                    ('CC6.1', 'Boundary Protection', 'Common Criteria'),
                    ('CC6.6', 'Threat Management', 'Common Criteria'),
                    ('CC7.1', 'System Monitoring', 'Common Criteria'),
                    ('CC7.2', 'Anomaly Detection', 'Common Criteria'),
                    ('CC8.1', 'Change Management', 'Common Criteria'),
                    ('A1.1', 'Availability Processing', 'Availability'),
                ],
            },
            {
                'name': 'HIPAA Security Rule',
                'framework_type': 'HIPAA',
                'description': 'Health Insurance Portability and Accountability Act',
                'version': '2013',
                'controls': [
                    ('164.308(a)(1)', 'Security Management Process', 'Administrative'),
                    ('164.308(a)(3)', 'Workforce Security', 'Administrative'),
                    ('164.308(a)(4)', 'Information Access Management', 'Administrative'),
                    ('164.308(a)(5)', 'Security Awareness Training', 'Administrative'),
                    ('164.310(a)', 'Facility Access Controls', 'Physical'),
                    ('164.310(c)', 'Workstation Security', 'Physical'),
                    ('164.312(a)', 'Access Control', 'Technical'),
                    ('164.312(b)', 'Audit Controls', 'Technical'),
                    ('164.312(c)', 'Integrity Controls', 'Technical'),
                    ('164.312(e)', 'Transmission Security', 'Technical'),
                ],
            },
            {
                'name': 'PCI DSS v4.0',
                'framework_type': 'PCIDSS',
                'description': 'Payment Card Industry Data Security Standard',
                'version': '4.0',
                'controls': [
                    ('Req.1', 'Network Security Controls', 'Network'),
                    ('Req.2', 'Secure System Configurations', 'Network'),
                    ('Req.3', 'Protect Stored Account Data', 'Data Protection'),
                    ('Req.4', 'Protect Data in Transit', 'Data Protection'),
                    ('Req.5', 'Protect from Malicious Software', 'Vulnerability'),
                    ('Req.6', 'Secure Systems and Software', 'Vulnerability'),
                    ('Req.7', 'Restrict Access by Business Need', 'Access Control'),
                    ('Req.8', 'Identify Users and Authenticate', 'Access Control'),
                    ('Req.10', 'Log and Monitor Access', 'Monitoring'),
                    ('Req.11', 'Test Security Regularly', 'Testing'),
                ],
            },
            {
                'name': 'RBI Cybersecurity Framework',
                'framework_type': 'RBI',
                'description': 'Reserve Bank of India guidelines on Information Security and Cyber Security',
                'version': '2023',
                'controls': [
                    ('RBI.1', 'IT Governance', 'Governance'),
                    ('RBI.2', 'Inventory of IT Assets', 'Asset Management'),
                    ('RBI.3', 'Cyber Crisis Management Plan', 'Incident Response'),
                    ('RBI.4', 'Network Security', 'Technical Controls'),
                    ('RBI.5', 'Advanced Real-time Monitoring', 'Monitoring'),
                    ('RBI.6', 'Data Leak Prevention', 'Data Protection'),
                    ('RBI.7', 'Vulnerability Assessment', 'Assessment'),
                    ('RBI.8', 'Phishing Mitigation', 'Awareness'),
                ],
            },
            {
                'name': 'SEBI CSCRF',
                'framework_type': 'SEBI',
                'description': 'SEBI Cyber Security and Cyber Resilience Framework',
                'version': '2023',
                'controls': [
                    ('SEBI.1', 'Governance Framework', 'Governance'),
                    ('SEBI.2', 'Identify Critical Assets', 'Asset Management'),
                    ('SEBI.3', 'Protection Measures', 'Protection'),
                    ('SEBI.4', 'Detection Capabilities', 'Detection'),
                    ('SEBI.5', 'Response Procedures', 'Response'),
                    ('SEBI.6', 'Recovery Planning', 'Recovery'),
                ],
            },
        ]

        statuses = ['compliant', 'non_compliant', 'partial', 'not_assessed']
        weights = [0.5, 0.1, 0.2, 0.2]

        for fw_data in frameworks_data:
            fw, created = ComplianceFramework.objects.get_or_create(
                framework_type=fw_data['framework_type'],
                defaults={
                    'name': fw_data['name'],
                    'description': fw_data['description'],
                    'version': fw_data['version'],
                }
            )
            if created:
                for ctrl in fw_data['controls']:
                    status = random.choices(statuses, weights=weights)[0]
                    ComplianceControl.objects.create(
                        framework=fw,
                        control_id=ctrl[0],
                        title=ctrl[1],
                        category=ctrl[2],
                        status=status,
                        description=f'Control {ctrl[0]} - {ctrl[1]} under {fw_data["name"]}',
                    )
                self.stdout.write(f'  [OK] Framework: {fw_data["name"]} with {len(fw_data["controls"])} controls')

                # Create audit record
                AuditRecord.objects.create(
                    framework=fw,
                    auditor_name=random.choice(['Deloitte India', 'KPMG', 'PwC', 'EY', 'BSI Group']),
                    audit_type='Annual Assessment',
                    status=random.choice(['completed', 'in_progress']),
                    findings=f'Annual audit findings for {fw_data["name"]}',
                    score=random.uniform(60, 95),
                    audit_date=timezone.now() - timedelta(days=random.randint(1, 90)),
                )

    def _create_vendors(self):
        vendors_data = [
            {
                'name': 'Infosys',
                'category': 'IT Services',
                'tech_stack': ['Java', 'Oracle', 'SAP', 'Azure'],
                'country': 'India',
                'risk_score': 3.2,
            },
            {
                'name': 'TCS (Tata Consultancy)',
                'category': 'IT Services',
                'tech_stack': ['Python', 'AWS', 'MongoDB', 'Jenkins'],
                'country': 'India',
                'risk_score': 2.8,
            },
            {
                'name': 'Wipro',
                'category': 'IT Services',
                'tech_stack': ['Microsoft', 'Windows', '.NET', 'SQL Server'],
                'country': 'India',
                'risk_score': 4.1,
            },
            {
                'name': 'AWS India',
                'category': 'Cloud Provider',
                'tech_stack': ['AWS', 'Linux', 'Docker', 'Kubernetes'],
                'country': 'India',
                'risk_score': 2.5,
            },
            {
                'name': 'Microsoft Azure India',
                'category': 'Cloud Provider',
                'tech_stack': ['Azure', 'Windows', 'Outlook', '.NET'],
                'country': 'India',
                'risk_score': 3.0,
            },
            {
                'name': 'Razorpay',
                'category': 'Payment Gateway',
                'tech_stack': ['Python', 'Go', 'PostgreSQL', 'Redis'],
                'country': 'India',
                'risk_score': 5.2,
            },
            {
                'name': 'Paytm',
                'category': 'Fintech',
                'tech_stack': ['Java', 'MySQL', 'Redis', 'Kafka'],
                'country': 'India',
                'risk_score': 5.8,
            },
            {
                'name': 'Fortinet India',
                'category': 'Network Security',
                'tech_stack': ['FortiOS', 'FortiGate', 'FortiManager'],
                'country': 'India',
                'risk_score': 4.5,
            },
            {
                'name': 'Palo Alto Networks India',
                'category': 'Cybersecurity',
                'tech_stack': ['PAN-OS', 'Cortex', 'Prisma'],
                'country': 'India',
                'risk_score': 3.8,
            },
            {
                'name': 'Cisco India',
                'category': 'Networking',
                'tech_stack': ['Cisco IOS', 'ASA', 'Meraki', 'Webex'],
                'country': 'India',
                'risk_score': 4.2,
            },
            {
                'name': 'NPCI (National Payments Corp)',
                'category': 'Payment Infrastructure',
                'tech_stack': ['Java', 'IBM', 'Oracle', 'UPI'],
                'country': 'India',
                'risk_score': 2.0,
            },
            {
                'name': 'Zoho',
                'category': 'SaaS',
                'tech_stack': ['Java', 'JavaScript', 'MySQL', 'PHP'],
                'country': 'India',
                'risk_score': 3.5,
            },
        ]

        for v_data in vendors_data:
            vendor, created = Vendor.objects.get_or_create(
                name=v_data['name'],
                defaults={
                    'category': v_data['category'],
                    'tech_stack': v_data['tech_stack'],
                    'country': v_data['country'],
                    'risk_score': v_data['risk_score'],
                    'risk_level': 'low' if v_data['risk_score'] < 4 else 'medium' if v_data['risk_score'] < 7 else 'high',
                    'description': f'{v_data["name"]} - {v_data["category"]} vendor operating in {v_data["country"]}',
                    'last_assessment_date': timezone.now() - timedelta(days=random.randint(1, 180)),
                }
            )
            if created:
                self.stdout.write(f'  [OK] Vendor: {v_data["name"]}')

    def _seed_cves(self):
        self.stdout.write('  Fetching and processing CVEs...')
        cve_list = fetch_cves_from_nvd()
        count = process_cves(cve_list)
        self.stdout.write(f'  [OK] Processed {count} CVEs')
