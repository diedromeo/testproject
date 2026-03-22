import json
import requests
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings

from .models import ChatSession, ChatMessage
from cve_engine.models import CVE



@login_required
def chat_view(request):
    """AI chat interface."""
    sessions = ChatSession.objects.filter(user=request.user)[:10]
    context = {
        'sessions': sessions,
    }
    return render(request, 'ai_assistant/chat.html', context)


@csrf_exempt
@login_required
def chat_api(request):
    """Handle chat API requests."""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    try:
        data = json.loads(request.body)
        user_message = data.get('message', '').strip()

        if not user_message:
            return JsonResponse({'error': 'Empty message'}, status=400)

        # Get or create session
        session_id = data.get('session_id')
        if session_id:
            session = ChatSession.objects.get(id=session_id, user=request.user)
        else:
            session = ChatSession.objects.create(
                user=request.user,
                title=user_message[:50]
            )

        # Save user message
        ChatMessage.objects.create(
            session=session,
            role='user',
            content=user_message
        )

        # Check if asking about a specific CVE
        cve_context = ''
        if 'CVE-' in user_message.upper():
            import re
            cve_match = re.search(r'CVE-\d{4}-\d+', user_message.upper())
            if cve_match:
                cve_id = cve_match.group()
                try:
                    cve = CVE.objects.get(cve_id=cve_id)
                    cve_context = f"\n\nCVE Context from database:\n- ID: {cve.cve_id}\n- Score: {cve.severity_score}\n- Severity: {cve.severity_level}\n- Description: {cve.description}\n- Vendor: {cve.vendor}\n- Product: {cve.product}"
                except CVE.DoesNotExist:
                    pass

        # Try Remote Llama AI 
        ai_response = ask_ai(user_message + cve_context)

        if not ai_response or ai_response == "AI unavailable":
            # Fallback to built-in responses
            ai_response = generate_fallback_response(user_message, cve_context)

        # Save assistant message
        ChatMessage.objects.create(
            session=session,
            role='assistant',
            content=ai_response
        )

        return JsonResponse({
            'response': ai_response,
            'session_id': session.id,
        })

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


def ask_ai(prompt):
    try:
        res = requests.post(
            "http://172.236.213.60:11434/api/generate",
            json={
                "model": "llama3.2:latest",
                "prompt": prompt,
                "stream": False
            },
            timeout=500
        )
        return res.json()["response"]
    except:
        return "AI unavailable"


def generate_fallback_response(user_message, cve_context):
    """Generate a detailed fallback response without Ollama."""
    msg_lower = user_message.lower()

    if cve_context:
        return f"""## CVE Analysis

{cve_context}

### Risk Assessment
This vulnerability requires immediate attention based on its severity rating. Here are the recommended actions:

#### Immediate Steps:
1. **Patch Management**: Check vendor advisories for available patches
2. **Network Isolation**: Restrict access to affected systems
3. **Monitoring**: Enable enhanced logging on affected components
4. **Incident Response**: Prepare IR team for potential exploitation

#### Compliance Impact:
- **ISO 27001**: Review controls A.12.6.1 (Technical Vulnerability Management)
- **PCI DSS**: Verify Requirement 6 (Develop and Maintain Secure Systems)
- **GDPR**: Assess data protection impact under Article 32
- **DPDP Act**: Verify reasonable security safeguards under Section 8

#### Indian Regulatory Considerations:
- **RBI**: Report as per RBI circular on cybersecurity framework
- **CERT-IN**: File incident report within 6 hours if exploited
- **SEBI**: Update CSIRT if handling market infrastructure"""

    if any(w in msg_lower for w in ['compliance', 'framework', 'iso', 'gdpr', 'dpdp']):
        return """## Compliance Framework Overview

### International Standards:
- **ISO 27001**: Information Security Management System (ISMS) - 114 controls across 14 domains
- **GDPR**: EU data protection regulation - focuses on consent, data rights, breach notification
- **SOC 2**: Trust Service Criteria - Security, Availability, Processing Integrity, Confidentiality, Privacy
- **HIPAA**: Healthcare data protection - PHI safeguards and breach notification
- **PCI DSS**: Payment card security - 12 requirements across 6 goals

### Indian Regulatory Requirements:
- **DPDP Act 2023**: India's Digital Personal Data Protection Act
- **RBI Cybersecurity Framework**: Mandatory for banks and NBFCs
- **NPCI Standards**: Payment infrastructure security requirements
- **UIDAI/Aadhaar**: Biometric data handling standards
- **SEBI CSCRF**: Cyber Security and Cyber Resilience Framework
- **IRDAI**: Insurance regulatory technology standards

### Recommendations:
1. Conduct gap analysis across all applicable frameworks
2. Implement unified control mapping
3. Schedule regular audits (quarterly for critical controls)
4. Maintain evidence repository for audit trails"""

    if any(w in msg_lower for w in ['vendor', 'third party', 'risk']):
        return """## Vendor Risk Management

### Risk Assessment Framework:
1. **Pre-Onboarding**: Due diligence questionnaire, SOC 2 review, penetration test results
2. **Ongoing Monitoring**: Continuous security posture assessment, SLA compliance
3. **Periodic Review**: Annual risk reassessment, compliance validation

### Key Risk Indicators:
- Security certifications (ISO 27001, SOC 2)
- Data handling practices
- Incident history
- Business continuity plans
- Sub-contractor management

### Indian Regulatory Specifics:
- RBI mandates vendor risk assessment for all outsourced activities
- SEBI requires third-party audit of critical vendors
- DPDP Act holds data fiduciaries accountable for processor actions

### Risk Scoring:
- **0-3**: Low Risk - Standard monitoring
- **4-6**: Medium Risk - Enhanced oversight required
- **7-8**: High Risk - Remediation plan needed
- **9-10**: Critical Risk - Immediate escalation"""

    if any(w in msg_lower for w in ['threat', 'attack', 'breach', 'incident']):
        return """## Threat Intelligence Overview

### Current Threat Landscape:
1. **Ransomware**: Continued evolution with double/triple extortion
2. **Supply Chain Attacks**: Targeting software build pipelines
3. **Zero-Day Exploits**: Increasing use in targeted attacks
4. **APT Groups**: State-sponsored targeting of critical infrastructure
5. **AI-Powered Attacks**: Social engineering and vulnerability discovery

### Incident Response Steps:
1. **Detection**: Identify indicators of compromise (IOCs)
2. **Containment**: Isolate affected systems
3. **Eradication**: Remove malicious artifacts
4. **Recovery**: Restore systems from clean backups
5. **Lessons Learned**: Post-incident analysis

### CERT-IN Reporting Requirements:
- Report cyber incidents within 6 hours (as per April 2022 directive)
- Types: targeted scanning, compromise of systems, data breaches
- Report to incident@cert-in.org.in

### Recommended Monitoring:
- SIEM integration for real-time alerting
- Network traffic analysis
- Endpoint detection and response (EDR)
- User behavior analytics (UBA)"""

    return """## CISO AI Assistant

I'm your cybersecurity and compliance AI assistant. I can help you with:

### 🔍 CVE Analysis
- Explain specific CVEs (try: "Explain CVE-2024-21762")
- Assess vulnerability impact
- Recommend mitigations

### 📋 Compliance Guidance
- Framework comparisons (ISO, GDPR, DPDP, SOC2, HIPAA, PCI DSS)
- Indian regulatory requirements (RBI, NPCI, SEBI, IRDAI)
- Audit preparation

### 🏢 Vendor Risk
- Risk assessment methodology
- Third-party evaluation criteria
- Continuous monitoring strategies

### 🛡️ Threat Intelligence
- Current threat landscape analysis
- Incident response guidance
- Attack vector explanations

### 💡 Example Questions:
- "What is the DPDP Act and how does it affect my organization?"
- "Explain CVE-2024-3400 and its impact"
- "How should I assess vendor cybersecurity risk?"
- "What are CERT-IN reporting requirements?"

Ask me anything about cybersecurity, compliance, or threat intelligence!"""
