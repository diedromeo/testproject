import json
import random
import requests
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone

from .models import DarkWebMonitor, DarkWebAlert, DarkWebScanResult


SIMULATED_ALERTS = [
    {
        'title': 'Employee credentials found on dark web marketplace',
        'description': 'Multiple employee email/password combinations were found listed on a known dark web marketplace. The credentials appear to originate from a third-party service breach.',
        'severity': 'critical',
        'alert_type': 'credential_leak',
        'source': 'Dark Market Forum',
        'affected_assets': 'employee@company.com, admin@company.com',
        'remediation': 'Force password reset for all affected accounts. Enable MFA. Monitor for unauthorized access attempts.',
    },
    {
        'title': 'Company domain mentioned in ransomware group blog',
        'description': 'Your organization domain was mentioned in a post on a ransomware group blog. This could indicate targeted reconnaissance or a claim of data exfiltration.',
        'severity': 'critical',
        'alert_type': 'ransomware',
        'source': 'Ransomware Group Blog',
        'affected_assets': 'Organization infrastructure',
        'remediation': 'Verify all systems. Check for IOCs. Engage incident response team. Review backup integrity.',
    },
    {
        'title': 'Database dump containing user records detected on paste site',
        'description': 'A paste containing what appears to be a partial database dump with user information was detected. The data includes names, email addresses, and hashed passwords.',
        'severity': 'high',
        'alert_type': 'data_breach',
        'source': 'Paste Site',
        'affected_assets': 'User database records',
        'remediation': 'Identify the source database. Notify affected users. Reset passwords. Review access controls.',
    },
    {
        'title': 'API keys exposed in public code repository',
        'description': 'Valid API keys associated with your organization were found in a public code repository that has been mirrored to dark web archives.',
        'severity': 'high',
        'alert_type': 'credential_leak',
        'source': 'Code Repository Mirror',
        'affected_assets': 'API keys, service credentials',
        'remediation': 'Rotate all exposed API keys immediately. Implement secret scanning in CI/CD pipeline.',
    },
    {
        'title': 'Organization mentioned in hacker forum discussion',
        'description': 'Your organization was mentioned in a discussion thread on a known hacker forum. The discussion appears to be about potential vulnerabilities in your public-facing applications.',
        'severity': 'medium',
        'alert_type': 'mention',
        'source': 'Hacker Forum',
        'affected_assets': 'Public-facing applications',
        'remediation': 'Conduct vulnerability assessment on public-facing applications. Review WAF rules. Monitor access logs.',
    },
    {
        'title': 'Phishing kit targeting your brand detected',
        'description': 'A phishing kit designed to impersonate your organization login page was detected being sold on a dark web marketplace.',
        'severity': 'medium',
        'alert_type': 'market',
        'source': 'Dark Marketplace',
        'affected_assets': 'Brand reputation, customers',
        'remediation': 'Report phishing domains. Notify customers. Implement DMARC/SPF/DKIM. Monitor for active phishing campaigns.',
    },
    {
        'title': 'Internal document shared on dark web forum',
        'description': 'A document marked as internal/confidential was found shared on a dark web forum. The document appears to contain organizational process information.',
        'severity': 'medium',
        'alert_type': 'data_breach',
        'source': 'Dark Web Forum',
        'affected_assets': 'Internal documents',
        'remediation': 'Investigate source of leak. Review DLP controls. Conduct insider threat assessment.',
    },
    {
        'title': 'Email addresses found in credential stuffing list',
        'description': 'Several organizational email addresses were found in a large credential stuffing list being distributed on dark web channels.',
        'severity': 'low',
        'alert_type': 'credential_leak',
        'source': 'Credential List',
        'affected_assets': 'Employee email addresses',
        'remediation': 'Enforce MFA on all accounts. Monitor for brute force attempts. Educate employees on password hygiene.',
    },
]



def darkweb_dashboard(request):
    """Dark web monitoring dashboard."""
    monitors = DarkWebMonitor.objects.all()
    recent_alerts = DarkWebAlert.objects.all()[:10]
    
    total_alerts = DarkWebAlert.objects.count()
    critical_alerts = DarkWebAlert.objects.filter(severity='critical').count()
    new_alerts = DarkWebAlert.objects.filter(status='new').count()

    context = {
        'monitors': monitors,
        'recent_alerts': recent_alerts,
        'total_alerts': total_alerts,
        'critical_alerts': critical_alerts,
        'new_alerts': new_alerts,
        'total_monitors': monitors.count(),
    }
    return render(request, 'darkweb/dashboard.html', context)



def live_search(request):
    """Live Dark Web OSINT search interface."""
    return render(request, 'darkweb/live_search.html')


@csrf_exempt
def darkweb_search_api(request):
    """Proxy to the Leakosint OSINT API."""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)
    
    try:
        data = json.loads(request.body)
        api_url = "https://leakosintapi.com/"
        
        # Proxy to the OSINT API
        response = requests.post(api_url, json=data, timeout=30)
        
        # Check if the response is actually JSON
        try:
            return JsonResponse(response.json())
        except ValueError:
            return JsonResponse({
                "error": "The intelligence server returned a non-JSON response.",
                "status_code": response.status_code,
                "raw_response": response.text[:500]
            }, status=502)
            
    except requests.exceptions.Timeout:
        return JsonResponse({"error": "Intelligence relay timeout. Protocol signal lost."}, status=504)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


@login_required
def monitor_list(request):
    """List all monitors."""
    monitors = DarkWebMonitor.objects.all()
    return render(request, 'darkweb/monitor_list.html', {'monitors': monitors})


@login_required
def monitor_create(request):
    """Create a new monitor."""
    if request.method == 'POST':
        org_name = request.POST.get('organization_name', '')
        domains = request.POST.get('domains', '').split(',')
        keywords = request.POST.get('keywords', '').split(',')
        emails = request.POST.get('emails', '').split(',')

        domains = [d.strip() for d in domains if d.strip()]
        keywords = [k.strip() for k in keywords if k.strip()]
        emails = [e.strip() for e in emails if e.strip()]

        monitor = DarkWebMonitor.objects.create(
            organization_name=org_name,
            domains=domains,
            keywords=keywords,
            emails=emails,
        )
        return redirect('darkweb:dashboard')

    return render(request, 'darkweb/monitor_create.html')


@login_required
def alert_list(request):
    """List dark web alerts."""
    severity = request.GET.get('severity', '')
    status = request.GET.get('status', '')
    
    alerts = DarkWebAlert.objects.all()
    if severity:
        alerts = alerts.filter(severity=severity)
    if status:
        alerts = alerts.filter(status=status)

    context = {
        'alerts': alerts[:50],
        'total': DarkWebAlert.objects.count(),
        'new_count': DarkWebAlert.objects.filter(status='new').count(),
    }
    return render(request, 'darkweb/alert_list.html', context)


@login_required
def alert_detail(request, pk):
    """Alert detail view."""
    alert = get_object_or_404(DarkWebAlert, pk=pk)
    return render(request, 'darkweb/alert_detail.html', {'alert': alert})


@login_required
def darkweb_stats_api(request):
    """API for dark web stats."""
    return JsonResponse({
        'total_monitors': DarkWebMonitor.objects.count(),
        'total_alerts': DarkWebAlert.objects.count(),
        'critical': DarkWebAlert.objects.filter(severity='critical').count(),
        'new': DarkWebAlert.objects.filter(status='new').count(),
    })


@csrf_exempt
@login_required
def simulate_scan(request):
    """Simulate a dark web scan for demo purposes."""
    if request.method == 'POST':
        monitors = DarkWebMonitor.objects.filter(status='active')
        
        if not monitors.exists():
            # Create a default monitor
            monitor = DarkWebMonitor.objects.create(
                organization_name='Demo Organization',
                domains=['example.com'],
                keywords=['company data', 'breach'],
                emails=['admin@example.com'],
            )
        else:
            monitor = monitors.first()

        # Generate simulated alerts
        num_alerts = random.randint(2, 5)
        selected = random.sample(SIMULATED_ALERTS, min(num_alerts, len(SIMULATED_ALERTS)))
        
        created = 0
        for alert_data in selected:
            DarkWebAlert.objects.create(
                monitor=monitor,
                **alert_data,
            )
            created += 1

        # Create scan result
        DarkWebScanResult.objects.create(
            monitor=monitor,
            findings_count=created,
            credentials_found=random.randint(0, 15),
            mentions_found=random.randint(1, 8),
            pastes_found=random.randint(0, 3),
            summary=f'Scan completed. Found {created} new alerts.',
        )

        monitor.last_scan = timezone.now()
        monitor.save()

        return JsonResponse({
            'status': 'success',
            'message': f'Scan completed. {created} new findings detected.',
            'count': created,
        })

    return JsonResponse({'error': 'POST required'}, status=405)
