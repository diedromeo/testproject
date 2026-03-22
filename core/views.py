from django.shortcuts import render, redirect
from django.dispatch import receiver
import json
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.db.models import Count
from django.utils import timezone
from datetime import timedelta

from cve_engine.models import CVE
from advisories.models import Advisory
from alerts.models import Alert
from vendors.models import Vendor
from compliance.models import ComplianceFramework, ComplianceControl
from darkweb.models import DarkWebAlert, DarkWebMonitor
from core.models import AuditLog, UserProfile

def checklists(request):
    return render(request, 'compliance/checklists.html')

def landing_page(request):
    return render(request, 'public/landing.html')

def about_page(request):
    return render(request, 'public/about.html')

def articles_page(request):
    return render(request, 'public/articles.html')

ARTICLES_DATA = {
    'dpdp-act-2023-guide': {
        'title': 'The Definitive Guide to DPDP Act 2023 Implementation',
        'date': 'Oct 2024',
        'author': 'Compliance Masterclass Team',
        'category': 'Regulatory Guidance',
        'summary': 'A deep dive into the Digital Personal Data Protection Act 2023, providing a step-by-step roadmap for Indian enterprises to achieve compliance.',
        'content': """
            <h2 class="text-2xl font-black mb-6">Mastering India's New Privacy Landscape</h2>
            <p class="mb-6 leading-relaxed">The Digital Personal Data Protection (DPDP) Act 2023 marks a historic shift in how Indian businesses handle citizen data. Every Data Fiduciary must now rethink their consent architecture from the ground up.</p>
            
            <h3 class="text-xl font-bold mb-4">The Consent Manager Framework</h3>
            <p class="mb-6">One of the most innovative aspects of the DPDP Act is the role of the 'Consent Manager'. Enterprises must establish clear protocols for data principals to give, manage, and withdraw consent through accessible digital interfaces. Our platform automates this lifecycle.</p>
            
            <h3 class="text-xl font-bold mb-4">Reporting Data Breaches to CERT-In</h3>
            <p class="mb-6 leading-relaxed">Timely reporting is no longer optional. Under the new regime, any personal data breach must be reported to the Data Protection Board and affected individuals. Our ThreatShield engine ensures no reporting deadline is ever missed.</p>
        """
    },
    'rbi-cyber-security-framework': {
        'title': 'RBI Cyber Security Framework: A Masterclass for Fintechs',
        'date': 'Nov 2024',
        'author': 'Banking Compliance Expert',
        'category': 'Financial Services',
        'summary': 'A comprehensive analysis of the RBI guidelines for digital lending and credit card platforms, focusing on security controls and risk mitigation.',
        'content': """
            <h2 class="text-2xl font-black mb-6">Securing the Indian Fintech Ecosystem</h2>
            <p class="mb-6 leading-relaxed">The Reserve Bank of India (RBI) has consistently raised the bar for cybersecurity across the financial sector. For fintechs and digital lenders, the 'RBI Cyber Security Framework' is the gold standard for operational resilience.</p>
            
            <h3 class="text-xl font-bold mb-4">Core Control Requirements</h3>
            <p class="mb-6">RBI guidelines explicitly require robust network segmentation, multi-factor authentication (MFA) for all critical systems, and regular vulnerability assessments. Our platform provides a pre-mapped control set that aligns exactly with the RBI's Annexure requirements.</p>
        """
    },
    'identity-centric-security-2026': {
        'title': 'The Disintegration of Perimeter Security in 2026',
        'category': 'Threat Research',
        'date': 'Jan 12, 2026',
        'author': 'Rahul, Head of Intel',
        'summary': 'In 2026, the concept of a secure internal network is dead. Learn why identity-centric security is the new baseline.',
        'content': """
            <h2 class="text-2xl font-black mb-6">Beyond the Firewall</h2>
            <p class="mb-6 leading-relaxed">The static firewall is a relic of the past. Modern threat actors bypass perimeter gateways using specialized credential harvesting and session hijacking techniques.</p>
            
            <h3 class="text-xl font-bold mb-4">The Age of Identity-Centric Security</h3>
            <p class="mb-6">Zero Trust Architecture (ZTA) replaces static trust with dynamic authorization. Every request, whether internal or external, must be verified using device posture attestation and adaptive risk scoring.</p>
        """
    }
}

def article_detail(request, slug):
    article = ARTICLES_DATA.get(slug)
    if not article:
        return redirect('core:articles')
    return render(request, 'public/article_detail.html', article)

def contact_page(request):
    return render(request, 'public/contact.html')

@login_required
def integrations_page(request):
    """View to show version control and identity provider integrations (CI/CD mockup)."""
    return render(request, 'core/integrations.html')

@login_required
def roadmap_page(request):
    """View to show onboarding roadmap mimicking Vanta's style."""
    return render(request, 'core/roadmap.html')

@login_required
def onboarding_view(request):
    if request.user.profile.is_onboarded:
        return redirect('core:dashboard')

    if request.method == 'POST':
        industry = request.POST.get('industry', '')
        org_size = request.POST.get('org_size', '')
        country = request.POST.get('country', '')
        org_name = request.POST.get('organization_name', request.user.profile.organization)

        business_desc = request.POST.get('business_desc', '').lower()

        profile = request.user.profile
        profile.industry = industry
        profile.org_size = org_size
        profile.country = country
        profile.organization = org_name
        profile.is_onboarded = True
        profile.save()

        # AI-like Keyword Analysis for Compliance Mapping
        recs = ['ISO27001']
        
        # Smart detection based on business description
        if 'health' in business_desc or 'clinic' in business_desc or 'patient' in business_desc:
            recs.append('HIPAA')
        if 'card' in business_desc or 'payment' in business_desc or 'finance' in business_desc:
            recs.append('PCIDSS')
        if 'europe' in business_desc or 'eu ' in business_desc or 'consumer data' in business_desc:
            recs.extend(['GDPR', 'DPDP'])
        if 'saas' in business_desc or 'cloud' in business_desc or 'software' in business_desc:
            recs.append('SOC2')

        # Override for production/manufacturing so they don't get useless frameworks
        if 'production' in business_desc or 'manufactur' in business_desc or 'factory' in business_desc:
            recs = ['ISO27001'] # They usually only need basic infosec standard
            
        if 'scada' in business_desc or 'automation' in business_desc:
            recs.append('IEC62443')

        # Industry explicit additions
        if industry == 'Banking':
            recs.extend(['RBI', 'PCIDSS', 'ISO27001'])
        elif industry == 'Healthcare':
            recs.extend(['HIPAA', 'ISO27001'])
        elif industry == 'Government':
            recs.extend(['UIDAI', 'NPCI', 'ISO27001'])
        elif industry == 'IT':
            recs.extend(['SOC2', 'GDPR', 'DPDP'])
        elif industry == 'SCADA':
            recs.extend(['IEC62443', 'ISO27001'])
            
        recs = list(set(recs)) # Remove duplicates

        # Get existing frameworks or create them if needed
        ComplianceFramework.objects.filter(framework_type__in=recs).update(is_active=True)

        AuditLog.objects.create(
            user=request.user, action_type='user_action',
            description=f'{profile.organization} completed onboarding. Assigned frameworks: {", ".join(recs)}',
        )
        return redirect('core:dashboard')

    return render(request, 'core/onboarding.html')

@login_required
def dashboard(request):
    """Main dashboard view with all widgets."""
    now = timezone.now()
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)

    total_cves = CVE.objects.count()
    critical_cves = CVE.objects.filter(severity_level='CRITICAL').count()
    recent_cves = CVE.objects.filter(published_date__gte=last_24h).count()

    open_alerts = Alert.objects.filter(status='open').count()
    critical_alerts = Alert.objects.filter(status='open', severity='critical').count()
    active_advisories = Advisory.objects.filter(is_active=True).count()
    total_vendors = Vendor.objects.count()
    high_risk_vendors = Vendor.objects.filter(risk_score__gte=7.0).count()
    total_frameworks = ComplianceFramework.objects.count()
    
    darkweb_alerts = DarkWebAlert.objects.filter(status='new').count()
    darkweb_critical = DarkWebAlert.objects.filter(severity='critical', status='new').count()

    latest_cves = CVE.objects.order_by('-published_date')[:6]
    latest_alerts = Alert.objects.order_by('-created_at')[:5]
    latest_advisories = Advisory.objects.order_by('-created_at')[:5]
    latest_activities = AuditLog.objects.order_by('-created_at')[:8]
    latest_darkweb = DarkWebAlert.objects.order_by('-discovered_at')[:5]

    severity_dist = CVE.objects.values('severity_level').annotate(
        count=Count('id')
    ).order_by('severity_level')

    # Frameworks with compliance percentage
    frameworks = ComplianceFramework.objects.all()

    context = {
        'total_cves': total_cves,
        'critical_cves': critical_cves,
        'recent_cves': recent_cves,
        'open_alerts': open_alerts,
        'critical_alerts': critical_alerts,
        'active_advisories': active_advisories,
        'total_vendors': total_vendors,
        'high_risk_vendors': high_risk_vendors,
        'total_frameworks': total_frameworks,
        'darkweb_alerts': darkweb_alerts,
        'darkweb_critical': darkweb_critical,
        'latest_cves': latest_cves,
        'latest_alerts': latest_alerts,
        'latest_advisories': latest_advisories,
        'latest_activities': latest_activities,
        'latest_darkweb': latest_darkweb,
        'severity_dist': json.dumps(list(severity_dist)),
        'frameworks': frameworks,
    }
    return render(request, 'core/dashboard.html', context)


def login_view(request):
    """Portal selection page."""
    if request.user.is_authenticated:
        return redirect('core:dashboard')
    return render(request, 'core/login_portal.html')


def admin_login_view(request):
    """Admin login."""
    if request.user.is_authenticated:
        return redirect('core:dashboard')

    error = None
    if request.method == 'POST':
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            try:
                profile = user.profile
            except UserProfile.DoesNotExist:
                UserProfile.objects.create(user=user, role='admin' if user.is_superuser else 'client')
                profile = user.profile
            
            if profile.is_admin:
                login(request, user)
                AuditLog.objects.create(
                    user=user, action_type='user_action',
                    description=f'Admin {user.username} logged in',
                )
                return redirect('core:dashboard')
            else:
                error = 'Access denied. This portal is for administrators only.'
        else:
            error = 'Invalid credentials. Please try again.'

    return render(request, 'core/admin_login.html', {'error': error})


def auditor_login_view(request):
    """Auditor login."""
    if request.user.is_authenticated:
        return redirect('core:dashboard')

    error = None
    if request.method == 'POST':
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            try:
                profile = user.profile
            except UserProfile.DoesNotExist:
                error = 'Access denied. Wait until you are assigned auditor role.'
                return render(request, 'core/admin_login.html', {'error': error})
            
            if profile.is_auditor:
                login(request, user)
                AuditLog.objects.create(
                    user=user, action_type='user_action',
                    description=f'Auditor {user.username} logged in',
                )
                return redirect('core:dashboard')
            else:
                error = 'Access denied. This portal is strictly for certified auditors.'
        else:
            error = 'Invalid credentials. Please try again.'

    return render(request, 'core/admin_login.html', {'error': error})


def client_login_view(request):
    """Client login."""
    if request.user.is_authenticated:
        return redirect('core:dashboard')

    error = None
    if request.method == 'POST':
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            AuditLog.objects.create(
                user=user, action_type='user_action',
                description=f'Client {user.username} logged in',
            )
            return redirect('core:dashboard')
        else:
            error = 'Invalid credentials. Please try again.'

    return render(request, 'core/client_login.html', {'error': error})


def logout_view(request):
    if request.user.is_authenticated:
        AuditLog.objects.create(
            user=request.user, action_type='user_action',
            description=f'User {request.user.username} logged out',
        )
    logout(request)
    return redirect('core:login')


def register_view(request):
    """Redirect to client registration."""
    return redirect('core:client_register')


def client_register_view(request):
    """Client registration."""
    if request.user.is_authenticated:
        return redirect('core:dashboard')

    error = None
    if request.method == 'POST':
        username = request.POST.get('username', '')
        email = request.POST.get('email', '')
        password1 = request.POST.get('password1', '')
        password2 = request.POST.get('password2', '')
        org = request.POST.get('organization', '')
        first_name = request.POST.get('first_name', '')
        last_name = request.POST.get('last_name', '')

        if not username:
            error = 'Username is required.'
        elif not email:
            error = 'Email is required.'
        elif password1 != password2:
            error = 'Passwords do not match.'
        elif len(password1) < 8:
            error = 'Password must be at least 8 characters.'
        elif User.objects.filter(username=username).exists():
            error = 'Username already taken.'
        elif User.objects.filter(email=email).exists():
            error = 'Email already registered.'
        else:
            user = User.objects.create_user(
                username=username, email=email, password=password1,
                first_name=first_name, last_name=last_name,
            )
            try:
                profile = user.profile
            except UserProfile.DoesNotExist:
                profile = UserProfile.objects.create(user=user)
            profile.role = 'client_admin'
            profile.organization = org
            profile.save()

            login(request, user)
            AuditLog.objects.create(
                user=user, action_type='user_action',
                description=f'New client {user.username} registered ({org})',
            )
            return redirect('core:onboarding')

    return render(request, 'core/client_register.html', {'error': error})


@login_required
def dashboard_stats_api(request):
    now = timezone.now()
    last_24h = now - timedelta(hours=24)

    data = {
        'total_cves': CVE.objects.count(),
        'critical_cves': CVE.objects.filter(severity_level='CRITICAL').count(),
        'recent_cves': CVE.objects.filter(published_date__gte=last_24h).count(),
        'open_alerts': Alert.objects.filter(status='open').count(),
        'active_advisories': Advisory.objects.filter(is_active=True).count(),
        'high_risk_vendors': Vendor.objects.filter(risk_score__gte=7.0).count(),
        'darkweb_new': DarkWebAlert.objects.filter(status='new').count(),
    }
    return JsonResponse(data)


@login_required
def activity_feed_api(request):
    activities = AuditLog.objects.order_by('-created_at')[:20]
    data = [{
        'id': a.id,
        'type': a.action_type,
        'description': a.description,
        'time': a.created_at.isoformat(),
    } for a in activities]
    return JsonResponse({'activities': data})
