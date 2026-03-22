from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse

from .models import ComplianceFramework, ComplianceControl, AuditRecord
from documents.models import Document
from core.models import AuditLog


@login_required
def framework_list(request):
    profile = request.user.profile
    industry = profile.industry
    
    recs = ['ISO27001']
    if industry == 'IT':
        recs = ['ISO27001', 'SOC2', 'GDPR', 'DPDP']
    elif industry == 'Banking':
        recs = ['RBI', 'PCIDSS', 'ISO27001']
    elif industry == 'Healthcare':
        recs = ['HIPAA', 'ISO27001']
    elif industry == 'Government':
        recs = ['UIDAI', 'NPCI', 'ISO27001']

    if profile.is_client:
        recommended = ComplianceFramework.objects.filter(framework_type__in=recs)
        others = ComplianceFramework.objects.exclude(framework_type__in=recs)
    else:
        # Admin or Auditor sees everything normally
        recommended = ComplianceFramework.objects.all()
        others = []

    return render(request, 'compliance/framework_list.html', {
        'recommended_frameworks': recommended,
        'other_frameworks': others,
        'industry_name': profile.get_industry_display() if industry else 'Your Industry'
    })

@login_required
def framework_detail(request, pk):
    """Framework detail with controls."""
    framework = get_object_or_404(ComplianceFramework, pk=pk)
    controls = framework.controls.all()
    audits = framework.audits.all()[:5]

    context = {
        'framework': framework,
        'controls': controls,
        'audits': audits,
        'compliance_pct': framework.compliance_percentage,
    }
    return render(request, 'compliance/framework_detail.html', context)


@login_required
def audit_list(request):
    """List audit records."""
    audits = AuditRecord.objects.all()
    context = {
        'audits': audits,
    }
    return render(request, 'compliance/audit_list.html', {
        'audits': audits,
    })


@login_required
def controls_list(request):
    controls = ComplianceControl.objects.all()
    # If client, only show active frameworks
    if request.user.profile.is_client:
        controls = controls.filter(framework__is_active=True)

    total = controls.count()
    compliant = controls.filter(status='compliant').count()
    comp_pct = round((compliant / total) * 100) if total > 0 else 0

    return render(request, 'compliance/controls_list.html', {
        'controls': controls,
        'total': total,
        'compliant': compliant,
        'comp_pct': comp_pct,
    })


@login_required
def auditor_dashboard(request):
    if not request.user.profile.is_auditor and not request.user.profile.is_admin:
        return redirect('core:dashboard')
        
    documents = Document.objects.filter(status='pending')
    controls = ComplianceControl.objects.filter(status='not_assessed')

    return render(request, 'compliance/auditor_dashboard.html', {
        'documents': documents,
        'controls': controls
    })


@login_required
def compliance_stats_api(request):
    """API for compliance stats."""
    frameworks = ComplianceFramework.objects.all()
    data = [{
        'id': f.id,
        'name': f.name,
        'type': f.framework_type,
        'compliance_pct': f.compliance_percentage,
        'total_controls': f.controls.count(),
    } for f in frameworks]
    return JsonResponse({'frameworks': data})
