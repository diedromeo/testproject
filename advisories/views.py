from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse

from .models import Advisory


@login_required
def advisory_list(request):
    """List all advisories."""
    severity = request.GET.get('severity', '')
    source = request.GET.get('source', '')

    advisories = Advisory.objects.all()
    if severity:
        advisories = advisories.filter(severity=severity)
    if source:
        advisories = advisories.filter(source=source)

    context = {
        'advisories': advisories[:50],
        'total': Advisory.objects.count(),
        'active': Advisory.objects.filter(is_active=True).count(),
        'severity_filter': severity,
        'source_filter': source,
    }
    return render(request, 'advisories/advisory_list.html', context)


@login_required
def advisory_detail(request, pk):
    """Advisory detail view."""
    advisory = get_object_or_404(Advisory, pk=pk)
    return render(request, 'advisories/advisory_detail.html', {'advisory': advisory})


@login_required
def advisory_api(request):
    """API for advisories."""
    advisories = Advisory.objects.all()[:30]
    data = [{
        'id': a.id,
        'title': a.title,
        'severity': a.severity,
        'source': a.source,
        'is_active': a.is_active,
        'created_at': a.created_at.isoformat(),
        'cve_id': a.linked_cve.cve_id if a.linked_cve else None,
    } for a in advisories]
    return JsonResponse({'advisories': data})
